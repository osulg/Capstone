#!/usr/bin/env python3
"""
eBPF 동적 데이터 수집기 (source=ebpf, 스키마 v1)

수집기가 워크로드를 직접 실행하고, 그 프로세스와 모든 자손만 커널에서 추적한다.
실행 1회 = run_id 1개 = 샘플 1개. 라벨은 run 메타데이터로 부여한다.

사용 예 (root 권한 필요, x86_64 / 커널 5.8+ / BCC):
  sudo python3 models/dynamic/collect/ebpf_collector.py \
      --run-id benign_tar_001 \
      --target-dir /home/capstone/guardfs_runtime/mount \
      --as-user capstone \
      -- tar czf /home/capstone/guardfs_runtime/mount/out.tgz -C /home/capstone/guardfs_runtime/mount docs

출력: <log-dir>/<run_id>.ebpf.jsonl, <run_id>.ebpf.meta.json
      (기본 log-dir은 FUSE 수집 로그와 같은 ~/guardfs_runtime/collect)
"""

import argparse
import ctypes
import json
import os
import pwd
import signal
import socket
import sys
import time
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
sys.path.insert(0, HERE)
sys.path.insert(0, PROJECT_ROOT)

from ebpf_events import OPS, SCHEMA_VERSION, EbpfEventProcessor  # noqa: E402
from guardfs.collect.fuse_logger import RUN_ID_PATTERN  # noqa: E402
from guardfs.common.paths import get_collect_log_dir  # noqa: E402

BPF_SRC = os.path.join(HERE, "ebpf_collector.c")
DEFAULT_CRYPTO_LIB = "/lib/x86_64-linux-gnu/libcrypto.so.3"
CRYPTO_SYMBOLS = (
    "EVP_EncryptInit_ex",
    "EVP_EncryptInit_ex2",
    "EVP_CipherInit_ex",
    "EVP_CipherInit_ex2",
    "EVP_SealInit",
)
POLL_MS = 100


def _run_id_arg(value: str) -> str:
    if not RUN_ID_PATTERN.match(value):
        raise argparse.ArgumentTypeError("영문, 숫자, '.', '_', '-'만 사용할 수 있습니다")
    return value


def parse_args():
    parser = argparse.ArgumentParser(description="GuardFS eBPF 동적 데이터 수집기")
    parser.add_argument("--run-id", required=True, type=_run_id_arg)
    parser.add_argument(
        "--target-dir",
        required=True,
        help="수집 대상 디렉터리(FUSE 마운트 경로). 이 기준 상대 경로로 기록한다",
    )
    parser.add_argument("--log-dir", help="로그 디렉터리 (기본: target-dir 옆 collect/)")
    parser.add_argument("--as-user", help="워크로드를 이 사용자 권한으로 실행 (정상 워크로드용)")
    parser.add_argument(
        "--timeout",
        type=float,
        default=600.0,
        help="최대 수집 시간(초). 초과 시 남은 추적 프로세스를 종료한다",
    )
    parser.add_argument("--crypto-lib", default=DEFAULT_CRYPTO_LIB)
    parser.add_argument("command", nargs=argparse.REMAINDER, help="-- 뒤에 실행할 명령")

    args = parser.parse_args()

    if args.command and args.command[0] == "--":
        args.command = args.command[1:]
    if not args.command:
        parser.error("실행할 명령이 없습니다 (-- <command> ...)")

    return args


def _str(raw: bytes) -> str:
    return raw.split(b"\0", 1)[0].decode("utf-8", "surrogateescape")


def to_dict(e) -> dict:
    return {
        "ts_ns": e.ts_ns,
        "ret": e.ret,
        "size": e.size,
        "offset": e.offset,
        "tgid": e.tgid,
        "tid": e.tid,
        "op": e.op,
        "fd": e.fd,
        "fd2": e.fd2,
        "flags": e.flags,
        "comm": _str(e.comm),
        "path": _str(e.path),
        "path2": _str(e.path2),
    }


def _drop_privileges(user: str) -> None:
    pw = pwd.getpwnam(user)
    os.initgroups(user, pw.pw_gid)
    os.setgid(pw.pw_gid)
    os.setuid(pw.pw_uid)
    os.environ.update(HOME=pw.pw_dir, USER=user, LOGNAME=user)


def spawn_paused(command, as_user):
    """추적 등록 전에 워크로드가 시작되지 않도록 파이프로 대기시킨 자식을 만든다."""
    gate_r, gate_w = os.pipe()
    pid = os.fork()

    if pid == 0:
        try:
            os.close(gate_w)
            os.read(gate_r, 1)
            os.close(gate_r)
            if as_user:
                _drop_privileges(as_user)
            os.execvp(command[0], command)
        except BaseException as e:
            os.write(2, f"[collector] 워크로드 실행 실패: {e}\n".encode())
        finally:
            os._exit(127)

    os.close(gate_r)
    return pid, gate_w


def _write_meta(path: str, meta: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)


def main() -> int:
    args = parse_args()

    if os.geteuid() != 0:
        print("[collector] root 권한이 필요합니다 (sudo)", file=sys.stderr)
        return 2

    from bcc import BPF

    log_dir = args.log_dir or get_collect_log_dir(args.target_dir)
    os.makedirs(log_dir, exist_ok=True)
    log_path = os.path.join(log_dir, f"{args.run_id}.ebpf.jsonl")
    meta_path = os.path.join(log_dir, f"{args.run_id}.ebpf.meta.json")

    # 같은 run_id로 이어 쓰면 서로 다른 실행이 한 샘플로 섞이므로 거부한다.
    out = open(log_path, "x", buffering=1, encoding="utf-8")

    b = BPF(src_file=BPF_SRC, cflags=[f"-D{k}={v}" for k, v in OPS.items()])

    crypto_probes = []
    for sym in CRYPTO_SYMBOLS:
        try:
            b.attach_uprobe(name=args.crypto_lib, sym=sym, fn_name="on_crypto")
            crypto_probes.append(sym)
        except Exception as e:
            print(f"[collector] uprobe 등록 실패 ({sym}): {e}", file=sys.stderr)

    processor = EbpfEventProcessor(
        args.run_id,
        args.target_dir,
        lambda record: out.write(json.dumps(record) + "\n"),
    )
    processing_errors = 0

    def on_event(ctx, data, size):
        nonlocal processing_errors
        try:
            processor.handle(to_dict(b["events"].event(data)))
        except Exception:
            processing_errors += 1
            traceback.print_exc()

    b["events"].open_ring_buffer(on_event)

    meta = {
        "schema_version": SCHEMA_VERSION,
        "source": "ebpf",
        "run_id": args.run_id,
        "target_dir": os.path.realpath(args.target_dir),
        "command": args.command,
        "as_user": args.as_user,
        "hostname": socket.gethostname(),
        "kernel": os.uname().release,
        "crypto_probes": crypto_probes,
        "start_wall": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "start_monotonic_ns": time.monotonic_ns(),
        "end_wall": None,
        "end_monotonic_ns": None,
        "root_pid": None,
        "root_exit_code": None,
        "timed_out": False,
        "killed_pids": [],
        "events": 0,
        "kernel_drops": 0,
        "processing_errors": 0,
    }
    _write_meta(meta_path, meta)

    stop = False

    def request_stop(signum, frame):
        nonlocal stop
        stop = True

    signal.signal(signal.SIGINT, request_stop)
    signal.signal(signal.SIGTERM, request_stop)

    root_pid, gate = spawn_paused(args.command, args.as_user)
    b["tracked"][ctypes.c_uint32(root_pid)] = ctypes.c_uint8(1)
    processor.seed_root(root_pid, os.getpid(), os.getcwd())
    meta["root_pid"] = root_pid

    started = time.monotonic()
    os.write(gate, b"1")
    os.close(gate)
    print(f"[collector] run_id={args.run_id} root_pid={root_pid} log={log_path}")

    # 루트가 끝나도 데몬화한 자손이 남아 있을 수 있으므로 추적 대상이 모두 사라질 때까지 수집한다.
    while not stop:
        b.ring_buffer_poll(POLL_MS)

        if meta["root_exit_code"] is None:
            pid, status = os.waitpid(root_pid, os.WNOHANG)
            if pid:
                meta["root_exit_code"] = os.waitstatus_to_exitcode(status)

        if len(list(b["tracked"].keys())) == 0:
            break

        if time.monotonic() - started > args.timeout:
            meta["timed_out"] = True
            break

    if meta["timed_out"] or stop:
        # 남은 프로세스가 다음 실행의 로그에 섞이지 않도록 정리한다.
        for key in b["tracked"].keys():
            try:
                os.kill(key.value, signal.SIGKILL)
                meta["killed_pids"].append(key.value)
            except ProcessLookupError:
                pass
        time.sleep(0.2)

    b.ring_buffer_consume()

    # 이 시점에 루트는 이미 종료됐거나 위에서 SIGKILL을 받았다.
    if meta["root_exit_code"] is None:
        try:
            _, status = os.waitpid(root_pid, 0)
            meta["root_exit_code"] = os.waitstatus_to_exitcode(status)
        except ChildProcessError:
            pass

    out.close()

    meta.update(
        end_wall=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        end_monotonic_ns=time.monotonic_ns(),
        events=processor.events,
        kernel_drops=b["drops"][ctypes.c_int(0)].value,
        processing_errors=processing_errors,
    )
    _write_meta(meta_path, meta)

    print(
        f"[collector] 완료 events={meta['events']} drops={meta['kernel_drops']} "
        f"exit={meta['root_exit_code']} timed_out={meta['timed_out']}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
