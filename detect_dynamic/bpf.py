from bcc import BPF
import os
import socket
import ctypes
import sys
import pwd
import json

# ============================================================
# 환경 설정
# ============================================================

UDP_IP = "192.168.1.1"
UDP_PORT = 9999

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

real_user = os.environ.get("SUDO_USER") or os.environ.get("USER")

try:
    user_info = pwd.getpwnam(real_user)
    REAL_HOME = user_info.pw_dir
    TARGET_UID = user_info.pw_uid
except Exception:
    REAL_HOME = os.path.expanduser("~")
    TARGET_UID = int(
        os.environ.get("SUDO_UID", os.getuid())
    )

# 감시 경로: 환경변수로 지정 가능
TARGET_DIR = os.environ.get(
    "GUARDFS_TARGET_DIR",
    REAL_HOME.rstrip("/") + "/"
)

# lineage의 시작점이 되는 실행 파일
ROOT_EXE = os.environ.get("GUARDFS_ROOT_EXE")

if ROOT_EXE:
    ROOT_EXE = os.path.abspath(ROOT_EXE)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
BPF_FILE = os.path.join(BASE_DIR, "bpf.c")

LOG_FILE = os.environ.get(
    "GUARDFS_LOG_FILE",
    os.path.join(BASE_DIR, "lineage_events.jsonl")
)

# 모든 unrelated EXEC도 화면에 출력할지 여부
VERBOSE_EXEC = (
    os.environ.get("GUARDFS_VERBOSE_EXEC", "0") == "1"
)

# TGID -> process 정보
process_cache = {}

# 공격 root 및 그 descendants
attack_lineage = set()

# TGID -> root TGID
lineage_root = {}


print("[*] eBPF 모듈 컴파일 및 라이브러리/프로브 로드 중...")


# ============================================================
# BPF 로드
# ============================================================

try:
    b = BPF(src_file=BPF_FILE)

    # 현재 로그인 사용자의 UID만 커널 단계에서 수집
    b["target_uid"][
        ctypes.c_uint32(TARGET_UID)
    ] = ctypes.c_uint32(1)

    lib_path = "/lib/x86_64-linux-gnu/libcrypto.so.3"

    crypto_functions = [
        "EVP_EncryptInit_ex",
        "EVP_CipherInit_ex",
        "EVP_SealInit_ex"
    ]

    for func in crypto_functions:
        try:
            b.attach_uprobe(
                name=lib_path,
                sym=func,
                fn_name="detect_encrypt"
            )
            print(f"[*] uprobe 등록 성공: {func}")

        except Exception as e:
            print(f"[!] {func} 등록 실패: {e}")

    my_pid = os.getpid()

    b["ignore_pid"][
        ctypes.c_uint32(my_pid)
    ] = ctypes.c_uint32(1)

    print(f"[*] 탐지기 로드 성공! (내 PID: {my_pid})")
    print(f"[*] 대상 사용자: {real_user} (UID={TARGET_UID})")
    print(f"[*] 감시 경로: {TARGET_DIR}")
    print(f"[*] Lineage Root EXE: {ROOT_EXE or '미지정'}")
    print(f"[*] JSONL 로그: {LOG_FILE}")

except Exception as e:
    print(f"[!] 초기화 중 치명적 에러 발생: {e}")
    sys.exit(1)


# ============================================================
# 유틸
# ============================================================

def decode_field(value):
    try:
        return (
            value.decode(errors="replace")
            .split("\x00", 1)[0]
        )
    except Exception:
        return str(value)


def save_json(record):
    try:
        with open(
            LOG_FILE,
            "a",
            encoding="utf-8"
        ) as f:
            f.write(
                json.dumps(
                    record,
                    ensure_ascii=False
                )
                + "\n"
            )
    except Exception as e:
        print(f"[!] 로그 저장 실패: {e}")


# ============================================================
# 이벤트 처리
# ============================================================

def print_event(cpu, data, size):

    event = b["events"].event(data)

    tgid = int(event.tgid)
    tid = int(event.tid)
    ppid = int(event.ppid)
    ts_ns = int(event.ts_ns)

    comm = decode_field(event.comm)
    filename = decode_field(event.filename)

    action = (
        decode_field(event.type)
        .strip()
        .upper()
    )

    # --------------------------------------------------------
    # EXIT
    # --------------------------------------------------------

    if action == "Z":

        # sched_process_exit는 thread 단위로도 발생한다.
        # process leader(TID == TGID)가 종료될 때만
        # PID/TGID 기반 cache를 제거한다.
        if tid != tgid:
            # sched_process_fork는 thread 생성도 관측할 수 있다.
            # fork 이벤트에서 child TID가 임시 key로 들어갔다면
            # thread 종료 시 함께 정리한다.
            process_cache.pop(tid, None)
            attack_lineage.discard(tid)
            lineage_root.pop(tid, None)
            return

        info = process_cache.get(
            tgid,
            {}
        )

        label = info.get(
            "label",
            -1 if ROOT_EXE else 0
        )

        relation = info.get(
            "relation",
            "unknown"
        )

        root_tgid = info.get(
            "root_tgid"
        )

        exe = info.get(
            "exe",
            ""
        )

        # JSONL에는 종료 시점도 남겨서
        # 이후 PID 재사용 시 process instance를 구분할 수 있게 한다.
        record = {
            "ts_ns": ts_ns,
            "tgid": tgid,
            "tid": tid,
            "ppid": ppid,
            "comm": comm,
            "action": "Z",
            "file": "",
            "exe": exe,
            "lineage_label": label,
            "relation": relation,
            "root_tgid": root_tgid
        }

        save_json(record)

        if label == 1 and VERBOSE_EXEC:
            print(
                f"[EXIT] "
                f"TGID={tgid} "
                f"COMM={comm} "
                f"LABEL={label}",
                flush=True
            )

        # PID 재사용으로 과거 lineage가 새 프로세스에
        # 상속되는 것을 방지한다.
        process_cache.pop(
            tgid,
            None
        )

        attack_lineage.discard(
            tgid
        )

        lineage_root.pop(
            tgid,
            None
        )

        return


    # --------------------------------------------------------
    # FORK
    # --------------------------------------------------------

    if action == "F":

        parent_info = process_cache.get(
            ppid,
            {}
        )

        # benign 전용 수집
        if not ROOT_EXE:
            label = 0
            relation = "benign"
            root_tgid = None

        # attack 수집:
        # parent가 공격 lineage이면 child도 즉시 descendant
        elif ppid in attack_lineage:
            label = 1
            relation = "descendant"

            root_tgid = lineage_root.get(
                ppid,
                ppid
            )

            attack_lineage.add(tgid)
            lineage_root[tgid] = root_tgid

        # 공격 실험 중이지만 lineage 관계가 확인되지 않음
        else:
            label = -1
            relation = "ambiguous"
            root_tgid = None

        # fork 직후 child는 exec 전까지 parent의 실행 이미지를 상속한다.
        inherited_exe = parent_info.get(
            "exe",
            ""
        )

        process_cache[tgid] = {
            "ppid": ppid,
            "exe": inherited_exe,
            "comm": comm,
            "label": label,
            "relation": relation,
            "root_tgid": root_tgid,
            "ts_ns": ts_ns
        }

        record = {
            "ts_ns": ts_ns,
            "tgid": tgid,
            "tid": tid,
            "ppid": ppid,
            "comm": comm,
            "action": "F",
            "file": "",
            "exe": inherited_exe,
            "lineage_label": label,
            "relation": relation,
            "root_tgid": root_tgid
        }

        save_json(record)

        if label == 1 or VERBOSE_EXEC:
            print(
                f"[FORK:{relation.upper()}] "
                f"TGID={tgid} "
                f"PPID={ppid} "
                f"COMM={comm} "
                f"LABEL={label}",
                flush=True
            )

        return


    # --------------------------------------------------------
    # EXEC
    # --------------------------------------------------------

    if action == "X":

        exe_abs = os.path.abspath(filename)

        # benign 전용 수집(ROOT_EXE 미지정):
        #   unrelated process -> Label 0
        #
        # attack 수집(ROOT_EXE 지정):
        #   lineage 미확인 process -> Label -1 (AMBIGUOUS)
        if ROOT_EXE:
            label = -1
            relation = "ambiguous"
        else:
            label = 0
            relation = "benign"

        root_tgid = None

        # 1. configured root executable
        if ROOT_EXE and exe_abs == ROOT_EXE:

            label = 1
            relation = "root"
            root_tgid = tgid

            attack_lineage.add(tgid)
            lineage_root[tgid] = tgid

        # 2. 이미 attack lineage인 동일 TGID가 exec된 경우
        elif tgid in attack_lineage:

            label = 1
            relation = process_cache.get(
                tgid,
                {}
            ).get(
                "relation",
                "lineage_exec"
            )

            root_tgid = lineage_root.get(
                tgid,
                tgid
            )

        # 3. parent가 attack lineage라면 descendant
        elif ppid in attack_lineage:

            label = 1
            relation = "descendant"
            root_tgid = lineage_root.get(
                ppid,
                ppid
            )

            attack_lineage.add(tgid)
            lineage_root[tgid] = root_tgid

        process_cache[tgid] = {
            "ppid": ppid,
            "exe": filename,
            "comm": comm,
            "label": label,
            "relation": relation,
            "root_tgid": root_tgid,
            "ts_ns": ts_ns
        }

        record = {
            "ts_ns": ts_ns,
            "tgid": tgid,
            "tid": tid,
            "ppid": ppid,
            "comm": comm,
            "action": "X",
            "file": filename,
            "exe": filename,
            "lineage_label": label,
            "relation": relation,
            "root_tgid": root_tgid
        }

        save_json(record)

        # 화면에는 관련 lineage만 기본 출력
        if label == 1 or VERBOSE_EXEC:

            print(
                f"[EXEC:{relation.upper()}] "
                f"TGID={tgid} "
                f"PPID={ppid} "
                f"COMM={comm} "
                f"EXE={filename} "
                f"LABEL={label}",
                flush=True
            )

        return


    # --------------------------------------------------------
    # 파일 행동
    # --------------------------------------------------------

    cached = process_cache.get(tgid)

    if cached:

        exe = cached["exe"]
        effective_ppid = cached["ppid"]
        label = cached["label"]
        relation = cached["relation"]
        root_tgid = cached["root_tgid"]

    else:

        exe = "UNKNOWN"
        effective_ppid = ppid

        # 수집기 실행 전에 이미 살아 있던 프로세스는
        # lineage를 확정할 수 없으므로 -1
        label = -1
        relation = "unknown"
        root_tgid = None


    # --------------------------------------------------------
    # 학습용 이벤트 노이즈 제한
    #
    # O/C:
    #   감시 대상 경로 내부의 파일 행동만 보존한다.
    #   /lib, /etc 등의 라이브러리 로딩을 학습하지 않도록 함.
    #
    # D/E:
    #   감시 경로 내부 이벤트는 항상 보존한다.
    #   attack lineage(label=1)는 경로 밖 D/E도 보존하여
    #   Wiper류 파괴 행동을 놓치지 않도록 한다.
    # --------------------------------------------------------

    in_target = (
        bool(filename)
        and TARGET_DIR in filename
    )

    if action in ("O", "C"):
        interesting = in_target

    elif action in ("D", "E"):
        interesting = (
            in_target
            or label == 1
        )

    else:
        interesting = False

    if not interesting:
        return


    record = {
        "ts_ns": ts_ns,
        "tgid": tgid,
        "tid": tid,
        "ppid": effective_ppid,
        "comm": comm,
        "action": action,
        "file": filename,
        "exe": exe,
        "lineage_label": label,
        "relation": relation,
        "root_tgid": root_tgid
    }

    save_json(record)


    # 화면 출력은 target path나 attack lineage 중심
    print(
        f"[EVENT] "
        f"TGID={tgid} "
        f"PPID={effective_ppid} "
        f"COMM={comm} "
        f"ACTION={action} "
        f"FILE={filename} "
        f"EXE={exe} "
        f"LABEL={label} "
        f"REL={relation}",
        flush=True
    )


    # --------------------------------------------------------
    # Legacy UDP compatibility
    #
    # 기존 Host 수신부 / data_prep.py가 기대하는 형식:
    #   [PID] process_name ACTION target
    #
    # 상세 lineage 정보는 JSONL에만 저장하고,
    # UDP는 기존 프로젝트 형식을 그대로 유지한다.
    # --------------------------------------------------------

    if action in ("D", "DELETE") or in_target:
        legacy_log_msg = (
            f"[{tgid}] "
            f"{comm} "
            f"{action} "
            f"{filename}"
        )

        try:
            sock.sendto(
                legacy_log_msg.encode(),
                (UDP_IP, UDP_PORT)
            )
        except Exception:
            pass


# ============================================================
# Poll
# ============================================================

b["events"].open_perf_buffer(print_event)

print(
    "--- [Process Lineage 추적 시작] ---",
    flush=True
)

while True:
    try:
        b.perf_buffer_poll()

    except KeyboardInterrupt:
        print("\n[*] 중단됨.", flush=True)
        sys.exit(0)
