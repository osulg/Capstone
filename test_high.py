import os
import sys
import time
import signal
import subprocess

BASE = os.path.dirname(os.path.abspath(__file__))

MOUNT = os.path.join(BASE, "mnt")
UNDERLAY = os.path.join(BASE, "underlay")
LOG = os.path.expanduser("~/high.log")


def mpath(name):
    return os.path.join(MOUNT, name)


def upath(name):
    return os.path.join(UNDERLAY, name)


def write_underlay(name, data: bytes):
    with open(upath(name), "wb") as f:
        f.write(data)


def trigger_high(case):
    trigger_name = f"trigger_high_{case}_{os.getpid()}.pdf"

    with open(mpath(trigger_name), "wb") as f:
        f.write(b"\x00\x01\x02\x03 encrypted data")


def child_case(case):
    print(f"[CHILD] PID={os.getpid()} CASE={case}")

    if case.startswith("direct_"):
        real_case = case.replace("direct_", "")
        trigger_high(real_case)
        time.sleep(0.2)
    else:
        real_case = case

        # MEDIUM → HIGH 테스트용:
        # create()를 발생시켜 해당 PID를 MEDIUM으로 먼저 올림
        with open(mpath(f"medium_seed_{real_case}_{os.getpid()}.tmp"), "wb") as f:
            f.write(b"seed")

        time.sleep(1.5)

        # MEDIUM → HIGH 테스트에서는 실제 동작 전에 깨진 파일 write로 HIGH 격상 유도
    if not case.startswith("direct_"):
        with open(
            mpath(f"medium_to_high_broken_{real_case}_{os.getpid()}.pdf"), "wb"
        ) as f:
            f.write(b"\x00\x01\x02\x03 broken pdf data")

        time.sleep(1.5)

    if real_case == "write":
        with open(mpath("high_write_target.txt"), "r+b") as f:
            f.write(b"MALICIOUS_WRITE")

    elif real_case == "delete":
        os.remove(mpath("high_delete_target.txt"))

    elif real_case == "rename":
        os.rename(mpath("high_rename_target.txt"), mpath("high_rename_target.locked"))

    # elif case == "truncate":
    #     with open(mpath("high_truncate_target.txt"), "r+b") as f:
    #         f.truncate(0)

    print(f"[CHILD] CASE={case} finished")


def run_child(case):
    p = subprocess.Popen([sys.executable, __file__, "--case", case])

    stopped = False
    start = time.time()

    while True:
        result = os.waitpid(p.pid, os.WNOHANG | os.WUNTRACED)

        if result != (0, 0):
            pid, status = result

            if os.WIFSTOPPED(status):
                stopped = True
                print(f"  ✓ child stopped by HIGH policy: pid={pid}")
                os.kill(pid, signal.SIGCONT)
                p.wait(timeout=5)
                break

            if os.WIFEXITED(status):
                break

        if time.time() - start > 5:
            print("  ✗ timeout")
            try:
                p.kill()
            except ProcessLookupError:
                pass
            break

        time.sleep(0.1)

    return stopped


def check_write():
    with open(upath("high_write_target.txt"), "rb") as f:
        data = f.read()
    return data == b"ORIGINAL_WRITE_DATA"


def check_delete():
    return os.path.exists(upath("high_delete_target.txt"))


def check_rename():
    return os.path.exists(upath("high_rename_target.txt")) and not os.path.exists(
        upath("high_rename_target.locked")
    )


def check_truncate():
    return os.path.getsize(upath("high_truncate_target.txt")) > 0


def main():
    print("=" * 60)
    print("[HIGH POLICY TEST]")
    print("=" * 60)

    os.makedirs(MOUNT, exist_ok=True)
    os.makedirs(UNDERLAY, exist_ok=True)

    # 테스트 파일 준비
    write_underlay("high_write_target.txt", b"ORIGINAL_WRITE_DATA")
    write_underlay("high_delete_target.txt", b"DELETE_TARGET")
    write_underlay("high_rename_target.txt", b"RENAME_TARGET")
    # write_underlay("high_truncate_target.txt", b"TRUNCATE_TARGET")

    tests = [
        ("direct_write", check_write, "처음부터 HIGH - WRITE 차단"),
        ("direct_delete", check_delete, "처음부터 HIGH - DELETE 차단"),
        ("direct_rename", check_rename, "처음부터 HIGH - RENAME 차단"),
        ("write", check_write, "MEDIUM → HIGH - WRITE 차단"),
        ("delete", check_delete, "MEDIUM → HIGH - DELETE 차단"),
        ("rename", check_rename, "MEDIUM → HIGH - RENAME 차단"),
    ]

    for case, checker, desc in tests:
        print()
        print("-" * 60)
        print(f"[TEST] {desc}")
        print("-" * 60)

        stopped = run_child(case)
        protected = checker()

        if stopped and protected:
            print(f"[PASS] {desc} 성공")
        else:
            print(f"[FAIL] {desc} 실패")
            print(f"  stopped={stopped}, protected={protected}")

    print()
    print("=" * 60)
    print("[LOG CHECK]")
    print("=" * 60)

    if os.path.exists(LOG):
        print(f"✓ HIGH 로그 파일 존재: {LOG}")
        print()
        with open(LOG, "r", encoding="utf-8") as f:
            print(f.read()[-2000:])
    else:
        print("✗ HIGH 로그 파일 없음")

    print()
    print("테스트 완료")


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--case":
        child_case(sys.argv[2])
    else:
        main()
