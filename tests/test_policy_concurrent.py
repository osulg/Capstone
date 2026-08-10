# test3.py — LOW / MEDIUM / HIGH 3개 프로세스 동시 정책 테스트
import multiprocessing
import os
import time

TARGET = os.path.expanduser("~/test_mount")
def set_state(pid: int, state: str) -> None:
    with open(f"/tmp/guardfs_state_{pid}", "w") as f:
        f.write(state)


def low_worker():
    pid = os.getpid()
    set_state(pid, "LOW")
    time.sleep(0.2)  # passthrough가 override 파일 읽을 시간

    print(f"[LOW  WORKER] pid={pid} 시작 → 즉시 디스크 저장")
    with open(f"{TARGET}/low_file.txt", "w") as f:
        f.write("hello from LOW " * 100)
    print(f"[LOW  WORKER] pid={pid} 완료 → underlay에 즉시 반영")


def medium_worker():
    pid = os.getpid()
    set_state(pid, "MEDIUM")
    time.sleep(0.2)

    print(f"[MED  WORKER] pid={pid} 시작 → 버퍼링 후 헤더 검증, 커밋")
    with open(f"{TARGET}/medium_file.txt", "w") as f:
        f.write("hello from MEDIUM " * 100)
    print(f"[MED  WORKER] pid={pid} write 완료 → 1초 후 커밋 예정, MEDIUM 유지")
    time.sleep(13)
    print(f"[MED  WORKER] pid={pid} 종료")


def high_worker():
    pid = os.getpid()
    set_state(pid, "HIGH")
    time.sleep(0.2)

    print(f"[HIGH WORKER] pid={pid} 시작 → write 차단 + SIGSTOP 예정")
    try:
        with open(f"{TARGET}/high_file.txt", "w") as f:
            f.write("hello from HIGH " * 100)
        print(f"[HIGH WORKER] pid={pid} write 완료 (차단됨, 내용 미반영)")
    except Exception as e:
        print(f"[HIGH WORKER] pid={pid} 오류: {e}")


if __name__ == "__main__":
    print("=" * 50)
    print("GuardFS 3-Policy 동시 테스트")
    print(f"마운트: {TARGET}")
    print("=" * 50)
    print()

    p_low  = multiprocessing.Process(target=low_worker,    name="LOW-worker")
    p_med  = multiprocessing.Process(target=medium_worker, name="MED-worker")
    p_high = multiprocessing.Process(target=high_worker,   name="HIGH-worker")

    p_low.start()
    p_med.start()
    p_high.start()

    p_low.join()

    # HIGH는 SIGSTOP으로 멈추므로 타임아웃 후 강제 종료
    p_high.join(timeout=5)
    if p_high.is_alive():
        p_high.terminate()
        print("[HIGH WORKER] SIGSTOP 상태 → 강제 종료")

    p_med.join()

    print()
    print("=" * 50)
    print("결과 확인: ls ~/test_underlay/")
    print("  low_file.txt    → 있어야 함 (즉시 저장)")
    print("  medium_file.txt → 있어야 함 (1초 후 커밋)")
    print("  high_file.txt   → 없어야 함 (차단)")
    print("=" * 50)
