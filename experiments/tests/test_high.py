"""
같은 PID에서 반복 고엔트로피 쓰기 + 이름변경
→ E_sum, D_sum, C_sum, 3-gram 누적 → dyn 점수 극대화 → HIGH 기대
"""
import os
import time

MOUNT = os.path.expanduser("~/test_mount")

print(f"[HIGH-SIM] pid={os.getpid()} 랜섬웨어 행동 시뮬레이션")

for i in range(10):
    path = os.path.join(MOUNT, f"victim_{i}.txt")
    enc  = os.path.join(MOUNT, f"victim_{i}.enc")

    # 고엔트로피 쓰기 (E_sum++)
    with open(path, "wb") as f:
        f.write(os.urandom(512))

    # 확장자 변경 (ExtChangeDetector)
    try:
        os.rename(path, enc)
    except OSError:
        pass

    # 원본 삭제 (D_sum++)
    try:
        os.unlink(enc)
    except OSError:
        pass

    time.sleep(0.5)   # REEVAL이 살아있는 동안 stats 누적 가능하게

print("[HIGH-SIM] 완료 — [STAGE2] final 점수 확인")
