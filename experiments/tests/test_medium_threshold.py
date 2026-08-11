# test.py
import os
import time

target = os.path.expanduser("~/test_mount")

print(f"[TEST] PID: {os.getpid()}")
print("[TEST] 파일 쓰기 시작...")

# 파일 2개 쓰기 → 임계치 초과 → SUSPICIOUS → MEDIUM
with open(f"{target}/test_1.txt", "w") as f:
    f.write("hello world " * 100)
print("[TEST] test_1.txt 작성 완료")

time.sleep(0.1)

with open(f"{target}/test_2.txt", "w") as f:
    f.write("hello world " * 100)
print("[TEST] test_2.txt 작성 완료")

time.sleep(0.1)

with open(f"{target}/test_3.txt", "w") as f:
    f.write("hello world " * 100)
print("[TEST] test_3.txt 작성 완료")

print("[TEST] 완료 - 10초 기다리면 Low 복귀됩니다")
time.sleep(15)
print("[TEST] 종료")