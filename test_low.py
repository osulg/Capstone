"""
test_low.py - LOW 정책 테스트

테스트 1: LOW 상태에서 즉시 디스크 기록 확인
테스트 2: MEDIUM → LOW 복귀 후 재탐지 확인

실행 전 GuardFS 마운트 필요:
    python3 passthrough.py ~/test_mount ~/test_underlay

실행:
    python3 test_low.py
"""

import os
import time

MOUNT = os.path.expanduser("~/test_mount")
UNDERLAY = os.path.expanduser("~/test_underlay")


def check_file(path: str, expected: bytes) -> bool:
    """underlay에 파일이 올바르게 기록됐는지 확인"""
    underlay_path = path.replace(MOUNT, UNDERLAY)
    try:
        with open(underlay_path, "rb") as f:
            actual = f.read()
        if actual == expected:
            print(f"  ✓ 디스크 기록 확인: {os.path.basename(underlay_path)}")
            return True
        else:
            print(f"  ✗ 내용 불일치: {os.path.basename(underlay_path)}")
            print(f"    expected: {expected}")
            print(f"    actual:   {actual}")
            return False
    except FileNotFoundError:
        print(f"  ✗ 파일 없음: {underlay_path}")
        return False


# ----------------------------------------------------------------
# 테스트 1: LOW 상태에서 즉시 디스크 기록 확인
# ----------------------------------------------------------------
print("=" * 50)
print("[TEST 1] LOW 상태 즉시 디스크 기록 확인")
print("=" * 50)
print()

path1 = os.path.join(MOUNT, "low_test_1.txt")
content1 = b"LOW state direct write test"

print(f"  Writing: {path1}")
with open(path1, "wb") as f:
    f.write(content1)

time.sleep(0.2)
result1 = check_file(path1, content1)

print()
if result1:
    print("[TEST 1] PASS - LOW 상태에서 즉시 디스크 기록 확인됨")
else:
    print("[TEST 1] FAIL - 디스크에 기록되지 않음 (MEDIUM 버퍼에 있을 수 있음)")

print()

# ----------------------------------------------------------------
# 테스트 2: MEDIUM → LOW 복귀 후 재탐지 확인
# ----------------------------------------------------------------
print("=" * 50)
print("[TEST 2] MEDIUM → LOW 복귀 후 재탐지 확인")
print("=" * 50)
print("※ 고엔트로피 랜덤 데이터를 여러 번 써서 Stage 1 탐지를 유도합니다.")
print("※ 10초 경과 후 LOW 복귀, 이후 write 시 다시 MEDIUM 진입되어야 합니다.")
print()

path2 = os.path.join(MOUNT, "low_test_2.bin")

# 1차 write → Stage 1 탐지 → SUSPICIOUS → MEDIUM 진입
print("  [1차] 고엔트로피 데이터 반복 write → MEDIUM 진입 예상")
for i in range(5):
    with open(path2, "wb") as f:
        f.write(os.urandom(4096))  # 랜덤 데이터 → 엔트로피 높음
    time.sleep(0.1)
print("  → 터미널 1에서 [SUSPICIOUS] 후 [STATE] LOW → MEDIUM 확인")
print()

# 10초 대기 → LOW 복귀
print("  10초 대기 중... (LOW 복귀 기다리는 중)")
for i in range(10, 0, -1):
    print(f"  {i}초 남음...", end="\r")
    time.sleep(1)
print()
print("  → 터미널 1에서 [REEVAL] 10초 경과 → Low 복귀 확인")
print("  → 터미널 1에서 [LOW] pid=XXXX 복귀 정리 완료 확인")
print()

# 2차 write → 재탐지로 다시 MEDIUM 진입해야 함
print("  [2차] 고엔트로피 데이터 반복 write → 재탐지 후 MEDIUM 재진입 예상")
for i in range(5):
    with open(path2, "wb") as f:
        f.write(os.urandom(4096))
    time.sleep(0.1)
print("  → 터미널 1에서 [STATE] pid=XXXX LOW → MEDIUM 다시 확인")
print()
print("[TEST 2] 터미널 1 로그에서 MEDIUM 재진입 확인하세요.")
print()

# ----------------------------------------------------------------
# 정리
# ----------------------------------------------------------------
print("=" * 50)
print("[정리] underlay 파일 확인")
print("=" * 50)
for fname in ["low_test_1.txt", "low_test_2.bin"]:
    upath = os.path.join(UNDERLAY, fname)
    exists = os.path.exists(upath)
    print(f"  {'✓' if exists else '✗'} {fname}: {'존재' if exists else '없음'}")

print()
print("테스트 완료. underlay 정리:")
print("  rm -f ~/test_underlay/low_test_*")
