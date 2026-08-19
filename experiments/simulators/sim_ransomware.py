"""
랜섬웨어 동작 시뮬레이터
실제 랜섬웨어처럼 mnt/ 디렉토리 내 파일을 AES-256-CBC로 암호화

동작 순서:
  1. mnt/에 정상 파일 5개 생성
  2. 각 파일을 AES-256-CBC로 암호화하여 덮어씀 (랜섬웨어 방식)
  3. FUSE write 콜백에서 엔트로피 탐지 → [STAGE1] 로그 확인

실행 전 FUSE 마운트 필요:
  python passthrough.py mnt/ underlay/
"""

import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

MOUNT    = "mnt"
KEY      = os.urandom(32)   # AES-256 키 (랜섬웨어는 이 키를 C2 서버로 전송)
IV       = os.urandom(16)


def pad(data: bytes) -> bytes:
    """PKCS7 패딩"""
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len] * pad_len)


def aes_encrypt(data: bytes) -> bytes:
    """AES-256-CBC 암호화"""
    cipher = Cipher(algorithms.AES(KEY), modes.CBC(IV))
    enc    = cipher.encryptor()
    return enc.update(pad(data)) + enc.finalize()


# ────────────────────────────────────────────────
# Step 1. 정상 파일 생성
# ────────────────────────────────────────────────

normal_files = {
    "report.txt":    ("This is a financial report document. " * 100).encode(),
    "resume.txt":    ("John Doe - Software Engineer. Experience: 5 years. " * 80).encode(),
    "notes.txt":     ("Meeting notes: discuss project timeline and budget. " * 120).encode(),
    "readme.txt":    ("This project is a FUSE-based file system monitor. " * 90).encode(),
    "diary.txt":     ("Today was a great day. I learned a lot about security. " * 110).encode(),
}

print()
print("=" * 60)
print("  랜섬웨어 동작 시뮬레이터")
print("=" * 60)
print()
print("[Step 1] 정상 파일 생성 중...")

for filename, content in normal_files.items():
    path = os.path.join(MOUNT, filename)
    with open(path, "wb") as f:
        f.write(content)
    print(f"  생성: {filename} ({len(content)} bytes)")

print()
print("정상 파일 생성 완료. 1초 후 암호화 시작...")
time.sleep(1)

# ────────────────────────────────────────────────
# Step 2. 랜섬웨어처럼 각 파일을 AES로 암호화
# ────────────────────────────────────────────────

print()
print("[Step 2] 파일 암호화 시작 (랜섬웨어 시뮬레이션)...")
print("  터미널 1에서 [STAGE1] 로그를 확인하세요!")
print()

for filename in normal_files:
    path = os.path.join(MOUNT, filename)

    # 원본 파일 읽기
    with open(path, "rb") as f:
        original = f.read()

    # AES-256-CBC 암호화
    encrypted = aes_encrypt(original)

    # 암호화된 내용으로 덮어쓰기 (랜섬웨어 핵심 동작)
    with open(path, "wb") as f:
        f.write(encrypted)

    print(f"  암호화 완료: {filename} → {len(encrypted)} bytes")
    time.sleep(0.3)  # 파일 간 간격

# ────────────────────────────────────────────────
# 결과 안내
# ────────────────────────────────────────────────

print()
print("=" * 60)
print("  시뮬레이션 완료!")
print()
print("  터미널 1에서 확인할 것:")
print("  [STAGE1] pid=? op=write path=.../report.txt reason=EntropyDetector")
print("  [STAGE1] pid=? op=write path=.../resume.txt reason=EntropyDetector")
print("  [STAGE1] pid=? op=write path=.../notes.txt  reason=EntropyDetector")
print("  [STAGE1] pid=? op=write path=.../readme.txt reason=EntropyDetector")
print("  [STAGE1] pid=? op=write path=.../diary.txt  reason=EntropyDetector")
print()
print("  로그 파일 확인:")
print("  cat guardfs_log.jsonl | grep -E 'report|resume|notes|readme|diary'")
print("=" * 60)
