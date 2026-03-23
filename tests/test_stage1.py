#!/usr/bin/env python3
"""
실제 FUSE 마운트포인트에 write해서 탐지 트리거 테스트
passthrough.py가 실행 중인 상태에서 돌려야 함
"""
import os
import time

MOUNT = "mnt/"       # 마운트포인트 경로로 바꿔주세요
HONEYPOT_DIR = f"{MOUNT}/honeypot"

def write_buf(path: str, buf: bytes):
    """실제 파일에 write → FUSE write() 핸들러 통과"""
    with open(path, "wb") as f:
        f.write(buf)
    print(f"  → wrote {len(buf)}B to {path}")

# ── 1. Honeypot 테스트 ───────────────────────────────────────────────────────
def test_honeypot():
    print("\n[Honeypot] honeypot 파일에 write")
    path = f"{HONEYPOT_DIR}/decoy.txt"
    write_buf(path, b"trigger honeypot" * 20)
    time.sleep(0.5)  # 이벤트 처리 대기

# ── 2. ExtChange 테스트 ─────────────────────────────────────────────────────
def test_ext_change():
    print("\n[ExtChange] .txt → .locked rename")
    src = f"{MOUNT}/test_file.txt"
    dst = f"{MOUNT}/test_file.locked"
    write_buf(src, b"normal content" * 10)
    os.rename(src, dst)
    time.sleep(0.5)

# ── 3. Entropy 테스트 ───────────────────────────────────────────────────────
def test_entropy():
    print("\n[Entropy] random 256B 이상 write")
    path = f"{MOUNT}/random.bin"
    buf = os.urandom(512)   # 고엔트로피 랜덤 바이트
    write_buf(path, buf)
    time.sleep(0.5)

if __name__ == "__main__":
    print("passthrough.py 실행 중인지 확인하세요!")
    print(f"MOUNT={MOUNT}")
    test_honeypot()
    test_ext_change()
    test_entropy()
    print("\nDone. passthrough.py 로그에서 [STAGE1] 확인하세요.")
