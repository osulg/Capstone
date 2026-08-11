# test_pdf.py
import os
import time

target = os.path.expanduser("~/test_mount")

print(f"[TEST] PID: {os.getpid()}")

# 정상 PDF 쓰기
with open(f"{target}/test_normal.pdf", "wb") as f:
    f.write(b"%PDF-1.4 normal content")  # 정상 헤더
print("[TEST] 정상 PDF 작성")

time.sleep(0.5)

# 깨진 PDF 쓰기 (랜섬웨어처럼)
with open(f"{target}/test_broken.pdf", "wb") as f:
    f.write(b"\x00\x01\x02\x03 encrypted!")  # 깨진 헤더
print("[TEST] 깨진 PDF 작성")

time.sleep(15)