from pathlib import Path

target = Path.home() / "guardfs_benign_temp_cleanup"
target.mkdir(parents=True, exist_ok=True)

files = []

# 임시 파일 대량 생성
for i in range(20):
    p = target / f"temp_work_{i}.txt"
    with open(p, "w", encoding="utf-8") as f:
        f.write(("normal temporary work data\n" * 10))
    files.append(p)

# 생성한 파일 다시 읽기
for p in files:
    with open(p, "r", encoding="utf-8") as f:
        _ = f.read()

# 작업 완료 후 임시 파일 정리
for p in files:
    p.unlink()

print("benign temp cleanup complete")
