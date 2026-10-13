from pathlib import Path

target = Path.home() / "guardfs_benign_dataset"
target.mkdir(parents=True, exist_ok=True)

files = []

# 정상적인 문서 생성
for i in range(10):
    p = target / f"document_{i}.txt"

    with open(p, "w", encoding="utf-8") as f:
        f.write(f"normal file {i}\n" * 5)

    files.append(p)

# 생성한 파일 다시 읽기
for p in files:
    with open(p, "r", encoding="utf-8") as f:
        _ = f.read()

# 일부 파일 정상 삭제
for p in files[:5]:
    p.unlink()

print("benign workload complete")
