#!/usr/bin/env python3
from pathlib import Path
import subprocess

target = Path.home() / "guardfs_attack_collection_test"
target.mkdir(parents=True, exist_ok=True)

files = []

# root process의 파일 생성
for i in range(12):
    p = target / f"test_{i}.txt"
    p.write_text("attack collection pipeline test\n" * 5)
    files.append(p)

# descendant process 발생
subprocess.run(
    ["/bin/bash", "-c",
     f'echo child-process-test > "{target}/child.txt"'],
    check=True
)

# root process의 읽기/삭제
for p in files:
    _ = p.read_text()

for p in files:
    p.unlink()

print("attack collection pipeline test complete")
