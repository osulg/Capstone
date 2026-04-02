import os
import shutil

BASE_DIR = "/home/osulg/capstone"

result_path = os.path.join(BASE_DIR, "Result")
backup_base = os.path.join(BASE_DIR, "backup")

os.makedirs(backup_base, exist_ok=True)

folders = ["byte_ngram", "opcode_ngram"]

for folder in folders:
    root_path = os.path.join(result_path, folder)
    backup_root = os.path.join(backup_base, folder)

    for root, dirs, files in os.walk(root_path):

        # 현재 위치에 대응되는 backup 경로 생성
        relative_path = os.path.relpath(root, root_path)
        backup_dir = os.path.join(backup_root, relative_path)
        os.makedirs(backup_dir, exist_ok=True)

        for filename in files:
            file_path = os.path.join(root, filename)

            keep = False

            # 조건
            if folder == "byte_ngram" and "n3_k300" in filename:
                keep = True

            elif folder == "opcode_ngram" and "n3_k500" in filename:
                keep = True

            # 이동
            if not keep:
                shutil.move(file_path, os.path.join(backup_dir, filename))
                print(f"[이동됨] {file_path}")
            else:
                print(f"[유지] {file_path}")
