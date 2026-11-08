"""공격 종료 후 문서 내용을 읽기만 하는 별도 검증 프로세스."""

import argparse
import json
import stat
from pathlib import Path

from experiments.simulators.sim_scn_icefire import document_bytes
from scenarios.icefire_config import FILE_COUNT, FILE_SIZE_KIB


def compare_documents(mount: Path, underlay: Path, workspace: str) -> list[dict]:
    results = []
    for index in range(FILE_COUNT):
        name = f"doc_{index:03d}{('.docx', '.pdf', '.xlsx')[index % 3]}"
        expected = document_bytes(name, FILE_SIZE_KIB * 1024)
        item = {"name": name}
        for label, root in (("mount", mount), ("underlay", underlay)):
            path = root / workspace / name
            try:
                if not stat.S_ISREG(path.lstat().st_mode):
                    raise OSError("일반 파일이 아닙니다.")
                if path.resolve().parent != (root / workspace).resolve():
                    raise OSError("작업 경로 밖의 파일입니다.")
                with path.open("rb") as stream:
                    item[label] = "matched" if stream.read(len(expected) + 1) == expected else "changed"
            except FileNotFoundError:
                item[label] = "missing"
            except OSError as error:
                item[label] = "unknown"
                item[f"{label}_error"] = str(error)
        results.append(item)
    return results


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mount", type=Path, required=True)
    parser.add_argument("--underlay", type=Path, required=True)
    parser.add_argument("--workspace", required=True)
    args = parser.parse_args()
    import re
    if re.fullmatch(r"s01_[0-9a-f]{32}", args.workspace) is None:
        parser.error("잘못된 workspace 이름입니다.")
    print(json.dumps(compare_documents(args.mount, args.underlay, args.workspace), ensure_ascii=False))


if __name__ == "__main__":
    main()
