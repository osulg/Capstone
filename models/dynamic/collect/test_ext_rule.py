"""guardfs/common/ext_rule.py 확장자 변경 판정 테스트 (FUSE 불필요)."""
import os
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from guardfs.common.ext_rule import is_ext_change  # noqa: E402

# (old, new, v5 기대값, v6 기대값)
CASES = [
    ("/a/.report.docx.Xy12Ab", "/a/report.docx", True, False),    # rsync 임시파일
    ("/a/sedAbC123", "/a/note.txt", True, False),                 # sed -i
    ("/r/.git/index.lock", "/r/.git/index", True, False),         # git lock
    ("/d/a.txt.swp", "/d/a.txt", True, False),                    # 편집기 swap
    ("/d/file.txt", "/d/0000000", True, False),                   # shred: 확장자 제거
    ("/d/report.docx", "/d/report.docx.encryp", True, True),      # 확장자 덧붙이기
    ("/d/photo.png", "/d/photo.png.babyk", True, True),
    ("/d/file_0001.dat", "/d/file_0001.dat.bak", True, True),     # 정상 확장자 일괄 변경도 그대로 셈
    ("/d/a.txt", "/d/b.txt", False, False),                       # 확장자 같음
    ("/d/a.txt", None, False, False),                             # new_path 없음
]


def test_cases():
    for old, new, v5, v6 in CASES:
        assert is_ext_change(old, new, "v5") is v5, (old, new, "v5")
        assert is_ext_change(old, new, "v6") is v6, (old, new, "v6")


if __name__ == "__main__":
    test_cases()
    print(f"ok ({len(CASES)} cases)")
