"""
동적 모델 피처의 "확장자 변경 rename" 판정 규칙.

학습(models/dynamic/collect/features.py)과 런타임(passthrough.py PidStats)이
이 함수 하나를 공유한다. 규칙이 어긋나면 학습 분포와 추론 분포가 달라진다.

v5: 확장자가 다르면 무조건 변경 (rf_model_v5.pkl 학습 기준).
v6: 임시 파일 → 원래 이름 rename("안전한 저장": rsync, sed -i, git, 편집기)과
    확장자 제거(shred, *.lock → 원래 이름)는 확장자 변경으로 세지 않는다.
    (근거: models/dynamic/dataset_v6/RESULTS.md)
"""

import posixpath
import re

# 안전한 저장에 쓰이는 임시 파일 이름
TEMP_NAME = re.compile(
    r"^(\.|#)"                               # .name.XXXXXX (rsync), .#name, 숨김 임시파일
    r"|^sed[A-Za-z0-9]{6}$"                  # sed -i
    r"|^tmp[A-Za-z0-9_]{4,}$|^tmp_obj_"      # mkstemp, git 객체
    r"|(\.tmp|\.temp|\.swp|\.part|\.lock|~)$",
    re.IGNORECASE)


def ext_of(path) -> str:
    if not path:
        return ""
    return posixpath.splitext(path)[1].lower()


def is_ext_change(old_path, new_path, rule="v5") -> bool:
    if not new_path:
        return False
    old_ext, new_ext = ext_of(old_path), ext_of(new_path)
    if old_ext == new_ext:
        return False
    if rule == "v6":
        if not new_ext:
            return False
        if TEMP_NAME.search(posixpath.basename(old_path or "")):
            return False
    return True
