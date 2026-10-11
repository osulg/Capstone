"""
파일 상태 탭용 폴더 스캐너 (읽기 전용)

보호 폴더(GuardFS underlay)와 보호 없는 비교 폴더의 파일을 읽어
엔트로피로 정상 / 암호화 의심을 판정한다.

안전 규칙
- 허용된 루트 폴더 안쪽만 읽는다. 심볼릭 링크로 밖을 가리키는 경로는 거부한다.
- 파일마다 앞부분 SAMPLE_BYTES 만 읽는다.
- 쓰기·삭제 기능은 없다.
"""

from __future__ import annotations

import math
import os
import sys
from collections import Counter

# GuardFS와 같은 엔트로피 기준을 쓴다 (guardfs/common/config.py).
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
try:
    from guardfs.common.config import ENTROPY_THRESHOLD
except ImportError:
    ENTROPY_THRESHOLD = 7.0

SAMPLE_BYTES = 4096        # 엔트로피 계산에 쓰는 앞부분 크기
MIN_SAMPLE_BYTES = 64      # 이보다 작으면 엔트로피 판정이 무의미해 '판정 불가'
PREVIEW_BYTES = 512
HEX_PREVIEW_BYTES = 96
MAX_FILES = 300
# 보호 폴더 최상위의 honeypot/ 은 GuardFS 미끼 파일 (guardfs/common/paths.get_honeypot_dir).
# 목록에는 '미끼 파일'로 따로 표시하고, 정상/암호화 판정 대상에서는 뺀다.
HONEYPOT_DIR = "honeypot"
RANSOM_EXTS = {".locked", ".enc", ".encrypted", ".crypt", ".crypted", ".lock", ".ransom"}

FOLDERS = [
    {
        "key": "protected",
        "label": "보호 폴더 (GuardFS)",
        "path": os.path.expanduser(os.environ.get("DASH_PROTECTED_DIR", "~/guardfs_runtime/underlay")),
    },
    {
        "key": "unprotected",
        "label": "보호 없는 폴더",
        "path": os.path.expanduser(os.environ.get("DASH_UNPROTECTED_DIR", "~/guardfs_demo/unprotected")),
    },
]


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def _folder(key: str) -> dict | None:
    return next((f for f in FOLDERS if f["key"] == key), None)


def _safe_join(root: str, rel: str) -> str | None:
    """root 안쪽 경로만 허용한다 (../, 절대경로, 바깥을 가리키는 심볼릭 링크 거부)."""
    root_real = os.path.realpath(root)
    target = os.path.realpath(os.path.join(root_real, rel))
    if target != root_real and not target.startswith(root_real + os.sep):
        return None
    return target


def _read_head(path: str, size: int) -> bytes:
    with open(path, "rb") as f:
        return f.read(size)


def _file_info(root: str, path: str, honeypot: bool = False) -> dict:
    st = os.stat(path)
    rel = os.path.relpath(path, root)
    info = {
        "path": rel,
        "name": os.path.basename(rel),
        "dir": os.path.dirname(rel),
        "size": st.st_size,
        "mtime": st.st_mtime,
        "entropy": None,
        "state": "unknown",
        "ransom_ext": os.path.splitext(rel)[1].lower() in RANSOM_EXTS,
        "honeypot": honeypot,
    }
    try:
        head = _read_head(path, SAMPLE_BYTES)
    except OSError:
        info["state"] = "unreadable"
        return info
    if honeypot:
        info["entropy"] = round(shannon_entropy(head), 2) if len(head) >= MIN_SAMPLE_BYTES else None
        info["state"] = "honeypot"
        return info
    if len(head) >= MIN_SAMPLE_BYTES:
        ent = shannon_entropy(head)
        info["entropy"] = round(ent, 2)
        info["state"] = "encrypted" if ent >= ENTROPY_THRESHOLD else "ok"
    return info


def scan_folder(folder: dict) -> dict:
    root = folder["path"]
    out = {"key": folder["key"], "label": folder["label"], "path": root,
           "exists": os.path.isdir(root), "files": [], "truncated": False}
    if not out["exists"]:
        return out

    root_real = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root_real):
        dirnames[:] = sorted(d for d in dirnames
                             if not d.startswith("."))
        for fn in sorted(filenames):
            if fn.startswith("."):
                continue
            full = os.path.join(dirpath, fn)
            if os.path.islink(full) or not os.path.isfile(full):
                continue
            if len(out["files"]) >= MAX_FILES:
                out["truncated"] = True
                return out
            try:
                rel_top = os.path.relpath(full, root_real).split(os.sep, 1)[0]
                is_honeypot = folder["key"] == "protected" and rel_top == HONEYPOT_DIR
                out["files"].append(_file_info(root_real, full, is_honeypot))
            except OSError:
                continue  # 스캔 중 삭제·이동된 파일
    # 미끼 파일을 목록 맨 위로 (시연 시 바로 보이도록)
    out["files"].sort(key=lambda f: not f["honeypot"])
    return out


def scan_all() -> dict:
    return {"threshold": ENTROPY_THRESHOLD, "folders": [scan_folder(f) for f in FOLDERS]}


def _decode_text(head: bytes) -> str | None:
    """UTF-8 텍스트면 문자열, 아니면 None. 앞부분만 읽어 끝에서 잘린 멀티바이트 문자는 허용한다."""
    for cut in range(4):
        try:
            text = head[: len(head) - cut].decode("utf-8")
            break
        except UnicodeDecodeError:
            continue
    else:
        return None
    if not text:
        return None
    printable = sum(ch.isprintable() or ch in "\n\r\t" for ch in text)
    return text if printable / len(text) > 0.95 else None


def preview(key: str, rel: str) -> dict | None:
    folder = _folder(key)
    if folder is None or not rel:
        return None
    path = _safe_join(folder["path"], rel)
    if path is None or not os.path.isfile(path):
        return None
    head = _read_head(path, PREVIEW_BYTES)
    text = _decode_text(head)
    if text is not None:
        return {"path": rel, "kind": "text", "content": text}
    data = head[:HEX_PREVIEW_BYTES]
    lines = [" ".join(f"{b:02x}" for b in data[i:i + 16]) for i in range(0, len(data), 16)]
    return {"path": rel, "kind": "hex", "content": "\n".join(lines), "bytes": len(data)}
