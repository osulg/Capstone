"""
미끼(씨앗) 파일 트리 생성기 — 방법 B (run마다 무작위 분포).

run마다 시드로 파일 수 / 디렉터리 깊이 / 파일 크기 / 파일 종류를 뽑아
"현실적인 사용자 디렉터리"를 만든다. 정상·악성 수집이 같은 생성기와 같은
분포를 써야 모델이 미끼 조건(개수·크기·구조)을 라벨로 착각하지 않는다.

- 파일 수 : 로그 균등 [files_min, files_max]  (기본 50~2000)
- 깊이    : 균등 [1, 4]
- 크기    : 로그 균등 [2KB, 1MB], run 총량 상한(기본 100MB)
- 종류    : 텍스트 계열(저엔트로피) 위주 + 원래 압축된 포맷(zip/png 등) 일부

같은 시드 → 같은 트리 (재현 가능). 단독 실행으로 분포를 확인할 수 있다:
  python3 decoy_gen.py --out /tmp/decoy_test --seed 1
  python3 decoy_gen.py --stats 200
"""

import argparse
import io
import json
import math
import os
import random
import zipfile
import zlib

FILES_MIN, FILES_MAX = 50, 2000
DEPTH_MIN, DEPTH_MAX = 1, 4
SIZE_MIN_KB, SIZE_MAX_KB = 2, 1024
TOTAL_CAP_MB = 100

WORDS = ("report budget meeting project customer invoice quarter summary "
         "design review schedule contract payment order delivery status "
         "analysis result team plan update draft final total amount date "
         "name address phone note item price count week month year").split()

DIR_NAMES = ("documents projects reports photos archive backup work personal "
             "finance hr sales 2023 2024 2025 drafts shared clients misc").split()

# (확장자, 가중치, 생성 함수 이름). 텍스트 계열이 대부분을 차지하게 한다.
TYPES = [
    ("txt", 14, "text"), ("md", 4, "text"), ("log", 6, "log"),
    ("csv", 10, "csv"), ("json", 6, "json"), ("xml", 4, "xml"),
    ("html", 5, "html"), ("sql", 4, "sql"), ("pdf", 8, "pdf"),
    ("rtf", 3, "rtf"), ("svg", 2, "svg"), ("bmp", 3, "bmp"),
    ("docx", 7, "office"), ("xlsx", 5, "office"), ("pptx", 3, "office"),
    ("png", 4, "png"), ("zip", 2, "zip"),
]


def _loguniform(rng, lo, hi):
    return math.exp(rng.uniform(math.log(lo), math.log(hi)))


def sample_spec(seed, files_min=FILES_MIN, files_max=FILES_MAX, files_fixed=None):
    """시드 → 트리 사양. 파일 내용은 build()에서 같은 시드로 결정적으로 만든다."""
    rng = random.Random(seed)
    n = files_fixed or int(round(_loguniform(rng, files_min, files_max)))
    depth = rng.randint(DEPTH_MIN, DEPTH_MAX)
    exts = [t[0] for t in TYPES]
    weights = [t[1] for t in TYPES]
    sizes = [int(_loguniform(rng, SIZE_MIN_KB, SIZE_MAX_KB) * 1024) for _ in range(n)]
    cap = TOTAL_CAP_MB * 1024 * 1024
    total = sum(sizes)
    if total > cap:  # 분포 모양은 유지한 채 총량만 상한에 맞춘다
        scale = cap / total
        sizes = [max(1024, int(s * scale)) for s in sizes]
    return {
        "seed": seed, "files": n, "depth": depth,
        "exts": rng.choices(exts, weights=weights, k=n),
        "sizes": sizes,
    }


def _dirs(rng, depth):
    """깊이 depth의 디렉터리 후보 목록 (루트 포함)."""
    paths = [""]
    frontier = [""]
    for _ in range(depth):
        nxt = []
        for p in frontier:
            for name in rng.sample(DIR_NAMES, rng.randint(1, 3)):
                q = os.path.join(p, name)
                paths.append(q)
                nxt.append(q)
        frontier = nxt
    return paths


def _words(rng, nbytes):
    out, size = [], 0
    while size < nbytes:
        line = " ".join(rng.choices(WORDS, k=rng.randint(6, 14))) + ".\n"
        out.append(line)
        size += len(line)
    return "".join(out)[:nbytes]


def _content(kind, rng, size):
    if kind == "text":
        return _words(rng, size).encode()
    if kind == "log":
        lines, n = [], 0
        while n < size:
            s = (f"2025-{rng.randint(1,12):02d}-{rng.randint(1,28):02d} "
                 f"{rng.randint(0,23):02d}:{rng.randint(0,59):02d} INFO "
                 + " ".join(rng.choices(WORDS, k=6)) + "\n")
            lines.append(s); n += len(s)
        return "".join(lines)[:size].encode()
    if kind == "csv":
        rows, n = ["id,name,amount,date\n"], 0
        while n < size:
            s = (f"{rng.randint(1,99999)},{rng.choice(WORDS)},"
                 f"{rng.randint(1,9999)}.{rng.randint(0,99):02d},2025-01-01\n")
            rows.append(s); n += len(s)
        return "".join(rows)[:size].encode()
    if kind == "json":
        body = _words(rng, max(size - 32, 16)).replace('"', "'").replace("\n", " ")
        return ('{"title": "%s", "body": "%s"}' % (rng.choice(WORDS), body)).encode()
    if kind == "xml":
        return ("<?xml version=\"1.0\"?>\n<doc>\n" + _words(rng, size)
                + "\n</doc>\n").encode()
    if kind == "html":
        return ("<!DOCTYPE html><html><body><p>" + _words(rng, size)
                + "</p></body></html>\n").encode()
    if kind == "sql":
        return ("CREATE TABLE t(id INTEGER, v TEXT);\n"
                + "".join(f"INSERT INTO t VALUES({i}, '{rng.choice(WORDS)}');\n"
                          for i in range(max(size // 40, 1)))).encode()[:max(size, 64)]
    if kind == "rtf":
        return ("{\\rtf1\\ansi " + _words(rng, size) + "}").encode()
    if kind == "svg":
        return ("<svg xmlns=\"http://www.w3.org/2000/svg\"><text>"
                + _words(rng, size) + "</text></svg>").encode()
    if kind == "pdf":
        # 비압축 스트림의 최소 PDF (저엔트로피, 유효 헤더)
        text = _words(rng, size).replace("(", "").replace(")", "").replace("\n", " ")
        stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET"
        objs = ["<< /Type /Catalog /Pages 2 0 R >>",
                "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
                "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>",
                f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream"]
        out = "%PDF-1.4\n"
        for i, o in enumerate(objs, 1):
            out += f"{i} 0 obj\n{o}\nendobj\n"
        return (out + "trailer\n<< /Root 1 0 R >>\n%%EOF\n").encode()
    if kind == "bmp":
        # 비압축 비트맵(그라데이션) — 이미지지만 저엔트로피
        w = max(int(math.sqrt(max(size - 54, 3) / 3)), 1)
        row = bytes((x * 255 // w) for x in range(w) for _ in range(3))
        pad = (4 - len(row) % 4) % 4
        pix = (row + b"\0" * pad) * w
        hdr = (b"BM" + (54 + len(pix)).to_bytes(4, "little") + b"\0\0\0\0"
               + (54).to_bytes(4, "little") + (40).to_bytes(4, "little")
               + w.to_bytes(4, "little") + w.to_bytes(4, "little")
               + (1).to_bytes(2, "little") + (24).to_bytes(2, "little")
               + b"\0" * 24)
        return hdr + pix
    if kind == "png":
        # 실제 PNG처럼 zlib 압축 (원래 고엔트로피인 정상 포맷)
        raw = _words(rng, size).encode() + rng.randbytes(size // 4)
        comp = zlib.compress(raw)
        return b"\x89PNG\r\n\x1a\n" + comp
    if kind in ("office", "zip"):
        # docx/xlsx/pptx도 실제로는 zip 컨테이너(압축 → 고엔트로피)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
            # 고정 시각: 같은 시드 → 같은 바이트 (재현성)
            fixed = (2025, 1, 1, 0, 0, 0)
            z.writestr(zipfile.ZipInfo("[Content_Types].xml", fixed), "<Types/>")
            z.writestr(zipfile.ZipInfo("content.xml", fixed),
                       "<doc>" + _words(rng, size * 3) + "</doc>",
                       compress_type=zipfile.ZIP_DEFLATED)
        return buf.getvalue()
    raise ValueError(kind)


def build(root, spec):
    """spec대로 root 아래에 트리를 만든다. 요약 dict 반환."""
    rng = random.Random(spec["seed"] ^ 0x5EED)
    kinds = {t[0]: t[2] for t in TYPES}
    dirs = _dirs(rng, spec["depth"])
    used_dirs, total = set(), 0
    for i, (ext, size) in enumerate(zip(spec["exts"], spec["sizes"])):
        d = os.path.join(root, rng.choice(dirs))
        os.makedirs(d, exist_ok=True)
        used_dirs.add(d)
        name = f"{rng.choice(WORDS)}_{rng.choice(WORDS)}_{i:04d}.{ext}"
        data = _content(kinds[ext], rng, size)
        with open(os.path.join(d, name), "wb") as f:
            f.write(data)
        total += len(data)
    return {"decoy_seed": spec["seed"], "decoy_files": spec["files"],
            "decoy_depth": spec["depth"], "decoy_dirs": len(used_dirs),
            "decoy_bytes": total}


def main():
    ap = argparse.ArgumentParser(description="미끼 파일 트리 생성기 (방법 B)")
    ap.add_argument("--out", help="생성할 루트 디렉터리")
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--files", type=int, help="파일 수 고정 (L 평가셋 등)")
    ap.add_argument("--stats", type=int, help="시드 N개의 사양 분포만 출력 (파일 생성 안 함)")
    a = ap.parse_args()
    if a.stats:
        specs = [sample_spec(s, files_fixed=a.files) for s in range(a.stats)]
        n = sorted(s["files"] for s in specs)
        mb = sorted(sum(s["sizes"]) / 2**20 for s in specs)
        q = lambda v: [round(v[int(len(v) * p)], 1) for p in (0, .25, .5, .75, .99)]
        print("files  min/25/50/75/99%:", q(n))
        print("MB     min/25/50/75/99%:", q(mb))
        print("depth  분포:", {d: sum(s["depth"] == d for s in specs) for d in range(1, 5)})
        return
    if not a.out:
        ap.error("--out 또는 --stats 필요")
    print(json.dumps(build(a.out, sample_spec(a.seed, files_fixed=a.files)),
                     ensure_ascii=False))


if __name__ == "__main__":
    main()
