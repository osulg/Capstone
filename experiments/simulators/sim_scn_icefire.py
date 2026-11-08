#!/usr/bin/env python3
"""
사례 ① IceFire 랜섬웨어 — 파일연산 모의 재현 (GuardFS/HoldFS 탐지 검증용).

근거: SentinelLABS, "IceFire Ransomware Returns | Now Targeting Linux
Enterprise Networks" (2023-03).

이 스크립트는 실제 랜섬웨어가 아니다. 암호키·복호·C2·랜섬 수익화가 없고,
이 스크립트가 만든 전용 workdir 의 더미 파일만 난수로 덮어쓴다.

재현하는 구간 (문서 2.3~2.4, + 노트 생성, + 자기 삭제):
  - 2.3 대상 탐색·선별 : 준비한 더미 문서를 open/read
  - 2.4 파일 암호화     : 고엔트로피 난수로 덮어써 원본 바이트·헤더 매직 파괴
                          → .ifire 확장자로 rename → 디렉터리마다 모의 노트 생성
  - 2.5 자기 삭제       : 공격 역할이 자신이 만든 '도구 표식' 파일을 unlink

재현에서 제외(배경·범위 밖):
  - 2.1 초기 접근(IBM Aspera Faspex CVE-2022-47986) — "이미 셸 확보" 전제로 대체
  - 2.2 페이로드 반입(wget/chmod/드롭릿) — ingress 는 FUSE 밖
  이 구간들은 재현하지 않고 전제로만 둔다.

탐지 관점(문서 1장): 비신뢰 exe 이므로 신뢰 면제 없이 Stage 1(엔트로피·매직·
확장자) 규칙에 즉시 걸린다. GuardFS 에서는 비신뢰 실행 경로 → 선제 MEDIUM,
고엔트로피 write → EntropyDetector/EntropyBurstDetector, .ifire rename →
ExtChangeDetector(계열 확장자 추가 시 즉시, 아니면 5개 누적) → Stage 2 → HIGH.

테스트 방법 (Linux/Ubuntu, 터미널 두 개):
  1) 터미널 A: GuardFS 를 detection 모드로 실행하고 mount 성공 확인
       cd ~/Capstone && bash scripts/run_guardfs.sh
     (또는 대시보드까지: bash dashboard/run_all.sh)
  2) 터미널 B:
       cd ~/Capstone && source venv/bin/activate
       mountpoint ~/guardfs_runtime/mount
       python3 experiments/simulators/sim_scn_icefire.py \
           ~/guardfs_runtime/mount/sim_icefire --keep

확인 기준:
  - 공격 PID 출력 후 터미널 A/대시보드에서 해당 PID 의 상태 격상과 탐지 사유
    (EntropyDetector/EntropyBurstDetector/ExtChangeDetector, ML dyn/stat/score,
    HIGH 사유)를 대조한다. HIGH 전환 후 write/rename/unlink 차단과 SIGSTOP 을
    확인한다.
  - 차단으로 인한 ENOENT 등 파일 오류는 GuardFS 상태/이벤트 로그와 함께 원인을
    확인한다(차단 여부를 이 스크립트 종료코드만으로 단정하지 않는다).

준비 로직만 검사하려면:
  python experiments/tests/test_scenario_sims.py
"""

from __future__ import annotations

import argparse
import io
import os
import sys
import time
import zipfile
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import scenario_lib as lib  # noqa: E402

# IceFire 랜섬노트 파일명(보고서 관찰치). 내용은 수익화 문구 없는 모의 텍스트.
NOTE_NAME = "iFire-readme.txt"
NOTE_BODY = (
    "[SIMULATION] This is a GuardFS detection test artifact.\n"
    "No real encryption, key, or contact information is involved.\n"
)
# 공격 도구가 자기 삭제하는 것을 모사하기 위한 표식 파일(이 스크립트가 만든다).
SELF_MARKER = "demo"


_PKG_REL = "http://schemas.openxmlformats.org/package/2006/relationships"
_OFFICE_REL = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_CONTENT_NS = "http://schemas.openxmlformats.org/package/2006/content-types"
_SHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
_WORD_NS = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"


def _relationships(target: str, kind: str) -> bytes:
    return (
        f'<Relationships xmlns="{_PKG_REL}">'
        f'<Relationship Id="rId1" Type="{_OFFICE_REL}/{kind}" '
        f'Target="{target}"/></Relationships>'
    ).encode()


def _content_types(overrides: dict[str, str]) -> bytes:
    entries = "".join(
        f'<Override PartName="/{name}" ContentType="{mime}"/>'
        for name, mime in overrides.items()
    )
    return (
        f'<Types xmlns="{_CONTENT_NS}">'
        '<Default Extension="rels" '
        'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        f"{entries}</Types>"
    ).encode()


def _zip_bytes(parts: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, content in parts.items():
            # Fixed metadata makes the entire fixture reproducible.
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            info.compress_type = zipfile.ZIP_STORED
            archive.writestr(info, content)
    return output.getvalue()


def _office_bytes(ext: str, size: int) -> bytes:
    if ext == ".docx":
        main = "word/document.xml"
        parts = {
            "[Content_Types].xml": _content_types(
                {
                    main: "application/vnd.openxmlformats-officedocument."
                    "wordprocessingml.document.main+xml",
                }
            ),
            "_rels/.rels": _relationships(main, "officeDocument"),
            main: (
                f'<w:document xmlns:w="{_WORD_NS}"><w:body><w:p><w:r>'
                "<w:t>GuardFS simulation document. No real user data.</w:t>"
                "</w:r></w:p><w:sectPr/></w:body></w:document>"
            ).encode(),
        }
    else:
        main = "xl/worksheets/sheet1.xml"
        parts = {
            "[Content_Types].xml": _content_types(
                {
                    "xl/workbook.xml": "application/vnd.openxmlformats-officedocument."
                    "spreadsheetml.sheet.main+xml",
                    main: "application/vnd.openxmlformats-officedocument."
                    "spreadsheetml.worksheet+xml",
                }
            ),
            "_rels/.rels": _relationships("xl/workbook.xml", "officeDocument"),
            "xl/workbook.xml": (
                f'<workbook xmlns="{_SHEET_NS}" xmlns:r="{_OFFICE_REL}">'
                '<sheets><sheet name="GuardFS" sheetId="1" r:id="rId1"/>'
                "</sheets></workbook>"
            ).encode(),
            "xl/_rels/workbook.xml.rels": _relationships(
                "worksheets/sheet1.xml", "worksheet"
            ),
            main: (
                f'<worksheet xmlns="{_SHEET_NS}"><sheetData>'
                '<row r="1"><c r="A1" t="inlineStr"><is>'
                "<t>GuardFS simulation spreadsheet</t></is></c></row>"
                "</sheetData></worksheet>"
            ).encode(),
        }

    padding = size - len(_zip_bytes(parts))
    if padding < 0:
        raise ValueError(f"{ext}: requested size is too small: {size}")

    # XML permits trailing whitespace. Store without compression to maintain
    # the requested byte size and avoid random, high-entropy preparation data.
    parts[main] += b" " * padding
    result = _zip_bytes(parts)
    if len(result) != size:
        raise ValueError("unexpected Office fixture size")
    return result


def _pdf_bytes(size: int) -> bytes:
    def build(padding: int) -> bytes:
        stream = (
            b"BT /F1 18 Tf 72 720 Td (GuardFS simulation PDF) Tj ET\n"
            + b" " * padding
            + b"\n"
        )
        objects = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>",
            b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
            f"<< /Length {len(stream)} >>\nstream\n".encode("ascii")
            + stream
            + b"endstream",
        ]
        output = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for number, body in enumerate(objects, 1):
            offsets.append(len(output))
            output += f"{number} 0 obj\n".encode("ascii") + body + b"\nendobj\n"
        xref = len(output)
        output += b"xref\n0 6\n0000000000 65535 f \n"
        for offset in offsets[1:]:
            output += f"{offset:010d} 00000 n \n".encode("ascii")
        output += (
            f"trailer\n<< /Size 6 /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n"
        ).encode("ascii")
        return bytes(output)

    padding = 0
    for _ in range(8):
        result = build(padding)
        difference = size - len(result)
        if difference == 0:
            return result
        padding += difference
        if padding < 0:
            break
    raise ValueError(f"cannot create PDF of requested size: {size}")


def document_bytes(name: str, size: int) -> bytes:
    """Expected complete file content; deterministic across separate processes."""
    ext = Path(name).suffix.lower()
    if ext in {".docx", ".xlsx"}:
        return _office_bytes(ext, size)
    if ext == ".pdf":
        return _pdf_bytes(size)
    raise ValueError(f"unsupported fixture extension: {ext}")


def prepare_documents(workdir, names, size, timeout) -> bool:
    expected = {name: document_bytes(name, size) for name in names}

    def make() -> int:
        for name, body in expected.items():
            path = os.path.join(workdir, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as handle:
                handle.write(body)
        return 0

    return lib.run_in_child(make, "document preparation", timeout)


def wait_for_documents(workdir, names, size, timeout) -> bool:
    expected = {name: document_bytes(name, size) for name in names}

    def ready() -> bool:
        for name, body in expected.items():
            try:
                with open(os.path.join(workdir, name), "rb") as handle:
                    if handle.read(size + 1) != body:
                        return False
            except FileNotFoundError:
                return False
        return True

    def wait() -> int:
        deadline = time.monotonic() + timeout
        while True:
            if ready():
                return 0
            if time.monotonic() >= deadline:
                lib.err("document visibility timed out; attack will not start")
                return 1
            time.sleep(0.1)

    return lib.run_in_child(wait, "document visibility", timeout)


def parse_args():
    p = argparse.ArgumentParser(description="IceFire 파일연산 모의 재현")
    p.add_argument("target", help="GuardFS 마운트 안의 대상 폴더 (없으면 생성)")
    p.add_argument("--files", type=int, default=12, help="테스트 문서 개수")
    p.add_argument("--size-kb", type=int, default=64, help="파일당 크기(KB)")
    p.add_argument(
        "--chunk-kb", type=int, default=16, help="한 번에 쓰는 난수 크기(KB)"
    )
    p.add_argument("--ext", default=".ifire", help="암호화 후 붙일 확장자")
    p.add_argument(
        "--delay",
        type=float,
        default=0.15,
        help="파일 간 대기(초). Stage2 재평가(1초 주기)가 개입할 시간을 준다",
    )
    p.add_argument("--duration", type=float, default=30.0, help="최대 반복 시간(초)")
    p.add_argument("--keep", action="store_true", help="종료 후 테스트 파일 보존")
    p.add_argument(
        "--prepare-timeout",
        type=float,
        default=30.0,
        help="준비/공개 확인 단계별 최대 대기 시간(초)",
    )
    p.add_argument(
        "--prepare-only",
        action="store_true",
        help="Create and verify document fixtures, then exit without attack",
    )
    args = p.parse_args()
    if args.files <= 0 or args.size_kb <= 0 or args.chunk_kb <= 0:
        p.error("--files, --size-kb, --chunk-kb 는 양수여야 합니다.")
    lib.validate_positive(
        p, prepare_timeout=args.prepare_timeout, duration=args.duration
    )
    lib.validate_non_negative(p, delay=args.delay)
    try:
        for ext in (".docx", ".pdf", ".xlsx"):
            document_bytes("probe" + ext, args.size_kb * 1024)
    except ValueError as exc:
        p.error(str(exc))
    return args


def main() -> int:
    args = parse_args()

    target = lib.resolve_target(args.target)
    if target is None:
        return 2

    workdir = lib.make_workdir(target, "icefire")
    size = args.size_kb * 1024
    chunk = args.chunk_kb * 1024
    # 분석 자료에 명시된 IceFire 암호화 대상 확장자.
    target_exts = (".docx", ".pdf", ".xlsx")
    names = [
        f"doc_{i:03d}{target_exts[i % len(target_exts)]}" for i in range(args.files)
    ]

    lib.log(f"작업 폴더: {workdir}")
    lib.log(f"[2.3 전제] 준비: 평문 문서 {args.files}개 x {args.size_kb}KB (자식 PID)")
    if not prepare_documents(workdir, names, size, args.prepare_timeout):
        lib.log(f"평문 준비 실패. 공격 미시작; 진단용 폴더 보존: {workdir}")
        return 1

    # 자기 삭제 모사용 표식 파일(공격 도구 자신). 준비 단계에서 같이 만든다.
    marker_path = os.path.join(workdir, SELF_MARKER)
    with open(marker_path, "wb") as f:
        f.write(b"icefire-sim-tool-marker\n")

    if not wait_for_documents(workdir, names, size, args.prepare_timeout):
        lib.log(f"준비 확인 실패. 공격 미시작; 진단용 폴더 보존: {workdir}")
        return 1

    if args.prepare_only:
        lib.log(f"Documents ready; attack not started. Preserved: {workdir}")
        return 0

    lib.log("준비 완료. 공격 역할 시작.")
    paths = [os.path.join(workdir, n) for n in names]
    lib.log(
        f"공격 역할 PID={os.getpid()} (비신뢰 바이너리 전제, duration={args.duration}s). "
        f"GuardFS 로그/대시보드를 확인하세요."
    )

    start = time.time()
    total = 0
    rc = 0
    try:
        for i, path in enumerate(paths):
            if time.time() - start >= args.duration:
                lib.log("duration 초과 → 중단")
                break
            # 2.3 대상 open/read → 2.4 고엔트로피 덮어쓰기 → .ifire rename
            lib.read_file(path)
            total += lib.overwrite_random(path, size, chunk)
            if args.ext and not path.endswith(args.ext):
                new_path = path + args.ext
                lib.rename_to(path, new_path)
                paths[i] = new_path
            if args.delay:
                time.sleep(args.delay)

        # 2.4 디렉터리마다 랜섬노트 생성
        lib.write_note(workdir, NOTE_NAME, NOTE_BODY)
        lib.log(f"모의 노트 생성: {NOTE_NAME}")

        # 2.5 공격 도구 자기 삭제 모사(이 스크립트가 만든 표식 파일만 unlink)
        try:
            os.unlink(marker_path)
            lib.log("자기 삭제 모사: 도구 표식 파일 unlink")
        except OSError as e:
            lib.log(f"자기 삭제 모사 실패(차단일 수 있음): {e}")
    except OSError as e:
        # ENOENT 등은 보호 차단만으로 설명되지 않으므로 결과를 단정하지 않는다.
        lib.log(f"파일 연산 실패: {e} → 차단 여부는 GuardFS 상태/이벤트 로그로 확인")
        rc = 3
    finally:
        lib.log(f"종료: {total / 1024 / 1024:.1f}MB 덮어씀, {time.time() - start:.1f}s")
        lib.cleanup_workdir(workdir, args.keep)
    return rc


if __name__ == "__main__":
    sys.exit(main())
