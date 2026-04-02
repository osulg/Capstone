import os
import csv
from pathlib import Path
from typing import List, Dict, Any
from elftools.elf.elffile import ELFFile

# =========================
# 설정
# =========================
PROJECT_ROOT = Path("~/capstone/malware").expanduser()
OUTPUT_CSV = Path("~/capstone/Result/ELF header/elf_header_features.csv").expanduser()

TARGET_EXTENSIONS = {".elf", ""}  # 분석 대상 확장자

# 제외할
EXCLUDE_DIRS = {"__pycache__", ".git", "ELF header", "_corrupted", "_failed_parse"}

# 정상적으로 자주 보이는 section 이름 목록
KNOWN_SECTIONS = {
    "",
    ".interp",
    ".note.gnu.property",
    ".note.gnu.build-id",
    ".note.ABI-tag",
    ".gnu.hash",
    ".dynsym",
    ".dynstr",
    ".gnu.version",
    ".gnu.version_r",
    ".rela.dyn",
    ".rela.plt",
    ".init",
    ".plt",
    ".plt.got",
    ".text",
    ".fini",
    ".rodata",
    ".eh_frame_hdr",
    ".eh_frame",
    ".init_array",
    ".fini_array",
    ".dynamic",
    ".got",
    ".got.plt",
    ".data",
    ".bss",
    ".comment",
    ".symtab",
    ".strtab",
    ".shstrtab",
    ".rela.text",
    ".rela.init",
    ".rela.fini",
    ".rela.eh_frame",
    ".rel.dyn",
    ".rel.plt",
    ".hash",
    ".ctors",
    ".dtors",
    ".tbss",
    ".tdata",
}


# =========================
# 파일 수집
# =========================
def collect_family_dirs(project_root: Path):
    """
    프로젝트 루트 아래의 하위 폴더를 family 폴더 후보로 수집
    ex)

    Returns:
        family_dir(list[Path]): family 폴더 경로 리스트
    """

    family_dir = []

    # 입력 폴더가 없으면 빈 리스트 반환
    if not project_root.exists():
        return family_dir

    # project_root 바로 아래 1단계 폴더만 확인
    for path in project_root.iterdir():
        # 폴더 아니면 무시
        if not path.is_dir():
            continue
        # 제외 대상 폴더면 무시
        if path.name in EXCLUDE_DIRS:
            continue

        # family 폴더 후보로 추가
        family_dir.append(path)

    # 폴더 이름 기준으로 정렬해서 변환
    return sorted(family_dir, key=lambda x: x.name.lower())


def is_target_elf_file(file_path: Path) -> bool:
    if not file_path.is_file():
        return False

    if file_path.suffix.lower() not in TARGET_EXTENSIONS:
        return False

    try:
        with open(file_path, "rb") as f:
            magic = f.read(4)
        return magic == b"\x7fELF"
    except Exception:
        return False


def collect_elf_files_from_family_dir(family_dirs: List[Path]):
    """
    family 폴더 안의 ELF 파일 경로 수집

    Args:
        family_dirs (list[Path]):

    Returns:
        samples(list[tuple[str, Path]]): [(family_name, file_path), ...]
    """
    samples = []

    for family_dir in family_dirs:
        family_name = family_dir.name

        for file_path in sorted(family_dir.iterdir(), key=lambda x: x.name.lower()):
            if is_target_elf_file(file_path):
                samples.append((family_name, file_path))

    return samples


# =========================
# 유틸
# =========================
def safe_div(numerator: float, denominator: float) -> float:
    return numerator / denominator if denominator else 0.0


def is_known_section_name(section_name: str) -> bool:
    if section_name in KNOWN_SECTIONS:
        return True

    # 흔한 변형 허용
    if section_name.startswith(".note"):
        return True
    if section_name.startswith(".debug"):
        return True
    if section_name.startswith(".gnu"):
        return True

    return False


def make_binary_label(family_name: str) -> int:
    """
    Benign -> 0
    그 외 malware family -> 1
    """
    return 0 if str(family_name).strip().lower() == "benign" else 1


# =========================
# ELF Header 분석
# =========================
def extract_elf_features(file_path: Path, family_name: str) -> Dict[str, Any]:
    file_size = file_path.stat().st_size

    label = make_binary_label(family_name)

    row: Dict[str, Any] = {
        # 기본 메타 정보
        "family": family_name,
        "label": label,
        "file_name": file_path.name,
        "file_path": str(file_path),
        "file_size": file_size,
        # 공통 파싱 상태
        "elf_parse_ok": 0,
        "program_header_parse_ok": 0,
        "section_parse_ok": 0,
        "parse_error": "",
        # =========================
        # 1) ELF Header 구간
        # =========================
        "is_64bit": None,
        "is_little_endian": None,
        "os_abi": None,
        "elf_type": None,
        "machine": None,
        "entry_point": None,
        "has_entry_point": None,
        "has_program_header": None,
        "has_section_header": None,
        "num_program_headers_declared": None,
        "num_sections_declared": None,
        # =========================
        # 2) Program Header 구간
        # =========================
        "num_load_segments": 0,
        "has_dynamic": 0,
        "has_interp": 0,
        "has_note": 0,
        "has_tls": 0,
        "num_executable_segments": 0,
        "num_writable_segments": 0,
        "num_readable_segments": 0,
        "has_rwx_segment": 0,
        "max_segment_filesz": 0,
        "avg_segment_filesz": 0.0,
        "max_segment_memsz": 0,
        "avg_segment_memsz": 0.0,
        "num_memsz_gt_filesz_segments": 0,
        # =========================
        # 3) Section Header 구간
        # =========================
        "text_size": 0,
        "has_text": 0,
        "data_size": 0,
        "has_data": 0,
        "rodata_size": 0,
        "has_rodata": 0,
        "bss_size": 0,
        "has_bss": 0,
        "has_symtab": 0,
        "has_dynsym": 0,
        "has_strtab": 0,
        "has_dynstr": 0,
        "has_plt": 0,
        "has_got": 0,
        "has_got_plt": 0,
        "is_stripped": 0,
        "max_section_size": 0,
        "avg_section_size": 0.0,
        "num_executable_sections": 0,
        "num_writable_sections": 0,
        "num_alloc_sections": 0,
        "num_known_sections": 0,
        "num_unusual_sections": 0,
        "has_unusual_section": 0,
        # =========================
        # 4) 비율 feature 구간
        # =========================
        "text_ratio": 0.0,
        "data_ratio": 0.0,
        "rodata_ratio": 0.0,
        "bss_ratio": 0.0,
        # =========================
        # 5) 통계 feature 구간
        # =========================
        "num_sections_actual": 0,
        "num_segments_actual": 0,
    }

    try:
        with open(file_path, "rb") as f:
            elf = ELFFile(f)

            # -------------------------------------------------
            # 1) ELF Header 구간
            # -------------------------------------------------
            hdr = elf.header

            row["is_64bit"] = 1 if elf.elfclass == 64 else 0
            row["is_little_endian"] = 1 if elf.little_endian else 0
            row["os_abi"] = str(hdr["e_ident"]["EI_OSABI"])
            row["elf_type"] = str(hdr["e_type"])
            row["machine"] = str(hdr["e_machine"])
            row["entry_point"] = int(hdr["e_entry"])
            row["has_entry_point"] = 1 if int(hdr["e_entry"]) != 0 else 0
            row["has_program_header"] = 1 if int(hdr["e_phoff"]) != 0 else 0
            row["has_section_header"] = 1 if int(hdr["e_shoff"]) != 0 else 0
            row["num_program_headers_declared"] = int(hdr["e_phnum"])
            row["num_sections_declared"] = int(hdr["e_shnum"])
            row["elf_parse_ok"] = 1

            # -------------------------------------------------
            # 2) Program Header 구간
            # -------------------------------------------------
            segment_filesz_list = []
            segment_memsz_list = []

            try:
                row["num_segments_actual"] = elf.num_segments()

                for seg in elf.iter_segments():
                    seg_type = str(seg["p_type"])
                    flags = int(seg["p_flags"])
                    p_filesz = int(seg["p_filesz"])
                    p_memsz = int(seg["p_memsz"])

                    segment_filesz_list.append(p_filesz)
                    segment_memsz_list.append(p_memsz)

                    if seg_type == "PT_LOAD":
                        row["num_load_segments"] += 1
                    elif seg_type == "PT_DYNAMIC":
                        row["has_dynamic"] = 1
                    elif seg_type == "PT_INTERP":
                        row["has_interp"] = 1
                    elif seg_type == "PT_NOTE":
                        row["has_note"] = 1
                    elif seg_type == "PT_TLS":
                        row["has_tls"] = 1

                    # ELF segment flags
                    # PF_X = 0x1, PF_W = 0x2, PF_R = 0x4
                    is_exec = bool(flags & 0x1)
                    is_write = bool(flags & 0x2)
                    is_read = bool(flags & 0x4)

                    if is_exec:
                        row["num_executable_segments"] += 1
                    if is_write:
                        row["num_writable_segments"] += 1
                    if is_read:
                        row["num_readable_segments"] += 1
                    if is_exec and is_write and is_read:
                        row["has_rwx_segment"] = 1

                    if p_memsz > p_filesz:
                        row["num_memsz_gt_filesz_segments"] += 1

                row["max_segment_filesz"] = (
                    max(segment_filesz_list) if segment_filesz_list else 0
                )
                row["avg_segment_filesz"] = (
                    sum(segment_filesz_list) / len(segment_filesz_list)
                    if segment_filesz_list
                    else 0.0
                )
                row["max_segment_memsz"] = (
                    max(segment_memsz_list) if segment_memsz_list else 0
                )
                row["avg_segment_memsz"] = (
                    sum(segment_memsz_list) / len(segment_memsz_list)
                    if segment_memsz_list
                    else 0.0
                )

                row["program_header_parse_ok"] = 1

            except Exception as e:
                row["program_header_parse_ok"] = 0
                row["parse_error"] += f"[PROGRAM_HEADER] {str(e)} "

            # -------------------------------------------------
            # 3) Section Header 구간
            # -------------------------------------------------
            section_size_list = []

            try:
                row["num_sections_actual"] = elf.num_sections()

                for sec in elf.iter_sections():
                    name = sec.name
                    sh_size = int(sec["sh_size"])
                    sh_flags = int(sec["sh_flags"])

                    section_size_list.append(sh_size)

                    # 주요 section
                    if name == ".text":
                        row["has_text"] = 1
                        row["text_size"] = sh_size
                    elif name == ".data":
                        row["has_data"] = 1
                        row["data_size"] = sh_size
                    elif name == ".rodata":
                        row["has_rodata"] = 1
                        row["rodata_size"] = sh_size
                    elif name == ".bss":
                        row["has_bss"] = 1
                        row["bss_size"] = sh_size
                    elif name == ".symtab":
                        row["has_symtab"] = 1
                    elif name == ".dynsym":
                        row["has_dynsym"] = 1
                    elif name == ".strtab":
                        row["has_strtab"] = 1
                    elif name == ".dynstr":
                        row["has_dynstr"] = 1
                    elif name == ".plt":
                        row["has_plt"] = 1
                    elif name == ".got":
                        row["has_got"] = 1
                    elif name == ".got.plt":
                        row["has_got_plt"] = 1

                    # section flags
                    # SHF_WRITE = 0x1, SHF_ALLOC = 0x2, SHF_EXECINSTR = 0x4
                    if sh_flags & 0x4:
                        row["num_executable_sections"] += 1
                    if sh_flags & 0x1:
                        row["num_writable_sections"] += 1
                    if sh_flags & 0x2:
                        row["num_alloc_sections"] += 1

                    # known / unusual section
                    if is_known_section_name(name):
                        row["num_known_sections"] += 1
                    else:
                        row["num_unusual_sections"] += 1

                row["max_section_size"] = (
                    max(section_size_list) if section_size_list else 0
                )
                row["avg_section_size"] = (
                    sum(section_size_list) / len(section_size_list)
                    if section_size_list
                    else 0.0
                )
                row["is_stripped"] = 1 if row["has_symtab"] == 0 else 0
                row["has_unusual_section"] = 1 if row["num_unusual_sections"] > 0 else 0

                row["section_parse_ok"] = 1

            except Exception as e:
                row["section_parse_ok"] = 0
                row["parse_error"] += f"[SECTION_HEADER] {str(e)} "

            # -------------------------------------------------
            # 4) 비율 feature 구간
            # -------------------------------------------------
            row["text_ratio"] = safe_div(row["text_size"], file_size)
            row["data_ratio"] = safe_div(row["data_size"], file_size)
            row["rodata_ratio"] = safe_div(row["rodata_size"], file_size)
            row["bss_ratio"] = safe_div(row["bss_size"], file_size)

    except Exception as e:
        row["elf_parse_ok"] = 0
        row["parse_error"] = f"[ELF_PARSE] {str(e)}"

    return row


# =========================
# CSV 저장
# =========================
def save_to_csv(rows: List[dict], output_csv: Path):
    if not rows:
        print("[WARNING] 저장할 데이터가 없음")
        return

    output_csv.parent.mkdir(parents=True, exist_ok=True)

    fieldnames = list(rows[0].keys())

    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[DONE] CSV 저장 완료: {output_csv}")


# =========================
# main
# =========================
def main():
    print("[1] family 폴더 수집 중")
    family_dirs = collect_family_dirs(PROJECT_ROOT)
    print(f"     - family 폴더 수: {len(family_dirs)}")

    if not family_dirs:
        print("[ERROR] Can't find family_folder")
        print(f"        Check your PROJECT_ROOT: {PROJECT_ROOT}")
        return

    print("\n[2] 각 family 폴더에서 ELF 파일 수집 중")
    samples = collect_elf_files_from_family_dir(family_dirs)
    print(f"     - 수집된 ELF 후보 파일 수: {len(samples)}")

    if not samples:
        print("[ERROR] There is no ELF file to analyze.")
        return

    print("\n[3] ELF feature 추출 중")
    rows = []
    success_count = 0
    fail_count = 0

    for idx, (family_name, file_path) in enumerate(samples, start=1):
        try:
            row = extract_elf_features(file_path, family_name)
            rows.append(row)

            if row["elf_parse_ok"] == 0:
                fail_count += 1
                print(
                    f"     [{idx}/{len(samples)}] FAIL - {family_name}/{file_path.name} | {row['parse_error']}"
                )
            elif row["program_header_parse_ok"] == 0 or row["section_parse_ok"] == 0:
                success_count += 1
                print(
                    f"     [{idx}/{len(samples)}] PARTIAL - {family_name}/{file_path.name}"
                )
            else:
                success_count += 1
                print(
                    f"     [{idx}/{len(samples)}] OK - {family_name}/{file_path.name}"
                )

        except Exception as e:
            fail_count += 1
            print(
                f"     [{idx}/{len(samples)}] FAIL - {family_name}/{file_path.name} | {e}"
            )

    print("\n[4] CSV 저장 중")
    save_to_csv(rows, OUTPUT_CSV)

    print("\n[5] SUMMARY")
    print(f"     - SUCCESS: {success_count}")
    print(f"     - FAIL: {fail_count}")
    print(f"     - RESULT FILE: {OUTPUT_CSV}")


if __name__ == "__main__":
    main()
