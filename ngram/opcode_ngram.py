import subprocess  # 외부 명령어(objdump) 실행을 위해
import json
import re
from collections import Counter
from pathlib import Path
import pandas as pd

# =========================
# 설정
# =========================
N_GRAM = 2  # n-gram 길이
TOP_K = 300  # 전체 데이터에서 가장 많이 등장한 상위 몇개의 feature 개수

EXPERIMENT_TAG = f"n{N_GRAM}_k{TOP_K}"

BASE_SAMPLE_DIR = Path("~/capstone/malware").expanduser()

# 모든 결과를 여기 하나로 통일
BASE_OUTPUT_DIR = Path("~/capstone/Result/opcode_ngram").expanduser()
ALL_OUTPUT_DIR = BASE_OUTPUT_DIR

EXPERIMENT_TAG = f"n{N_GRAM}_k{TOP_K}"

COMBINED_CSV = ALL_OUTPUT_DIR / f"opcode_ngram_{EXPERIMENT_TAG}_all_dataset.csv"
GLOBAL_VOCAB_JSON = BASE_OUTPUT_DIR / f"global_vocab_{EXPERIMENT_TAG}.json"

# family 폴더 탐색 시 제외 폴더
EXCLUDE_DIRS = {"byte_ngram", "__pycache__", "all", "PE", "opcode_ngram"}

# 정상 파일(benign) 폴더 이름
BENIGN_FAMILY_NAMES = {"Benign", "benign"}

# 캐시
opcode_cache = {}
ngram_cache = {}


# =========================
# 파일 수집
# =========================
def collect_family_dirs(project_root: Path):
    """
    프로젝트 루트 아래의 하위 폴더를 family 폴더 후보로 수집
    ex)
        ~/project/Wannacry

    Args:
        project_root (Path): 프로젝트 루트 경로

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


def is_elf_file(path: Path) -> bool:
    try:
        with open(path, "rb") as f:
            return f.read(4) == b"\x7fELF"
    except Exception:
        return False


def collect_files_in_family(family_dir: Path):
    """
    - 특정 family 폴더 내부를 재귀적으로 순회
    - 분석 대상 확장자 파일 수집

    Args:
        family_dir (Path): 특정 family 폴더 경로

    Returns:
        files (list[Path]): 해당 family에 속한 e 파일 리스트
    """

    files = []

    # rglob("*")는 하위 폴더까지 전부 재귀 탐색
    for path in family_dir.rglob("*"):
        # 파일이고, 확장자 대사 -> 수집
        if path.is_file() and is_elf_file(path):
            files.append(path)

    return sorted(files)


# =========================
# objdump 실행
# =========================
def run_objdump(file_path: Path):
    """
    objdump -d 실행 후, stdout 문자열 반환

    Args:
        file_path (Path): _description_

    Returns:
        _type_: _description_
    """
    try:
        result = subprocess.run(
            ["objdump", "-d", str(file_path)],
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout

    except subprocess.CalledProcessError as e:
        print(f"[skip] objdump failed: {file_path}")
        print(e.stderr)
        return None

    except Exception as e:
        print(f"[skip] unexpected error: {file_path} | {e}")
        return None


def shorten_name(file_path: Path, length=16):
    """_summary_

    Args:
        file_path (Path): _description_
        length (int, optional): _description_. Defaults to 8.

    Returns:
        _type_: _description_
    """
    name = file_path.name
    base = name.split(".")[0]
    short = base[:length]

    return short + ".objdump.txt"


def save_objdump_output(family_name: str, file_path: Path, output_base: Path):
    """
    _summary_

    Args:
        family_name (str): _description_
        file_path (Path): _description_
        output_base (Path): _description_
    """

    family_out_dir = output_base / family_name
    family_out_dir.mkdir(parents=True, exist_ok=True)

    output = run_objdump(file_path)
    if output is None:
        return

    out_name = shorten_name(file_path, length=16)
    out_path = family_out_dir / out_name

    with open(out_path, "w", encoding="utf-8") as f:
        f.write(output)

    print(f"[saved] {out_path}")


# =========================
# n-gram 추출 함수
# =========================
def extract_opcodes(file_path: Path):
    key = str(file_path)

    if key in opcode_cache:
        return opcode_cache[key]

    output = run_objdump(file_path)

    if output is None:
        opcode_cache[key] = []
        return []

    opcodes = []

    for line in output.splitlines():
        m = re.match(
            r"^\s*[0-9a-fA-F]+:\s+(?:[0-9a-fA-F]{2}\s+)+([a-zA-Z][a-zA-Z0-9._]*)", line
        )

        if m:
            opcode = m.group(1).lower()
            opcodes.append(opcode)

    opcode_cache[key] = opcodes
    return opcodes


def get_opcode_ngram_counts(file_path: Path, n=N_GRAM):
    key = (str(file_path), n)

    # 이미 계산한 파일이면 캐시 결과 재사용
    if key in ngram_cache:
        return ngram_cache[key]

    opcodes = extract_opcodes(file_path)

    if len(opcodes) < n:
        ngram_cache[key] = Counter()
        return Counter()

    counts = Counter(" ".join(opcodes[i : i + n]) for i in range(len(opcodes) - n + 1))

    ngram_cache[key] = counts
    return counts


# =========================
# global vocabulary 생성 함수
# =========================
def build_global_vocab(family_to_files: dict, n=N_GRAM, top_k=TOP_K):
    """
    - 모든 family의 모든 파일 대상
    - n-gram으로 빈도 누적
    - 가장 많이 등장한 상위 top_k개의 n-gram만 vocabulary로 선정

    Args:
        family_to_files (dict): "Wannacry": [Path(...), Path(...)]
        n (int, optional): n-gram 길이
        top_k (int): 상위 몇 개 선택

    Returns:
        vocab (list[bytes]): 가장 많이 등장한 n-gram 패턴들의 리스트
    """

    total_counter = Counter()

    # family 별로 파일 순호 -> n-gram 빈도 합산
    for family, file_list in family_to_files.items():
        print(f"[vocab] {family}: {len(file_list)} files")

        for file_path in file_list:
            try:
                # 파일 1개의 n-gram 빈도 얻기
                file_counter = get_opcode_ngram_counts(file_path, n)
                # 전체 누적 Counter에 더함
                total_counter.update(file_counter)

            except Exception as e:
                # 읽기 실패한 파일 건너뛰기 + 로그
                print(f"[skip] voca build failed: {file_path} | {e}")

    # 가장 많이 나온 top_k개 패턴 선택
    vocab = [gram for gram, _ in total_counter.most_common(top_k)]
    return vocab


# =========================
# (파일 -> 벡터) 관련 함수
# =========================
def file_to_vector(file_path: Path, vocab, n: int = 3):
    """
    파일을 고정 길이 vector로 변환
    - 해당 파일의 n-gram 계산
    - global vocab에 있는 각 패턴이 해당 파일에 몇 번 나왔는지 꺼내기

    Args:
        file_path (Path): 분석 파일
        vocab (_type_): global vocabulary
        n (int, optional): n-gram 길이

    Returns:
        list[int]: 길이가 len(vocab)인 숫자 벡터
    """
    count = get_opcode_ngram_counts(file_path, n)
    return [count.get(gram, 0) for gram in vocab]


def get_binary_label(family_name: str):
    """
    family 이름을 바탕으로 이진분류용 label을 부여한다.
    - benign family면 0
    - 그 외는 1

    Args:
        family_name (str): family 이름

    Returns:
        int: 0 또는 1
    """
    return 0 if family_name in BENIGN_FAMILY_NAMES else 1


def build_family_dataframe(family_name: str, file_list, vocab, n: int = 3):
    """
    - 특정 family의 파일을 DataFrame으로 만들기
    - 각 row는 파일 1개 의미
    - 컬럼은
        - file_path
        - family
        - label
        - f_0, ... : n-gram feature 값

    Args:
        family_name (str): family 이름
        file_list (_type_): family 파일 목록
        vocab (_type_): global vocabulary
        n (int, optional): n-gram 길이

    Returns:
        pd.DataFrame: family별 feature table
    """
    rows = []

    for file_path in file_list:
        try:
            # 파일을 n-gram 벡터로 변경
            vector = file_to_vector(file_path, vocab, n)

            label = get_binary_label(family_name)

            # 리스트 기반 row 생성
            row = [str(file_path), family_name, label] + vector

            rows.append(row)

        except Exception as e:
            print(f"[skip] dataset build failed: {file_path} | {e}")

    # 컬럼 이름 생성
    columns = ["file_path", "family", "label"] + [f"f_{i}" for i in range(len(vocab))]

    # 모든 row를 DataFrame으로 변환
    return pd.DataFrame(rows, columns=columns)


# =========================
# 저장 함수
# =========================
def load_existing_csv(csv_path: Path) -> pd.DataFrame:
    """
    기존 CSV가 있으면 불러오고,
    없거나 읽기 실패 시 빈 DataFrame 반환

    Args:
        csv_path (Path): 기존 csv 경로

    Returns:
        pd.DataFrame
    """

    if csv_path.exists():
        try:
            return pd.read_csv(csv_path, encoding="utf-8-sig")
        except Exception:
            return pd.DataFrame()

    return pd.DataFrame()


def merge_and_deduplicate(old_df: pd.DataFrame, new_df: pd.DataFrame) -> pd.DataFrame:
    """
    기존 데이터와 새 데이터를 병합한 뒤 중복 제거

    Args:
        old_df (pd.DataFrame): 기존 누적 데이터
        new_df (pd.DataFrame): 새로 생성한 데이터

    Returns:
        pd.DataFrame: 병합 + 중복 제거 완료한 데이터
    """

    # 기존 데이터가 비어있으면, 새 데이터 복사해 이용
    if old_df.empty:
        merged = new_df.copy()
    # 새 데이터가 비어있으면, 기존 데이터만 복사해 이용
    elif new_df.empty:
        merged = old_df.copy()
    # 둘 다 값이 있으면, 행(row) 방향으로 위아래 이어붙여 하나의 DataFrame 생성
    else:
        merged = pd.concat([old_df, new_df], ignore_index=True)

    # 중복 판별에 사용할 컬럼 선택
    # merged 안에 실재로 존재하는 컬럼만 사용
    # file_path와 family 기준으로 확인
    dedup_cols = [col for col in ["file_path", "family"] if col in merged.columns]

    # 중복 컬럼이 있으면
    if dedup_cols:
        # 같은 file_path + family 조합이 여러번 나와도
        # 가장 마지막 행만 남기고 제거
        merged = merged.drop_duplicates(subset=dedup_cols, keep="last")
    else:
        # 중복 기준 컬럼이 없으면
        # 행 전체가 완전히 같은 경우만 중복 제거
        merged = merged.drop_duplicates(keep="last")

    return merged


def save_family_output(family_name: str, df: pd.DataFrame, output_base: Path):
    """
    - 특정 family의 DataFrame을 csv로 저장
    - 간단 요약 정보를 json으로 저장

    ex)
        ~/project/byte_ngram/Wannacry/Wannacry_ngram_dataset.csv
        ~/project/byte_ngram/Wannacry/Wannacry_ngram_summary.json

    Args:
        family_name (str): family 이름
        df (pd.DataFrame): 저장할 family별 Dataframe
        output_base (Path): byte_ngram 기본 저장 포더
    """

    # family별 저장 폴더 생성
    family_out_dir = output_base / family_name
    family_out_dir.mkdir(parents=True, exist_ok=True)

    # 저장 파일 경로
    csv_path = family_out_dir / f"{family_name}_ngram_{EXPERIMENT_TAG}_dataset.csv"
    summary_path = family_out_dir / f"{family_name}_ngram_{EXPERIMENT_TAG}_summary.json"

    # family별 CSV 저장
    df.to_csv(csv_path, index=False, encoding="utf-8-sig")

    # summary 정보
    summary = {
        "family": family_name,
        "num_samples": int(len(df)),
        "num_features": int(max(len(df.columns) - 3, 0)),
        "output_csv": str(csv_path),
    }

    # summary json 저장
    with open(summary_path, "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2, ensure_ascii=False)

    print(f"[saved] family CSV: {csv_path}")
    print(f"[saved] family summary JSON: {summary_path}")


# =========================
# vocab 저장/불러오기 함수
# =========================
def save_vocab_json(vocab, json_path: Path):
    """
    vocab(list[bytes])를 json 파일로 저장
    - key: f_0, f_1, ...
    - value: n-gram의 hex 문자열
    """
    vocab_mapping = {f"f_{i}": gram for i, gram in enumerate(vocab)}

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(vocab_mapping, f, indent=2, ensure_ascii=False)


def load_vocab_json(json_path: Path):
    """
    저장된 global_vocab.json을 읽어서
    다시 list[bytes] 형태의 vocab로 복원
    """
    with open(json_path, "r", encoding="utf-8") as f:
        vocab_mapping = json.load(f)

    # f_0, f_1, ... 순서대로 정렬해서 bytes로 복원
    vocab = [
        gram
        for _, gram in sorted(
            vocab_mapping.items(), key=lambda x: int(x[0].split("_")[1])
        )
    ]
    return vocab


# =========================
# main 함수
# =========================
def main():
    BASE_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ALL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    # 1단계: family 폴더 검색
    print("[1] family 폴더 탐색")
    family_dir = collect_family_dirs(BASE_SAMPLE_DIR)

    if not family_dir:
        print("family 폴더 찾기 실패")
        return

    print("    탐지된 family 폴더:")
    for dir in family_dir:
        print(f"    - {dir.name}")

    # 2단계: family별 파일 수집
    print("\n[2] family별 파일 수집")
    family_to_files = {}

    for dir in family_dir:
        file = collect_files_in_family(dir)

        if file:
            family_to_files[dir.name] = file
            print(f"    - {dir.name}: {len(file)} files")
        else:
            print(f"    - {dir.name}: 0 files (skip)")

    if not family_to_files:
        print("분석할 elf 파일이 없습니다.")
        return

    # 전체 파일 목록
    total_files = sum(len(files) for files in family_to_files.values())

    print(f"\n[3] 전체 파일 수: {total_files}")

    # 3단계: objdump txt 저장 디버깅
    DEBUG_SAVE_OBJDUMP = False
    if DEBUG_SAVE_OBJDUMP:
        print("\n[4] objdump 결과 txt 저장")
        objdump_output_dir = BASE_OUTPUT_DIR / "objdump_txt"
        for family_name, file_list in family_to_files.items():
            for file_path in file_list:
                save_objdump_output(family_name, file_path, objdump_output_dir)

    # 4단계: global vocab 생성
    print("\n[4] global vocabulary 준비")

    # 이미 global vocab이 있으면 -> 그대로 불러와서 고정 사용
    if GLOBAL_VOCAB_JSON.exists():
        vocab = load_vocab_json(GLOBAL_VOCAB_JSON)
        print(f"    기존 global vocab 불러옴: {GLOBAL_VOCAB_JSON}")
        print(f"    global vocab 크기: {len(vocab)}")

    # 없으면 -> 처음 1회만 새로 생성 후 저장
    else:
        vocab = build_global_vocab(family_to_files, n=N_GRAM, top_k=TOP_K)
        print(f"    새 global vocab 생성 완료: {len(vocab)}")

        save_vocab_json(vocab, GLOBAL_VOCAB_JSON)
        print(f"    global vocab 저장: {GLOBAL_VOCAB_JSON}")

    # 5단계: family별 dataframe 생성
    print("\n[5] family별 dataframe 생성")
    family_df = []

    for family_name, file_list in family_to_files.items():
        # family dataframe 생성
        df_family = build_family_dataframe(family_name, file_list, vocab, n=N_GRAM)

        # family별 csv, summary 생성
        save_family_output(family_name, df_family, BASE_OUTPUT_DIR)

        # 종합 csv를 만들기 위해 보관
        family_df.append(df_family)

    # 6단계: 종합 csv 생성
    print("\n[6] Total CSV 생성")

    # 이번 실행에서 생성한 family DataFrame을 하나로 병합
    if family_df:
        df_all_new = pd.concat(family_df, ignore_index=True)
    else:
        df_all_new = pd.DataFrame()

    # 기존 누적 csv 불러오기
    old_all_df = load_existing_csv(COMBINED_CSV)

    # 기존 + 신규 데이터 병합 후, 중복 제거
    merged_all_df = merge_and_deduplicate(old_all_df, df_all_new)

    # 전체 누적 csv 저장
    merged_all_df.to_csv(COMBINED_CSV, index=False, encoding="utf-8-sig")
    print(f"[saved] combined CSV: {COMBINED_CSV}")

    # 마무리
    print("\n----- Complete -----")
    print(f"- Base sample dir : {BASE_SAMPLE_DIR}")
    print(f"- Family output   : {BASE_OUTPUT_DIR}")
    print(f"- Global vocab    : {GLOBAL_VOCAB_JSON}")
    print(f"- Total CSV       : {COMBINED_CSV}")
    print(f"- Total samples   : {len(merged_all_df)}")


if __name__ == "__main__":
    main()
