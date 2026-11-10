import os

# ========== Project ========== #
PROJECT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "..")
)

# ========== ML Models ========== #
DYNAMIC_MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "dynamic",
    "rf_model_v6.pkl",
)

DYNAMIC_SCALER_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "dynamic",
    "dataset",
    "csv_files",
    "scaler.pkl",
)

STATIC_MODEL_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "static",
    "static_rf_n3_k1000.pkl",
)

STATIC_VOCAB_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "static",
    "byte_ngram_vocab_n3_k1000.json",
)

# 동적 모델 v6의 입력 피처 순서(22개, FUSE-only · PID 단위, v5와 같은 스키마).
# models/dynamic/collect/extract_perpid_fuse.py 의 FEATURE_ORDER_V5 와,
# 런타임 PidStats.to_feature_row() 의 키와, 모델 pkl의 feature_names_in_ 이
# 모두 일치해야 한다. train_v6.py 가 이 파일과 rf_model_v6.pkl 을 생성한다.
# rf_model_v6.pkl 은 GuardFS venv(배포 scikit-learn)에서 train_v6.py 로 만들어야 한다.
# 확장자 판정 규칙(config.DYNAMIC_EXT_RULE)과 반드시 짝을 맞춘다.
DYNAMIC_FEATURE_COLS_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "dynamic",
    "feature_cols_v6.json",
)

# ========== Runtime ========== #
STAGING_DIR = "/tmp/guardfs_staging"
PID_OVERRIDE_FILE = "/tmp/guardfs_pid_override.json"

def get_forced_state_path(pid: int) -> str:
    return f"/tmp/guardfs_state_{pid}"

# ========== Logs ========== #

FILESECURITY_LOG_PATH = os.path.expanduser("~/filesecurity.log")

# 웹 시연이 등록한 작업 프로세스의 역할 기록 (PID·시작 tick·역할, 한 줄에 하나).
# demo-web runner 가 등록 시 쓰고, 대시보드가 프로세스 이름 대신 역할을 보여줄 때 읽는다.
PROCESS_ROLES_PATH = os.path.expanduser("~/guardfs_runtime/process_roles.jsonl")

def get_event_log_path(root: str) -> str:
    return os.path.join(
        os.path.dirname(os.path.realpath(root)),
        "guardfs_log.jsonl",
    )

# 수집 모드 로그. mount/underlay 바깥에 두어 수집 대상에 섞이지 않게 한다.
def get_collect_log_dir(root: str) -> str:
    return os.path.join(
        os.path.dirname(os.path.realpath(root)),
        "collect",
    )

# ========== Honeypot ========== #

def get_honeypot_dir(root: str) -> str:
    return os.path.join(
        os.path.realpath(root),
        "honeypot",
    )
