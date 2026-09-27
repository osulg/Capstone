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
    "rf_model_v2.pkl",
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

# 동적 모델 v2의 입력 피처 순서(68개, W-event scheme).
# 모델 pkl의 feature_names_in_ 과 반드시 일치해야 한다.
DYNAMIC_FEATURE_COLS_PATH = os.path.join(
    PROJECT_ROOT,
    "models",
    "dynamic",
    "feature_cols_v2.json",
)

# ========== Runtime ========== #
STAGING_DIR = "/tmp/guardfs_staging"
PID_OVERRIDE_FILE = "/tmp/guardfs_pid_override.json"

def get_forced_state_path(pid: int) -> str:
    return f"/tmp/guardfs_state_{pid}"

# ========== Logs ========== #

FILESECURITY_LOG_PATH = os.path.expanduser("~/filesecurity.log")

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
