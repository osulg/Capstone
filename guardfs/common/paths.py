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
    "dataset",
    "csv_files",
    "best_model.pkl",
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
    "final_rf_model.pkl",
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

# ========== Honeypot ========== #

def get_honeypot_dir(root: str) -> str:
    return os.path.join(
        os.path.realpath(root),
        "honeypot",
    )