# common/paths.py
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

MODEL_DIR = PROJECT_ROOT / "guardfs" / "models"

STATIC_MODEL_DIR = MODEL_DIR / "static"
DYNAMIC_MODEL_DIR = MODEL_DIR / "dynamic"
METADATA_DIR = MODEL_DIR / "metadata"

# 정적 모델 (byte 3-gram, n=3, k=1000)
STATIC_VOCAB_PATH = STATIC_MODEL_DIR / "byte_ngram_vocab_n3_k1000.json"
STATIC_MODEL_PATH = STATIC_MODEL_DIR / "static_rf_n3_k1000.pkl"

# 동적 모델
DYNAMIC_MODEL_PATH = DYNAMIC_MODEL_DIR / "best_model.pkl"
DYNAMIC_SCALER_PATH = DYNAMIC_MODEL_DIR / "scaler.pkl"

# 런타임
RUNTIME_DIR = Path.home() / "guardfs_runtime"
MOUNT_DIR = RUNTIME_DIR / "mount"
UNDERLAY_DIR = RUNTIME_DIR / "underlay"
LOG_PATH = RUNTIME_DIR / "guardfs_log.jsonl"
