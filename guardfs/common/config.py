# ========== Stage 1 - Entropy Detection ========== #
ENTROPY_THRESHOLD = 7.0
ENTROPY_HEADER_SIZE = 256

# ========== Stage 1 - Extension Change Detection ========== #
EXT_CHANGE_WINDOW_SEC = 10
EXT_CHANGE_THRESHOLD = 5

# ========== Stage 1 - PID Statistics ========== #
STATS_WINDOW_SEC = 1.0

STATS_WRITE_THRESHOLD = 2
STATS_E_SUM_THRESHOLD = 0.1
STATS_RENAME_THRESHOLD = 2
STATS_UNLINK_THRESHOLD = 2

# ========== Stage 2 - ML ========== #
STAGE2_MEDIUM_THRESHOLD = 0.3
STAGE2_HIGH_THRESHOLD = 0.82

DYNAMIC_MODEL_WEIGHT = 0.5
STATIC_MODEL_WEIGHT = 0.5

# 동적(행동) 모델 단독 HIGH 임계값.
#   가중합(score)만 쓰면 실행 파일이 양성 인터프리터(python3 등)인
#   스크립트형 랜섬웨어는 stat 점수가 낮아 HIGH(0.82)에 영원히 도달 못 한다.
#   (예: dyn=0.65, stat=0.30 -> score=0.47 로 MEDIUM 후 LOW 복귀)
#   행동만으로도 충분히 확신하면 정적 점수와 무관하게 격상하도록 OR 규칙을 둔다.
#
#   값은 추정이 아니라 데이터로 정한다(dataset_v5, train_v5.py 교차검증 OOF):
#   정상 PID 3382개의 OOF 점수 최대가 0.145, 악성은 대부분 0.9+ 로 깨끗이
#   갈린다. 임계값 0.3~0.80 어디서든 정상 오탐률(FPR) 0% / 악성 탐지율 97.4%.
#   아래 0.5 는 정상 최대(0.145) 대비 큰 여유를 두면서 탐지율 손실이 없는 값.
#   (FPR 0% 되는 최저값은 0.3; 재측정은 dataset_v5/train_v5_report.json)
STAGE2_DYN_ONLY_HIGH_THRESHOLD = 0.5

# ========== Stage 2 - MEDIUM Re-evaluation ========== #
STAGE2_REEVAL_INTERVAL_SEC = 1.0
STAGE2_MEDIUM_TIMEOUT_SEC = 10.0

# ========== MEDIUM Policy ========== #
MEDIUM_WRITE_DELAY_MID = 0.1
MEDIUM_WRITE_DELAY_HIGH = 0.5

MEDIUM_WRITE_THRESHOLD_MID = 10
MEDIUM_WRITE_THRESHOLD_HIGH = 20

MEDIUM_SIZE_LIMIT = 1_000_000