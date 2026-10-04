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
#   값 근거: 동적 모델은 정상 248개에서 임계값 0.5 기준 FPR 0% 이므로
#   0.5 위 여유(margin)를 둔 0.6 을 기본값으로 한다. 정상 동적 점수 분포를
#   재확인하면 조정 가능.
STAGE2_DYN_ONLY_HIGH_THRESHOLD = 0.6

# ========== Stage 2 - MEDIUM Re-evaluation ========== #
STAGE2_REEVAL_INTERVAL_SEC = 1.0
STAGE2_MEDIUM_TIMEOUT_SEC = 10.0

# ========== MEDIUM Policy ========== #
MEDIUM_WRITE_DELAY_MID = 0.1
MEDIUM_WRITE_DELAY_HIGH = 0.5

MEDIUM_WRITE_THRESHOLD_MID = 10
MEDIUM_WRITE_THRESHOLD_HIGH = 20

MEDIUM_SIZE_LIMIT = 1_000_000