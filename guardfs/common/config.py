# ========== Stage 1 - Entropy Detection ========== #
ENTROPY_THRESHOLD = 7.0
ENTROPY_HEADER_SIZE = 256

# 256바이트 미만 파일을 release 시 평가하기 위한 별도 정책
ENTROPY_MIN_SAMPLE_SIZE = 128
ENTROPY_SHORT_SAMPLE_THRESHOLD = 6.5

# ========== Stage 1 - Entropy Accumulation ========== #

# 마지막 write 이후 불완전한 블록을 유지하는 최대 비활성 시간
ENTROPY_ACCUMULATION_WINDOW_SEC = 5.0

# 첫 write 이후 불완전한 블록을 유지하는 최대 전체 수명
ENTROPY_ACCUMULATION_MAX_LIFETIME_SEC = 30.0

# 블록 완성 및 엔트로피 평가에 필요한 누적 크기
ENTROPY_ACCUMULATION_SIZE = ENTROPY_HEADER_SIZE

# ========== Stage 1 - Entropy Block Sampling ========== #

# 파일 하나에서 동시에 추적할 최대 256B block 수
ENTROPY_MAX_BLOCKS_PER_FILE = 4

# PID 하나에서 동시에 추적할 최대 파일 수
ENTROPY_MAX_FILES_PER_PID = 100

# 하나의 write 이벤트에서 Stage 1으로 전달할 최대 표본 크기
ENTROPY_MAX_EVENT_SAMPLE_SIZE = ENTROPY_HEADER_SIZE * ENTROPY_MAX_BLOCKS_PER_FILE

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

# ========== Stage 2 - MEDIUM Re-evaluation ========== #
STAGE2_REEVAL_INTERVAL_SEC = 1.0
STAGE2_MEDIUM_TIMEOUT_SEC = 10.0

# ========== MEDIUM Policy ========== #
MEDIUM_WRITE_DELAY_MID = 0.1
MEDIUM_WRITE_DELAY_HIGH = 0.5

MEDIUM_WRITE_THRESHOLD_MID = 10
MEDIUM_WRITE_THRESHOLD_HIGH = 20

MEDIUM_SIZE_LIMIT = 1_000_000
