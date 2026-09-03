# config.py
# GuardFS 동작을 조절하는 설정값 (실험하면서 바꿔볼 수 있는 값)

# ==========================================
# Stage 1 Detection
# ==========================================

# [주의] 노션 문서 예시는 7.5이나, 현재 검증된 동작 기준(E 이벤트 매핑 포함)은 7.0.
# 값을 바꾸면 stage1 엔트로피 탐지와 동적 feature의 E 카운트가 함께 영향받음.
ENTROPY_THRESHOLD = 7.0

ENABLE_ENTROPY_DETECTION = True
ENABLE_HONEYPOT_DETECTION = True
ENABLE_EXT_CHANGE_DETECTION = True

# stats_collector 집계 윈도우 및 임계값
STATS_WINDOW_S = 1.0
C_THRESHOLD = 10
D_THRESHOLD = 10

# ==========================================
# Stage 2 Defense
# ==========================================

STATIC_MODEL_WEIGHT = 0.5
DYNAMIC_MODEL_WEIGHT = 0.5

MEDIUM_REEVALUATION_INTERVAL = 10.0

# ==========================================
# Risk Policy
# ==========================================

MEDIUM_THRESHOLD = 0.5
HIGH_THRESHOLD = 0.8

# ==========================================
# Stage 3 Analysis
# ==========================================

ENABLE_FORENSIC_LOGGING = False
ENABLE_RAG_ANALYSIS = False

# ==========================================
# Logging
# ==========================================

LOG_LEVEL = "INFO"
