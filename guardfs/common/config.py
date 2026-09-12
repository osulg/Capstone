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

# ========== Stage 1 - 보조 샘플링 게이트 ========== #
# 허니팟/확장자변경/엔트로피/PidStats 임계치를 모두 피해가는 프로세스도
# 신규 PID + 비신뢰 실행 경로 조합이면 이 확률로 강제로 Stage2 큐에 등록한다.
# (단일 게이트 사각지대 보완용. PID당 최초 1회만 굴린다.)
STAGE1_SAMPLING_RATE = 0.15

# ========== Stage 2 - ML ========== #
STAGE2_MEDIUM_THRESHOLD = 0.3
STAGE2_HIGH_THRESHOLD = 0.82

DYNAMIC_MODEL_WEIGHT = 0.5
STATIC_MODEL_WEIGHT = 0.5

# ========== Stage 2 - MEDIUM Re-evaluation ========== #
STAGE2_REEVAL_INTERVAL_SEC = 1.0
STAGE2_MEDIUM_TIMEOUT_SEC = 10.0

# ========== MEDIUM Policy - 파일 크기 기준 (신뢰 경로 버퍼링 예외) ========== #
MEDIUM_SIZE_LIMIT = 1_000_000

# ========== MEDIUM Policy - 확장자 그룹별 보호 강도 ========== #
# 근거: 이미 압축된 포맷(JPG/PPTX 등)은 암호화 후에도 엔트로피 증가폭이 작아
# 단일 엔트로피 임계값으로는 탐지가 어렵다는 지적 (Taylor et al., "The
# Inadequacy of Entropy-Based Ransomware Detection", ICONIP 2019).
# NetApp ONTAP Autonomous Ransomware Protection도 확장자군에 따라
# 엔트로피 기준/임계값을 차등 적용하고, 한 번도 관찰 안 된 확장자를
# 별도로 취급한다 — 그 아이디어를 반영해 UNKNOWN 그룹을 fallback으로 둔다.
EXTENSION_GROUPS = {
    "HIGH_VALUE": {
        # 랜섬웨어 1순위 타깃 — 원본 손실 시 피해가 큰 문서/DB/키 파일
        "exts": {".docx", ".xlsx", ".pptx", ".pdf", ".db", ".sqlite",
                 ".sql", ".mdb", ".kdbx", ".key", ".pem", ".wallet"},
        "buffer_limit_bytes": 5_000_000,
        "structural_check": True,     # magic byte를 넘어 내부 구조까지 검증
        "delay_multiplier": 1.0,
        "entropy_threshold": 7.2,
    },
    "COMPRESSED": {
        # 이미 고엔트로피인 포맷 — 엔트로피 증가폭으로 암호화를 구분하기 어려움
        "exts": {".jpg", ".jpeg", ".png", ".gif", ".mp4", ".zip",
                 ".gz", ".7z", ".rar", ".mp3", ".mov"},
        "buffer_limit_bytes": 10_000_000,
        "structural_check": False,
        "delay_multiplier": 0.5,      # 정상 write가 빈번한 미디어 파일 → 지연 완화
        "entropy_threshold": None,    # 엔트로피 기준 비적용
    },
    "PLAIN_TEXT": {
        "exts": {".txt", ".log", ".csv", ".json", ".xml", ".py",
                 ".js", ".c", ".h", ".md"},
        "buffer_limit_bytes": 3_000_000,
        "structural_check": False,
        "delay_multiplier": 1.0,
        "entropy_threshold": 6.5,     # 평문은 원래 엔트로피가 낮음 → 기준도 낮게
    },
    "UNKNOWN": {
        # 세 그룹 어디에도 없는 확장자의 fallback (가장 보수적으로 취급)
        "exts": set(),
        "buffer_limit_bytes": 2_000_000,
        "structural_check": False,
        "delay_multiplier": 1.5,
        "entropy_threshold": 6.8,
    },
}

# ========== MEDIUM Policy - 경과시간 기반 지연 (레이어 1) ========== #
# 근거: GuardFS(von der Assen et al., arXiv:2401.17917) Table 6 —
# DEL+OBF 방어에서 탐지 후 지연을 1초로 두면 평균 3.87MB 손실, 5초는 0.7MB,
# 10초는 0.75MB로 5초 이후로는 더 늦춰도 개선되지 않는다는 실측 결과.
# write "누적 횟수"가 아니라 MEDIUM 진입 후 "경과시간" 구간별로 지연을
# 적용하도록 바꿨다 (짧게 치고 빠지는 프로세스도 초반부터 지연이 걸리게).
# (phase 종료 시각(초), 비신뢰 지연(ms), 신뢰 지연(ms))
MEDIUM_DELAY_PHASES = (
    (2.0, 50, 25),
    (5.0, 200, 100),
    (float("inf"), 500, 200),
)

# ========== MEDIUM Policy - 버퍼 상한 ========== #
# PID당 상한은 확장자 그룹별로 다르다 (EXTENSION_GROUPS 참고). 이와 별개로
# 시스템 전체 상한을 둬서, 여러 프로세스가 동시에 MEDIUM에 몰릴 때 총
# 메모리 사용량이 무한정 늘어나는 걸 막는다 (GuardFS/ShieldFS 공통 지적:
# 버퍼 기반 방어는 프로세스 수에 비례해 메모리 요구량이 커지는 DoS 위험).
MEDIUM_GLOBAL_BUFFER_LIMIT_BYTES = 200_000_000

# ========== MEDIUM Policy - Process Trust ========== #
TRUSTED_EXE_PREFIXES = (
    "/bin", "/usr/bin", "/sbin", "/usr/sbin",
    "/usr/local/bin", "/usr/local/sbin",
)

# exe가 이 인터프리터들이면 exe 경로 대신 cmdline의 스크립트 인자를 신뢰 판단 대상으로 삼는다
INTERPRETER_BASENAMES = {
    "python", "python2", "python3",
    "perl", "ruby", "node", "nodejs",
    "bash", "sh", "dash", "zsh", "php",
}