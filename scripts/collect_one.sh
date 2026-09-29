#!/bin/bash
# ============================================================
# GuardFS 단일 샘플 수집 스크립트 (FUSE + eBPF 동시 수집)
#
# 하나의 run_id로
#   1) GuardFS를 --collect-only 모드로 마운트 (FUSE 관점 로깅)
#   2) 마운트 안에 테스트 파일 준비 + 실행 전 해시
#   3) eBPF 수집기로 워크로드를 추적 (eBPF 관점 로깅)
#   4) 실행 후 해시 비교 + 결과 요약
#   5) 마운트 해제
# 를 한 번에 수행한다.
#
# ⚠️ 이 스크립트는 워크로드(샘플)를 스스로 고르거나 내려받지 않는다.
#    추적할 명령은 반드시 사용자가 '--' 뒤에 직접 넘겨야 하며,
#    그 명령을 실행하는 주체는 사용자다.
#
# 사용법:
#   scripts/collect_one.sh --run-id <ID> [옵션] -- <실행할 명령> [인자...]
#
# 옵션:
#   --run-id <ID>          (필수) 예: lockbit_4dc06ece_001  (dataset_v2 명명 규칙)
#   --as-user <user>       워크로드를 이 사용자 권한으로 실행 (정상 워크로드용, label 0)
#   --timeout <sec>        eBPF 수집기 최대 실행 시간(초). 기본 120
#   --target-subdir <name> 마운트 하위 대상 디렉터리 이름. 기본 attack_target
#   --no-prep              테스트 파일 20종 생성을 건너뜀 (기존 마운트 내용 사용)
#   --repo <path>          레포 루트. 기본: 이 스크립트의 상위 디렉터리
#   -h, --help             도움말
#
# 예) 악성 세션 (샘플 실행은 사용자 몫):
#   scripts/collect_one.sh --run-id lockbit_4dc06ece_001 -- \
#       sudo /path/to/sample.elf "$HOME/guardfs_runtime/mount/attack_target"
#
# 예) 정상 세션 (label 0):
#   scripts/collect_one.sh --run-id benign_bulkread_001 --as-user "$USER" -- \
#       python3 models/dynamic/dataset_v2/benign_bulk_read.py \
#       "$HOME/guardfs_runtime/mount/attack_target"
# ============================================================

set -uo pipefail

# ----------------------------------------
# 기본값
# ----------------------------------------
RUN_ID=""
AS_USER=""
TIMEOUT="120"
TARGET_SUBDIR="attack_target"
DO_PREP=1
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/.." && pwd)"

RUNTIME_DIR="$HOME/guardfs_runtime"
MOUNT_DIR="$RUNTIME_DIR/mount"
UNDERLAY_DIR="$RUNTIME_DIR/underlay"
COLLECT_DIR="$RUNTIME_DIR/collect"
HASH_DIR="$RUNTIME_DIR/hashes"

usage() {
    sed -n '2,45p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
    exit "${1:-0}"
}

die() {
    echo "[collect_one] ERROR: $*" >&2
    exit 1
}

# ----------------------------------------
# 인자 파싱 ('--' 이전은 옵션, 이후는 실행할 명령)
# ----------------------------------------
COMMAND=()
while [ $# -gt 0 ]; do
    case "$1" in
        --run-id)        RUN_ID="${2:-}"; shift 2 ;;
        --as-user)       AS_USER="${2:-}"; shift 2 ;;
        --timeout)       TIMEOUT="${2:-}"; shift 2 ;;
        --target-subdir) TARGET_SUBDIR="${2:-}"; shift 2 ;;
        --no-prep)       DO_PREP=0; shift ;;
        --repo)          REPO="${2:-}"; shift 2 ;;
        -h|--help)       usage 0 ;;
        --)              shift; COMMAND=("$@"); break ;;
        *)               die "알 수 없는 옵션: $1 (도움말: --help)" ;;
    esac
done

# ----------------------------------------
# 검증
# ----------------------------------------
[ -n "$RUN_ID" ] || die "--run-id 가 필요합니다."
[[ "$RUN_ID" =~ ^[A-Za-z0-9._-]+$ ]] || die "run_id 형식 오류(영문/숫자/._- 만): $RUN_ID"
[ "${#COMMAND[@]}" -gt 0 ] || die "추적할 명령이 없습니다. '-- <command>' 형태로 넘기세요."

COLLECTOR="$REPO/models/dynamic/collect/ebpf_collector.py"
PASSTHROUGH="$REPO/guardfs/fuse_fs/passthrough.py"
VENV_ACTIVATE="$REPO/venv/bin/activate"
TARGET_DIR="$MOUNT_DIR/$TARGET_SUBDIR"

[ -f "$COLLECTOR" ]   || die "수집기를 찾을 수 없음: $COLLECTOR"
[ -f "$PASSTHROUGH" ] || die "passthrough.py를 찾을 수 없음: $PASSTHROUGH"
[ -f "$VENV_ACTIVATE" ] || die "venv가 없습니다. 먼저 ./scripts/setup.sh 실행: $VENV_ACTIVATE"

# 이미 존재하는 run_id 로그는 수집기가 거부하므로 미리 확인
FUSE_LOG="$COLLECT_DIR/${RUN_ID}.fuse.jsonl"
EBPF_LOG="$COLLECT_DIR/${RUN_ID}.ebpf.jsonl"
if [ -e "$FUSE_LOG" ] || sudo test -e "$EBPF_LOG"; then
    die "이미 같은 run_id의 로그가 존재합니다. run 번호를 올리세요. ($RUN_ID)"
fi

# tracefs (eBPF tracepoint 컴파일에 필요)
if [ ! -e /sys/kernel/tracing/events/raw_syscalls/sys_enter/format ] \
   && [ ! -e /sys/kernel/debug/tracing/events/raw_syscalls/sys_enter/format ]; then
    echo "[collect_one] tracefs 마운트 중..."
    sudo mount -t tracefs nodev /sys/kernel/tracing || die "tracefs 마운트 실패"
fi

mkdir -p "$RUNTIME_DIR" "$MOUNT_DIR" "$UNDERLAY_DIR" "$HASH_DIR"

# ----------------------------------------
# 정리 트랩: 종료 시 GuardFS 마운트 해제
# ----------------------------------------
GUARDFS_PID=""
cleanup() {
    if [ -n "$GUARDFS_PID" ] && kill -0 "$GUARDFS_PID" 2>/dev/null; then
        echo "[collect_one] GuardFS 종료(PID $GUARDFS_PID)..."
        kill -INT "$GUARDFS_PID" 2>/dev/null
        wait "$GUARDFS_PID" 2>/dev/null
    fi
    if mountpoint -q "$MOUNT_DIR"; then
        "$REPO/scripts/unmount.sh" >/dev/null 2>&1 \
            || fusermount3 -u "$MOUNT_DIR" 2>/dev/null \
            || fusermount -u "$MOUNT_DIR" 2>/dev/null
    fi
}
trap cleanup EXIT INT TERM

# ----------------------------------------
# 1) GuardFS --collect-only 마운트 (백그라운드, venv 파이썬)
# ----------------------------------------
if mountpoint -q "$MOUNT_DIR"; then
    die "GuardFS가 이미 마운트되어 있습니다. 먼저 ./scripts/unmount.sh"
fi

echo "========================================================"
echo " GuardFS 수집 시작"
echo "  run_id     : $RUN_ID"
echo "  mount      : $MOUNT_DIR"
echo "  target     : $TARGET_DIR"
echo "  collect    : $COLLECT_DIR"
echo "  timeout    : ${TIMEOUT}s"
echo "  as_user    : ${AS_USER:-(root)}"
echo "  command    : ${COMMAND[*]}"
echo "========================================================"

echo "[collect_one] GuardFS 마운트(collect-only) 중..."
# shellcheck disable=SC1090
( source "$VENV_ACTIVATE"; exec python3 "$PASSTHROUGH" "$MOUNT_DIR" "$UNDERLAY_DIR" \
      --collect-only --run-id "$RUN_ID" ) &
GUARDFS_PID=$!

# 마운트 완료 대기 (최대 15초)
for _ in $(seq 1 30); do
    if mountpoint -q "$MOUNT_DIR"; then break; fi
    if ! kill -0 "$GUARDFS_PID" 2>/dev/null; then die "GuardFS가 시작 중 종료됨"; fi
    sleep 0.5
done
mountpoint -q "$MOUNT_DIR" || die "GuardFS 마운트 실패(타임아웃)"
echo "[collect_one] 마운트 완료"

# ----------------------------------------
# 2) 대상 파일 준비 + 실행 전 해시
# ----------------------------------------
if [ "$DO_PREP" -eq 1 ]; then
    echo "[collect_one] 테스트 파일 20종 생성: $TARGET_DIR"
    mkdir -p "$TARGET_DIR"
    i=1
    for ext in txt doc docx pdf xls xlsx ppt pptx html ps jpg png csv json xml log bak db sql unk; do
        printf 'GuardFS test file\nindex=%02d\nextension=%s\nrun=%s\n' \
            "$i" "$ext" "$RUN_ID" \
            > "$TARGET_DIR/file_$(printf '%02d' "$i").$ext"
        i=$((i + 1))
    done
else
    echo "[collect_one] --no-prep: 기존 마운트 내용 사용"
    mkdir -p "$TARGET_DIR"
fi

BEFORE_HASH="$HASH_DIR/${RUN_ID}_before.sha256"
( cd "$TARGET_DIR" && find . -type f -exec sha256sum {} + 2>/dev/null | sort ) > "$BEFORE_HASH"
echo "[collect_one] 실행 전 해시: $BEFORE_HASH ($(wc -l < "$BEFORE_HASH") 파일)"

# ----------------------------------------
# 3) eBPF 수집기로 워크로드 추적 (root 권한, 시스템 python + bcc)
#    수집기는 프로브 등록 전까지 워크로드를 멈춰뒀다가 시작한다.
# ----------------------------------------
COLLECTOR_ARGS=(
    "$COLLECTOR"
    --run-id "$RUN_ID"
    --target-dir "$MOUNT_DIR"
    --timeout "$TIMEOUT"
)
[ -n "$AS_USER" ] && COLLECTOR_ARGS+=(--as-user "$AS_USER")

echo "[collect_one] eBPF 수집기 시작 (워크로드는 사용자가 지정한 명령)"
echo "--------------------------------------------------------"
sudo python3 "${COLLECTOR_ARGS[@]}" -- "${COMMAND[@]}"
COLLECTOR_RC=$?
echo "--------------------------------------------------------"
echo "[collect_one] 수집기 종료 (rc=$COLLECTOR_RC)"

# ----------------------------------------
# 4) 실행 후 해시 + 변경 요약
# ----------------------------------------
AFTER_HASH="$HASH_DIR/${RUN_ID}_after.sha256"
( cd "$TARGET_DIR" && sudo find . -type f -exec sha256sum {} + 2>/dev/null | sort ) > "$AFTER_HASH"

echo ""
echo "=== 파일 변경 요약 ==="
if diff -q "$BEFORE_HASH" "$AFTER_HASH" >/dev/null; then
    echo "변경 없음 (파일 내용 동일)"
else
    CHANGED=$(comm -13 <(cut -d' ' -f1 "$BEFORE_HASH" | sort) \
                       <(cut -d' ' -f1 "$AFTER_HASH" | sort) | wc -l)
    echo "파일 변경 감지됨 (해시 기준). before=$(wc -l < "$BEFORE_HASH") after=$(wc -l < "$AFTER_HASH")"
fi

# ----------------------------------------
# 5) 로그 요약
# ----------------------------------------
echo ""
echo "=== 수집 로그 (${COLLECT_DIR}) ==="
for suffix in ebpf fuse; do
    log="$COLLECT_DIR/${RUN_ID}.${suffix}.jsonl"
    if sudo test -e "$log"; then
        lines=$(sudo wc -l < "$log" 2>/dev/null || echo "?")
        echo "  ${RUN_ID}.${suffix}.jsonl : ${lines} events"
    else
        echo "  ${RUN_ID}.${suffix}.jsonl : (없음)"
    fi
done

echo ""
echo "[collect_one] 완료. 다음 샘플 전에 Infected VM 스냅샷을 복원하세요."
# cleanup 트랩이 마운트 해제를 처리한다.
