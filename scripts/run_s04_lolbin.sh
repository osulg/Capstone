#!/usr/bin/env bash
# S04: 시스템 Python과 신뢰 경로를 사용하는 LOLBin 실험.
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
SOURCE="$PROJECT_ROOT/experiments/simulators/sim_highentropy.py"
INSTALLED="/usr/local/bin/holdfs_sim.py"
SYSTEM_PYTHON="/usr/bin/python3"
MOUNT_DIR="$HOME/guardfs_runtime/mount"
TARGET="$MOUNT_DIR/s04_lolbin"

fail() {
    printf '[S04] 오류: %s\n' "$*" >&2
    exit 1
}

[ "$(uname -s)" = Linux ] || fail "Ubuntu 내부에서 실행하세요."
[ -f "$SOURCE" ] || fail "프로젝트 원본 시뮬레이터가 없습니다."
[ -x "$SYSTEM_PYTHON" ] || fail "시스템 Python이 없습니다."
[ -f "$INSTALLED" ] || fail "먼저 sudo cp experiments/simulators/sim_highentropy.py /usr/local/bin/holdfs_sim.py 를 실행하세요."
mountpoint -q "$MOUNT_DIR" || fail "HoldFS가 마운트되어 있지 않습니다."

# 수정 전 파일이나 다른 실험 코드가 실행되는 것을 방지한다.
cmp -s "$SOURCE" "$INSTALLED" || \
    fail "설치된 시뮬레이터와 프로젝트 원본이 다릅니다. 다시 복사하세요."

if grep -q 'os.waitstatus_to_exitcode' "$INSTALLED"; then
    fail "구버전 Python 호환성 수정이 필요합니다."
fi

printf '[S04] 실행 Python: %s\n' "$SYSTEM_PYTHON"
printf '[S04] 실행 스크립트: %s\n' "$INSTALLED"
printf '[S04] 대상: %s\n' "$TARGET"
printf '[S04] 출력되는 공격 PID를 기준으로 ML 점수와 HIGH 사유를 확인하세요.\n'

# 가상환경 활성화 여부와 관계없이 시스템 Python을 직접 사용한다.
# 생성한 더미 파일은 종료 후에도 보존한다.
timeout --signal=KILL 120s \
    "$SYSTEM_PYTHON" -u "$INSTALLED" "$TARGET" \
    --files 20 \
    --size-kb 64 \
    --chunk-kb 16 \
    --passes 1 \
    --duration 30 \
    --delay 0.15 \
    --keep
