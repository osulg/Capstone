#!/bin/bash
# HoldFS(HIGH 정책)가 SIGSTOP 으로 멈춰 둔 프로세스를 정리한다.
#
# 시뮬레이터를 돌리면 HIGH 판정을 받은 프로세스가 'T(stopped)' 상태로 계속 남는다.
# 이 스크립트는 HoldFS 기록에 나온 PID 중 지금도 멈춰 있는 프로세스만 골라 종료한다.
# (Ctrl+Z 로 멈춘 vim 같은, HoldFS 와 무관한 정지 프로세스는 건드리지 않는다)
#
# PID 출처
#   - ~/filesecurity.log 의 [HIGH] 기록 (HoldFS 가 직접 씀)
#   - run_all.sh 실행 출력 로그의 "[HIGH] pid=N suspend 완료" 줄 (있을 때만)
#
# 사용법
#   ./scripts/kill_suspended.sh           # 대상 목록을 보여주고 확인 후 SIGKILL
#   ./scripts/kill_suspended.sh -n        # 목록만 보기 (아무것도 종료하지 않음)
#   ./scripts/kill_suspended.sh -y        # 확인 없이 종료
#   ./scripts/kill_suspended.sh --cont    # 종료 대신 SIGCONT 로 다시 실행 (오탐 확인용)

set -u

FILESECURITY_LOG="${FILESECURITY_LOG:-$HOME/filesecurity.log}"
STDOUT_LOG="${GUARDFS_STDOUT_LOG:-$HOME/guardfs_runtime/dashboard_logs/guardfs_stdout.log}"

DRY=0; YES=0; SIG=KILL
for a in "$@"; do
    case "$a" in
        -n|--dry-run) DRY=1 ;;
        -y|--yes) YES=1 ;;
        --cont) SIG=CONT ;;
        -h|--help) sed -n '2,17p' "$0"; exit 0 ;;
        *) echo "알 수 없는 옵션: $a (-h 로 도움말)"; exit 2 ;;
    esac
done

# HoldFS 기록에 나온 PID 모으기
pids_from_logs() {
    if [ -f "$FILESECURITY_LOG" ]; then
        awk '/^\[HIGH\]/{h=1; next} h && /^PID:/{print $2; h=0} /^$/{h=0}' "$FILESECURITY_LOG"
    fi
    if [ -f "$STDOUT_LOG" ]; then
        grep -o '\[HIGH\] pid=[0-9]* suspend 완료' "$STDOUT_LOG" | grep -o 'pid=[0-9]*' | cut -d= -f2
    fi
}

mapfile -t CANDS < <(pids_from_logs | sort -un)

TARGETS=()
for pid in "${CANDS[@]}"; do
    [ -n "$pid" ] || continue
    stat=$(ps -o stat= -p "$pid" 2>/dev/null | tr -d ' ')
    # T = 시그널로 정지 (t 는 디버거 추적이라 제외)
    [[ "$stat" == T* ]] && TARGETS+=("$pid")
done

if [ ${#TARGETS[@]} -eq 0 ]; then
    echo "HoldFS 가 멈춰 둔 프로세스가 없습니다."
    others=$(ps -eo pid=,stat=,comm= | awk '$2 ~ /^T/' | wc -l)
    [ "$others" -gt 0 ] && echo "(HoldFS 기록에 없는 정지 프로세스 ${others}개는 건드리지 않았습니다: ps -eo pid,stat,comm | awk '\$2 ~ /^T/')"
    exit 0
fi

echo "HoldFS 가 멈춰 둔 프로세스 ${#TARGETS[@]}개:"
ps -o pid,ppid,stat,lstart,args -p "$(IFS=,; echo "${TARGETS[*]}")" | cut -c1-160

[ "$DRY" -eq 1 ] && exit 0

if [ "$YES" -ne 1 ]; then
    if [ "$SIG" = KILL ]; then q="모두 종료(SIGKILL)할까요?"; else q="모두 다시 실행(SIGCONT)할까요?"; fi
    read -r -p "$q [y/N] " ans
    [[ "$ans" =~ ^[yY]$ ]] || { echo "취소했습니다."; exit 0; }
fi

fail=0
for pid in "${TARGETS[@]}"; do
    if kill -s "$SIG" "$pid" 2>/dev/null; then
        echo "  pid=$pid SIG$SIG 보냄"
    else
        echo "  pid=$pid 실패 (이미 종료됐거나 권한 없음: 다른 사용자 프로세스면 sudo 로 실행)"
        fail=1
    fi
done
exit $fail
