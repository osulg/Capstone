#!/bin/bash
# ============================================================
# run_scenarios.sh — 공개 침해사고 4종 파일연산 모의 재현을 순차 실행
#
# 전제: GuardFS 가 이미 detection 모드로 떠 있고 마운트가 완료돼 있어야 한다.
#   (별도 터미널에서)  bash scripts/run_guardfs.sh
#   또는 대시보드까지   bash dashboard/run_all.sh
#
# 이 스크립트는 GuardFS 를 띄우지 않는다. 마운트 안에 시나리오별 전용 폴더를
# 만들어 각 시뮬레이터를 순서대로 실행한다. 각 시나리오의 작업 폴더 이름에
# 시나리오 슬러그(icefire/darkradiation/huntress/akira)가 들어가므로, 대시보드
# '이벤트' 탭의 Target 경로로 어느 시나리오인지 구분할 수 있다.
#
# 사용법:
#   bash scripts/run_scenarios.sh                 # 4종 전부 (기본값)
#   bash scripts/run_scenarios.sh icefire akira   # 선택 실행
#   MOUNT=~/guardfs_runtime/mount bash scripts/run_scenarios.sh
#   GAP=5 bash scripts/run_scenarios.sh           # 시나리오 간 간격(초)
#
# 환경변수:
#   MOUNT (기본 ~/guardfs_runtime/mount), GAP (기본 3), KEEP (기본 1 → --keep 전달)
# ============================================================
set -uo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MOUNT="${MOUNT:-$HOME/guardfs_runtime/mount}"
GAP="${GAP:-3}"
KEEP="${KEEP:-1}"
SIM_DIR="$PROJECT_ROOT/experiments/simulators"
PY="${PYTHON:-python3}"

KEEP_FLAG=""
[ "$KEEP" = "1" ] && KEEP_FLAG="--keep"

say() { echo ""; echo "=============================================================="; echo " $*"; echo "=============================================================="; }

if ! mountpoint -q "$MOUNT"; then
    echo "[ERROR] 마운트가 아닙니다: $MOUNT"
    echo "        먼저 GuardFS 를 실행하세요:  bash scripts/run_guardfs.sh"
    exit 1
fi

# 실행할 시나리오 목록(인자가 없으면 전부)
SCENARIOS=("$@")
if [ "${#SCENARIOS[@]}" -eq 0 ]; then
    SCENARIOS=(icefire darkradiation huntress akira)
fi

run_one() {
    case "$1" in
        icefire)
            say "① IceFire — 비신뢰 바이너리 직접 암호화 (.ifire)"
            "$PY" "$SIM_DIR/sim_scn_icefire.py" "$MOUNT/sim_icefire" $KEEP_FLAG
            ;;
        darkradiation)
            say "② DarkRadiation — 신뢰 도구(openssl) 암호화 (☢)"
            # 신뢰 시연: 시스템 openssl 이 있으면 openssl 엔진, 없으면 inprocess
            if [ -x /usr/bin/openssl ]; then ENGINE=openssl; else ENGINE=inprocess; fi
            "$PY" "$SIM_DIR/sim_scn_darkradiation.py" "$MOUNT/sim_darkradiation" \
                --engine "$ENGINE" $KEEP_FLAG
            ;;
        huntress)
            say "③ Huntress — 읽기 기반 탈취(Actor C) + 허니팟 경유 + 로그삭제(Actor B)"
            echo "--- Actor C: 읽기 기반 탈취 (사각지대 관찰) ---"
            "$PY" "$SIM_DIR/sim_scn_huntress.py" "$MOUNT/sim_huntress" $KEEP_FLAG
            sleep 1
            echo "--- Actor C: 허니팟 경유 (탐지 경로) ---"
            "$PY" "$SIM_DIR/sim_scn_huntress.py" "$MOUNT/sim_huntress" --honeypot $KEEP_FLAG
            sleep 1
            echo "--- Actor B: 로그 연속 삭제 ---"
            "$PY" "$SIM_DIR/sim_scn_huntress.py" "$MOUNT/sim_huntress" --actor-b $KEEP_FLAG
            ;;
        akira)
            say "④ Akira — 부분 암호화 VM 더미 파일 (.akiranew)"
            "$PY" "$SIM_DIR/sim_scn_akira.py" "$MOUNT/sim_akira" \
                --encryption-percent 20 --offset head $KEEP_FLAG
            ;;
        *)
            echo "[WARN] 알 수 없는 시나리오: $1 (icefire|darkradiation|huntress|akira)"
            return 1
            ;;
    esac
}

for s in "${SCENARIOS[@]}"; do
    run_one "$s" || true
    sleep "$GAP"
done

say "완료 — 대시보드(이벤트/파일 상태 탭)와 GuardFS 로그에서 결과를 확인하세요."
