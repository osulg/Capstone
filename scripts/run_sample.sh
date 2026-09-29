#!/bin/bash
# ============================================================
# run_sample.sh — 악성 샘플 1개를 GuardFS(FUSE+eBPF)로 수집
#
# collect_one.sh를 감싸서 다음을 자동 처리한다.
#   - ~/malware/<FAMILY>/ 에서 샘플 찾기 (SHA8 앞자리로 지정 가능)
#   - 실행권한 부여 (chmod +x)
#   - 패밀리별 인자 형식 자동 적용 (미검증 패밀리는 경고)
#   - run_id 자동 생성/증가 (<family>_<sha8>_<NNN>)
#   - HelloKitty libcrypto 심링크 등 특수처리
#   - 기본은 현재 사용자로 실행(FUSE 마운트 접근). --root로 전환 가능.
#
# ⚠️ 이 스크립트는 샘플을 스스로 고르거나 내려받지 않는다. 실행할 패밀리는
#    사용자가 인자로 지정하며, 실제 실행 주체는 사용자다.
#
# 사용법:
#   scripts/run_sample.sh <FAMILY> [SHA8] [옵션]
# 옵션:
#   --root         root(sudo)로 실행 (기본: 현재 사용자)
#   --timeout N    수집 시간(초). 기본 120
#   --run NNN      run 번호 강제 지정
#   --list         해당 패밀리 샘플 목록만 출력하고 종료
#
# 예:
#   scripts/run_sample.sh HelloKitty
#   scripts/run_sample.sh lockbit 4dc06ece
#   scripts/run_sample.sh Akira 0ee1d284 --timeout 180
#   scripts/run_sample.sh Conti --list
# ============================================================
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MALWARE_BASE="${MALWARE_BASE:-$HOME/malware}"
TARGET="$HOME/guardfs_runtime/mount/attack_target"
COLLECT_DIR="$HOME/guardfs_runtime/collect"
COLLECT_ONE="$SCRIPT_DIR/collect_one.sh"

die() { echo "[run_sample] ERROR: $*" >&2; exit 1; }

# ---------- 인자 파싱 ----------
FAMILY=""; SHA8=""; AS_ROOT=0; TIMEOUT=120; RUN_FORCE=""; LIST_ONLY=0
while [ $# -gt 0 ]; do
    case "$1" in
        --root)    AS_ROOT=1; shift ;;
        --timeout) TIMEOUT="${2:-}"; shift 2 ;;
        --run)     RUN_FORCE="${2:-}"; shift 2 ;;
        --list)    LIST_ONLY=1; shift ;;
        -h|--help) sed -n '2,35p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        -*)        die "알 수 없는 옵션: $1" ;;
        *) if [ -z "$FAMILY" ]; then FAMILY="$1"
           elif [ -z "$SHA8" ]; then SHA8="$1"
           else die "인자가 너무 많습니다: $1"; fi; shift ;;
    esac
done

[ -n "$FAMILY" ] || die "패밀리를 지정하세요. 예: run_sample.sh HelloKitty"
[ -f "$COLLECT_ONE" ] || die "collect_one.sh를 찾을 수 없음: $COLLECT_ONE"
FAM_DIR="$MALWARE_BASE/$FAMILY"
[ -d "$FAM_DIR" ] || die "패밀리 폴더 없음: $FAM_DIR"

# ---------- 샘플 선택 ----------
mapfile -t ELVES < <(ls "$FAM_DIR"/*.elf 2>/dev/null | sort)
[ "${#ELVES[@]}" -gt 0 ] || die "$FAM_DIR 에 .elf 파일이 없음"

if [ "$LIST_ONLY" -eq 1 ]; then
    printf '%s\n' "${ELVES[@]##*/}"
    exit 0
fi

ELF=""
if [ -n "$SHA8" ]; then
    for e in "${ELVES[@]}"; do
        [[ "${e##*/}" == "$SHA8"* ]] && ELF="$e" && break
    done
    [ -n "$ELF" ] || die "SHA8 '$SHA8' 로 시작하는 샘플이 $FAMILY 에 없음"
elif [ "${#ELVES[@]}" -eq 1 ]; then
    ELF="${ELVES[0]}"
else
    echo "[run_sample] $FAMILY 에 샘플이 여러 개예요. SHA8 앞자리로 지정하세요:"
    printf '  %s\n' "${ELVES[@]##*/}"
    exit 1
fi

BASENAME="$(basename "$ELF" .elf)"
SHA8="${BASENAME:0:8}"
FAM_LC="$(echo "$FAMILY" | tr '[:upper:]' '[:lower:]')"

# ---------- run 번호 결정 (기존 로그와 충돌 회피) ----------
if [ -n "$RUN_FORCE" ]; then
    RUN="$RUN_FORCE"
else
    RUN=1
    while [ -e "$COLLECT_DIR/${FAM_LC}_${SHA8}_$(printf '%03d' "$RUN").ebpf.jsonl" ] \
       || [ -e "$COLLECT_DIR/${FAM_LC}_${SHA8}_$(printf '%03d' "$RUN").fuse.jsonl" ]; do
        RUN=$((RUN + 1))
    done
fi
RID="${FAM_LC}_${SHA8}_$(printf '%03d' "$RUN")"

# ---------- 실행권한 ----------
chmod +x "$ELF" 2>/dev/null || sudo chmod +x "$ELF" || die "chmod +x 실패: $ELF"

# ---------- 패밀리별 인자 (검증된 것만; 나머지는 경로 위치인자 + 경고) ----------
VERIFIED=1
case "$FAMILY" in
    Babuk|IceFire|lockbit)  ARGS=( "$TARGET" ) ;;
    AvosLocker)             ARGS=( 50 "$TARGET" ) ;;
    MONTI|REvil)            ARGS=( --path "$TARGET" ) ;;
    BlackCat|blackcat)      ARGS=( --access-token "ANY_TOKEN" -p "$TARGET" --verbose ) ;;
    HelloKitty)
        sudo ln -sf /lib/x86_64-linux-gnu/libcrypto.so.3 \
                    /lib/x86_64-linux-gnu/libcrypto.so 2>/dev/null || true
        ARGS=( -m 50 "$TARGET" ) ;;
    wiper|wiper_misc)       ARGS=( ) ;;
    *)                      ARGS=( "$TARGET" ); VERIFIED=0 ;;
esac

echo "========================================================"
echo " run_sample : $FAMILY"
echo " sample     : ${ELF##*/}"
echo " run_id     : $RID"
echo " mode       : $([ "$AS_ROOT" -eq 1 ] && echo 'root' || echo "user($USER)")"
echo " timeout    : ${TIMEOUT}s"
echo " args       : ${ARGS[*]:-(없음)}"
if [ "$VERIFIED" -eq 0 ]; then
    echo " ⚠️  '$FAMILY' 인자 형식 미검증 — 기본(경로 위치인자)으로 실행함."
    echo "     결과에서 'No Files Found'나 이벤트 수가 적으면 인자 확인 필요:"
    echo "       strings '$ELF' | grep -iE 'usage|--|path|encrypt' | head"
fi
echo "========================================================"

# ---------- collect_one.sh 호출 ----------
CMD=( "$COLLECT_ONE" --run-id "$RID" --timeout "$TIMEOUT" )
if [ "$AS_ROOT" -eq 1 ]; then
    # collector가 이미 root이므로 워크로드도 root로 실행됨
    CMD+=( -- "$ELF" "${ARGS[@]}" )
else
    # FUSE 마운트 접근을 위해 마운트 소유 사용자로 실행
    CMD+=( --as-user "$USER" -- "$ELF" "${ARGS[@]}" )
fi

"${CMD[@]}"
RC=$?

echo ""
echo "[run_sample] run_id=$RID 종료. 결과 요약은 위 'collect_one' 출력을 확인하세요."
echo "[run_sample] 성공(파일 변경 감지됨)이면 → 스냅샷 복원 후 다음 샘플."
echo "[run_sample] 실패면 로그 정리: sudo rm -f $COLLECT_DIR/${RID}.* $HOME/guardfs_runtime/hashes/${RID}_*"
exit $RC
