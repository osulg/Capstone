#!/usr/bin/env bash
# Ubuntu 최초 설정: GuardFS, 대시보드, 웹 데모, 시뮬레이터 설치.
set -euo pipefail

PROJECT_ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"

if [ "$(uname -s)" != Linux ]; then
    echo '[Setup] Ubuntu/Linux 환경에서 실행하세요.' >&2
    exit 1
fi
if [ "$EUID" -eq 0 ]; then
    echo '[Setup] sudo bash가 아닌 일반 사용자로 실행하세요. 필요한 단계에서 sudo를 요청합니다.' >&2
    exit 1
fi

trap 'printf "[Setup] 설치 실패 (줄 %s). 오류를 해결한 뒤 다시 실행하세요.\n" "$LINENO" >&2' ERR
cd "$PROJECT_ROOT"

echo '[1/4] GuardFS 기본 환경 설치'
bash "$PROJECT_ROOT/scripts/setup.sh"

# setup.sh가 설치한 uv는 현재 셸의 PATH에 아직 없을 수 있다.
if command -v uv >/dev/null 2>&1; then
    UV_BIN="$(command -v uv)"
elif [ -x "$HOME/.local/bin/uv" ]; then
    UV_BIN="$HOME/.local/bin/uv"
else
    echo '[Setup] uv를 찾을 수 없습니다.' >&2
    exit 1
fi

echo '[2/4] 대시보드 Python 패키지 설치'
"$UV_BIN" pip install --python "$PROJECT_ROOT/venv/bin/python" \
    -r "$PROJECT_ROOT/dashboard/requirements.txt"

echo '[3/4] 웹 데모 환경 설치'
bash "$PROJECT_ROOT/scripts/setup_demo_web.sh"

echo '[4/4] 시뮬레이터 설치 (/usr/local/bin/holdfs_sim.py)'
sudo cp -- "$PROJECT_ROOT/experiments/simulators/sim_highentropy.py" \
    /usr/local/bin/holdfs_sim.py

echo '[Setup] 최초 설정 완료'
echo '웹 데모 실행: bash scripts/run_demo_web.sh'
