#!/bin/bash
# GuardFS 실행 자동화
set -e
cd "$(dirname "$0")/.."
if [ -d venv ]; then source venv/bin/activate; fi
exec python3 -m guardfs.main ~/guardfs_runtime/mount ~/guardfs_runtime/underlay
