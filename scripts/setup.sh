#!/bin/bash
# GuardFS 실행에 필요한 초기 환경 생성
set -e
mkdir -p ~/guardfs_runtime/mount ~/guardfs_runtime/underlay/honeypot
echo "[setup] runtime 디렉토리 생성 완료: ~/guardfs_runtime/{mount,underlay}"
