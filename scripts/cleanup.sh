#!/bin/bash
# 실험 후 임시 파일, 로그 및 상태 정보 정리
rm -f ~/guardfs_runtime/guardfs_log.jsonl
rm -f ~/guardfs_runtime/underlay/*.txt 2>/dev/null
echo "[cleanup] 로그 및 임시 파일 정리 완료"
