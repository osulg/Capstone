#!/bin/bash
# 실행 중인 FUSE 파일시스템 마운트 해제
fusermount -u ~/guardfs_runtime/mount 2>/dev/null && echo "[unmount] 완료" || echo "[unmount] 마운트되어 있지 않음"
