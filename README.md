# GuardFS

FUSE 기반 악성코드 탐지 파일시스템

## 실행 방법
```bash
mkdir -p mnt underlay/honeypot
echo "do not touch" > underlay/honeypot/decoy.txt
python3 passthrough.py mnt underlay
```
