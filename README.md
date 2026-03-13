# GuardFS

FUSE 기반 악성코드 탐지 파일시스템

## 환경 설정

### 가상환경 생성 및 활성화
python3 -m venv venv
source venv/bin/activate

### 패키지 설치
pip install pyfuse3 trio

## 실행 방법

### 가상환경 활성화
source venv/bin/activate

### FUSE 마운트
python3 passthrough.py mnt underlay

### 언마운트 (다른 터미널에서)
fusermount -u mnt
