# GuardFS

FUSE 기반 악성코드 탐지 파일시스템

## 환경 설정
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 실행
```bash
./scripts/setup.sh          # 최초 1회: runtime 디렉토리 생성
./scripts/run_guardfs.sh    # GuardFS 실행 (= python3 -m guardfs.main)
```

## 실험
```bash
python3 experiments/simulators/stage1_detection/sim_entropy.py
```

## 종료 / 정리
```bash
./scripts/unmount.sh
./scripts/cleanup.sh
```

## 모델
- `guardfs/models/static/` : byte 3-gram(n=3, k=1000) 정적 모델 (vocab + pkl)
- `guardfs/models/dynamic/`: O/C/D/E 동적 모델 (best_model.pkl + scaler.pkl)
- sklearn==1.3.2 고정 필수 (`guardfs/models/metadata/model_info.md` 참고)
