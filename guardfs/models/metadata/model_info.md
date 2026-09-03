# 모델 메타데이터
| 모델 | 파일 | feature | 학습 데이터 | 학습 환경 |
|---|---|---|---|---|
| 정적 | static_rf_n3_k1000.pkl | byte 3-gram k=1000 (k합 정규화) | 501개 (정상288/악성213) | sklearn 1.3.2 |
| 동적 | best_model.pkl + scaler.pkl | O/C/D/E sums + 3-gram 39개 | lineage 라벨링 데이터셋 | sklearn 1.3.2 |

- fusion: dynamic 0.5 + static 0.5 (config.py)
- sklearn==1.3.2 고정 필수 (버전 불일치 시 predict_proba 값 깨짐 확인됨)
