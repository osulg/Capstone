# GuardFS Dataset v2

## 목적
기존 수동 PID 라벨링 데이터셋의 provenance 및 label ambiguity 문제를 줄이기 위해,
eBPF process lineage 기반으로 정상/악성 데이터를 새로 수집한다.

## Label 정책

- Label = 1 (ATTACK_LINEAGE)
  - 지정한 악성 Root EXE 자체
  - Root PID의 PPID lineage로 확인된 자식/후손 프로세스

- Label = 0 (BENIGN)
  - 별도의 정상 workload 수집 세션에서 발생한 정상 프로세스

- Label = -1 (AMBIGUOUS)
  - 공격 실험 중 관찰됐지만 악성 Root의 lineage임을 확인할 수 없는 프로세스
  - 학습에서는 제외하고 audit 용도로만 보존

## 데이터 보존

각 실험은 다음 자료를 함께 보존한다.

1. raw JSONL
2. ML feature CSV
3. audit CSV
4. attack_manifest.csv의 sample provenance

## Attack Sample ID

형식:

<family>_<sha256 앞 8자리>_<run번호>

예:
lockbit_4dc06ece_001

동일 샘플을 여러 번 실행할 경우:

lockbit_4dc06ece_001
lockbit_4dc06ece_002

처럼 run 번호를 증가시킨다.

## 원칙

- 기존 legacy Label을 자동으로 정답으로 간주하지 않는다.
- 프로세스 이름만 보고 Label=1/0을 결정하지 않는다.
- 공격 실행 중 발생한 unrelated process는 임의로 정상/악성 처리하지 않고 -1로 둔다.
- CSV는 raw JSONL로부터 재생성 가능해야 한다.
