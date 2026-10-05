# 동적 모델 v5 — FUSE-only · PID 단위 (런타임 정합 모델)

## 왜 v5인가

런타임(GuardFS 탐지 모드)은 **FUSE 이벤트만** 보고, Stage2는 **PID 단위**로
점수를 매긴다. 기존 v4(`dataset_v4`)는 **eBPF+FUSE 합본을 run 단위**로 집계해
학습했기 때문에, 런타임 입력과 분포가 어긋났다:

| | v4 (연구/검증용) | 런타임 | v5 (배포용) |
|---|---|---|---|
| 신호원 | eBPF + FUSE | **FUSE만** | **FUSE만** |
| 집계 단위 | run(모든 PID 합산) | **PID** | **PID** |
| proc_count | run 내 프로세스 수 | 항상 1 | **제외** |
| crypto_calls | eBPF uprobe | 없음 | **제외** |

v5는 런타임이 실제로 보는 신호에 맞춘다. **재수집은 하지 않는다** — 이미 모은
`*.fuse.jsonl`을 FUSE-only·PID 단위로 **다시 계산**할 뿐이다. eBPF 로그는
악성 서브트리를 가려내는 **라벨링(빌드 타임)에만** 쓰이고, 탐지기에는 안 쓰인다.

## 피처 (22개)

`features.py:FEATURE_ORDER`(24) 에서 `proc_count`, `crypto_calls` 제외.
런타임 `PidStats.to_feature_row()` 와 추출기 `extract_perpid_fuse.py` 가
동일 산식을 쓴다(검증: 두 경로 피처값 바이트 단위 일치).

## 라벨링

- 정상 run: 모든 PID `label=0`
- 악성 run: **악성 프로세스 서브트리의 PID만 `label=1`**, prep/수집 하네스는 `0`.
  서브트리는 `<run_id>.ebpf.meta.json` 의 `root_pid` + `<run_id>.ebpf.jsonl`
  의 (pid,ppid) lineage 로 계산. (prep PID는 유용한 정상 샘플이 된다.)

## VM에서 실행 (GuardFS venv — 배포 때와 같은 sklearn)

피처 추출은 이미 끝나 `dataset_v5/features_perpid.csv` 로 커밋돼 있다
(클라우드에서 전체 286 run의 원시 로그로 추출·검증 완료). 성능 수치는
`RESULTS.md` 참고. **VM에서는 모델 pkl만 그 CSV로 학습**하면 된다 — 원시 로그
불필요. pkl은 반드시 GuardFS venv(배포 sklearn)에서 만들어야 런타임 로드시
깨지지 않는다.

```bash
cd ~/Capstone
source venv/bin/activate          # pyfuse3/trio/sklearn 있는 그 venv

# 커밋된 features_perpid.csv 로 모델 학습·저장 (몇 초)
python3 models/dynamic/collect/train_v5.py \
    --features models/dynamic/dataset_v5/features_perpid.csv \
    --out-model models/dynamic/rf_model_v5.pkl \
    --out-cols  models/dynamic/feature_cols_v5.json
```

`train_v5.py` 출력 마지막 줄 **`로드 자가진단 predict_proba 범위 정상`** 이어야
한다(아니면 sklearn 버전 문제 — venv 확인). 임계값은 이미 데이터로 확정됨
(`STAGE2_DYN_ONLY_HIGH_THRESHOLD = 0.5`, 근거는 RESULTS.md).

> 원시 로그로 처음부터 재현하려면 `extract_perpid_fuse.py` 부터 돌리면 된다
> (아래 "재현" 참고). VM엔 정상 로그만 있고 악성 원시 로그는 dataset_v4.zip 에
> 있으므로, 정상+악성 로그를 한 폴더에 모아 `--collect-dir` 로 지정할 것.

## 테스트

```bash
# detection 모드 재기동 후 (venv), sim_entropy 로 스크립트형 랜섬웨어 차단 확인
python3 guardfs/fuse_fs/passthrough.py ~/guardfs_runtime/mount ~/guardfs_runtime/underlay
# 다른 터미널:
python3 experiments/simulators/sim_entropy.py ~/guardfs_runtime/mount/victim.txt
# 기대: [STAGE2] ... dyn 높음 → dyn_only 로 HIGH 격상 → 차단
# 정상 작업(cp/tar/gzip/git)에서 HIGH 안 뜨는지도 함께 확인(오탐 점검)
```

## 되돌리기

문제가 있으면 `paths.py` 의 `DYNAMIC_MODEL_PATH`/`DYNAMIC_FEATURE_COLS_PATH`
를 v2로 되돌리면 된다(v2 모델 파일은 그대로 보존).
## 모델 파일 환경

`rf_model_v5.pkl` 은 scikit-learn 1.3.2, Python 3.12.3 (GuardFS venv)에서 학습했다. 다른 버전에서는 predict_proba 가 깨질 수 있다.
