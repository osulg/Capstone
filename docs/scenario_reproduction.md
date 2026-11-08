# 공개 침해사고 파일연산 모의 재현 (GuardFS/HoldFS 검증)

본 문서는 공개된 실제 침해사고 4종에서 **GuardFS 가 관찰 가능한 파일시스템
행위만** 격리·더미 환경에서 모의 재현하는 시뮬레이터와, 각 시나리오가 어떤
탐지기·상태로 이어질지에 대한 **예상 결과**, 그리고 구현 중 발견한 **설계상
편차·한계**를 정리한다. 원 시나리오 설계 문서(요청 첨부)의 선정 기준·근거를
그대로 따른다.

> 전제: 모든 시뮬레이터는 실제 랜섬웨어/멀웨어가 아니다. 암호키·복호·C2·수익화·
> 전파·자격탈취·실제 ESXi 제어가 없고, 각 스크립트가 **마운트 안에 새로 만든
> 전용 workdir 의 더미 파일**만 다룬다. 초기 접근·전달·웜·계정조작 등은 각
> 사고 문서의 "배경·범위 밖"이므로 재현하지 않고 전제로만 둔다.

---

## 1. 구성 파일

| 경로 | 역할 |
| --- | --- |
| `experiments/simulators/scenario_lib.py` | 공용 하네스(안전 불변식: 전용 workdir, 광범위 대상 거부, PID 분리 준비/검증, 자식 reaping, 부분/전체 난수 덮어쓰기, 노트, 정리) |
| `experiments/simulators/sim_scn_icefire.py` | ① IceFire — 비신뢰 바이너리 직접 암호화 |
| `experiments/simulators/sim_scn_darkradiation.py` | ② DarkRadiation — 신뢰 도구(openssl) 암호화 |
| `experiments/simulators/sim_scn_huntress.py` | ③ Huntress — 읽기 기반 탈취(Actor C) + 로그삭제(Actor B) |
| `experiments/simulators/sim_scn_akira.py` | ④ Akira — 부분 암호화 VM 더미 파일 |
| `scripts/run_scenarios.sh` | 4종을 라이브 마운트에 순차 실행(오케스트레이션) |
| `experiments/tests/test_scenario_sims.py` | FUSE-비의존 단위 테스트 |

---

## 2. 실행 방법 (요약; 상세는 각 스크립트 docstring)

GuardFS 와 대시보드가 떠 있어야 한다. 터미널 두 개를 쓴다.

```bash
# 터미널 A — GuardFS + 대시보드 + 에이전트 한 번에
cd ~/Capstone
bash dashboard/run_all.sh            # http://127.0.0.1:5000
#   (대시보드 없이 탐지 로그만 보려면)  bash scripts/run_guardfs.sh

# 터미널 B — 시나리오 실행
cd ~/Capstone && source venv/bin/activate
mountpoint ~/guardfs_runtime/mount   # 마운트 확인
bash scripts/run_scenarios.sh                 # 4종 전부
#   또는 개별:
bash scripts/run_scenarios.sh icefire akira
```

각 시나리오 workdir 이름에 슬러그(`sim_icefire` 등)가 들어가므로, 대시보드
**이벤트** 탭의 Target 경로로 어느 시나리오의 연산인지 구분한다. **파일 상태**
탭에서는 보호 폴더의 암호화 의심 파일과 허니팟 미끼를 확인한다.

---

## 3. 시나리오별 재현 범위와 예상 결과

예상 결과는 코드/설정(`guardfs/common/config.py`, `stage1/*`, `stage2/*`) 근거의
**추정**이며, 실측값이 아니다. 실제 수치·격상 여부는 VM 에서 확인한다.

### ① IceFire (`sim_scn_icefire.py`)
- **재현**: 더미 문서 read → 고엔트로피 난수 덮어쓰기 → `.ifire` rename →
  모의 노트 생성 → 도구 표식 파일 자기 삭제(unlink).
- **제외(전제)**: Aspera Faspex CVE-2022-47986 초기 접근, wget/chmod 페이로드 반입.
- **예상 탐지**: 비신뢰 실행 경로 → `_resolve_effective_state` 가 **선제 MEDIUM**.
  고엔트로피 write → `EntropyDetector`(파일 앞 256B) 및 `EntropyBurstDetector`.
  `.ifire` rename → `ExtChangeDetector` **즉시 차단**(§4 개선으로 계열 확장자 추가).
  Stage2 재평가에서 dyn 점수 상승 → **HIGH → write/rename/unlink 차단 + SIGSTOP**.
- **관전 포인트**: 신뢰 면제 없이 Stage1 경량 규칙에 즉시 걸리는 전형.

### ② DarkRadiation (`sim_scn_darkradiation.py`)
- **재현**: 더미 파일 read → AES-256-CBC 암호화 덮어쓰기 → `☢`(U+2622) rename.
  `--engine openssl` 은 시스템 `/usr/bin/openssl`(신뢰 경로, dpkg 검증)이 쓰기를
  수행. `--engine inprocess` 는 단일 프로세스가 수행.
- **제외(전제)**: SSH 웜(`downloader.sh`/`sshpass`), openssl/yum 설치, who/shadow/
  ferrum 계정조작, Docker 중지.
- **예상 탐지**: 쓰기 주체가 **신뢰**면 비신뢰 선제-MEDIUM 게이트가 적용되지 않는다.
  Stage1 `EntropyDetector` 가 걸리면 `mark_suspect` → SUSPICIOUS 로 큐잉되지만,
  `_resolve_suspicious_state` 가 신뢰 PID 의 SUSPICIOUS 를 LOW 로 매핑해 **재평가
  동안 write 가 underlay 로 반영**된다. 즉 **Stage2 동적 ML(dyn 단독 격상,
  `STAGE2_DYN_ONLY_HIGH_THRESHOLD=0.6`)이 유일한 탐지 주체**가 되고, 재평가 지연
  동안 일부 파일이 변경(=손실)된다. → **탐지 ≠ 완전 차단**.
- **관전 포인트**: MEDIUM/HIGH 도달 전 반영된 파일 수, 정상 openssl 작업과의 오탐.
- **주의**: 신뢰 분류는 실행 방식에 좌우된다(§4의 발견 2 참조). 신뢰 시연은
  `--engine openssl` 을 권장.

### ③ Huntress (`sim_scn_huntress.py`)
- **재현(Actor C)**: 더미 `.ssh/.aws/.kube/.env` 를 순차 open/read(내용 불변).
  - 기본(decoy): 평범한 더미 → **읽기만으로는 LOW 유지 가능**(사각지대).
  - `--honeypot`: 허니팟 경로(`<mount>/honeypot`) 미끼에 **읽기 접근 시도** →
    `HoneypotDetector` 탐지 + `[HONEYPOT] blocked`.
- **재현(Actor B, `--actor-b`)**: 더미 로그 다수를 짧은 시간에 연속 unlink →
  1초 창 `d_win ≥ STATS_UNLINK_THRESHOLD(2)` → `[SUSPICIOUS]` → Stage2.
- **제외**: Base64/wget/urllib/perl/netcat 반입, cron.d/UDEV/systemd 지속성, XMRig,
  **외부 반출(`wget --post-file`)은 실제 전송 없이 읽기까지만**.
- **관전 포인트**: 읽기 기반 탈취는 쓰기/엔트로피/rename 신호가 없어 현재 탐지
  파이프라인에서 대체로 LOW 에 머문다(**읽기 기록 ≠ 유출 탐지**). 허니팟 배치가
  이 사각지대를 메우는 유일한 경로임을 보여준다.

### ④ Akira (`sim_scn_akira.py`)
- **재현**: 더미 `.vmdk/.vmx/.vmsd/.vmsn` read → 파일의 일부 비율만
  (`--encryption-percent`, 기본 20%) 난수 덮어쓰기(부분 암호화) → `.akiranew`
  rename → `akiranew.txt` 모의 노트. `--offset {head,tail}` 로 덮어쓰기 위치 선택.
- **제외**: Cloudflare Tunnel, Netscan, Mimikatz/DonPAPI, RDP/wmiexec, net use/7-Zip,
  **실제 ESXi SSH·VMFS 암호화·ESXCLI·vim-cmd VM 전원제어**.
- **예상 탐지**: `EntropyDetector` 는 파일 앞 `ENTROPY_HEADER_SIZE(256B)` 를 본다.
  - `--offset head`: 앞부분을 덮으면 헤더 엔트로피가 올라 **탐지되기 쉽다**.
  - `--offset tail`: 뒷부분만 덮으면 헤더가 평문으로 보존돼 **놓치기 쉽다**
    (헤더보존 사각지대). `.akiranew` rename(§4 개선으로 즉시 탐지)·반복 쓰기·ML
    종합이 보조 신호가 된다.
- **범위 한계**: GuardFS 는 ESXi VMFS 를 직접 보호하지 않는다. VM 파일 변경 특성을
  일반 Linux FUSE 에서 유사 연산으로 모사해 검증할 뿐이다.

---

## 4. 구현 중 발견한 설계상 편차·한계와 조치

### 개선 1 (적용) — 재현 대상 계열 확장자 즉시 탐지 누락
- **발견**: `guardfs/stage1/ext_change.py` 의 `SUSPICIOUS_EXTENSIONS` 에
  `.ifire`(IceFire)·`.akira`/`.akiranew`(Akira) 가 없어, 정작 본 프로젝트가
  재현하는 계열의 확장자 변경이 **즉시 탐지되지 않고** "정상→unknown" 5개 누적
  (`EXT_CHANGE_THRESHOLD`)에만 의존했다. 단일/소수 파일 변조는 놓친다.
- **조치**: 세 확장자를 집합에 추가(데이터만). 이 집합은 Stage1 즉시 탐지에만
  쓰이고 Stage2 ML 피처의 확장자 판정은 `guardfs/common/ext_rule.py` 가 전담하므로
  **학습 모델·피처 스키마에는 영향이 없다**. 회귀 테스트(`scripts/stage1/
  test_stage1_rules.py`) 89개 통과, 신규 2 케이스 추가.
- **영향 범위 검토**: `.ifire`/`.akira`/`.akiranew` 는 정상 파일이 가질 리 없는
  계열 특정 확장자라 오탐 위험이 사실상 없다. 기존 동작은 "정상→이 확장자"가
  5개 누적돼야 걸리던 것이 1개로 당겨질 뿐, 정상→정상 rename 은 영향 없음.

### 발견 2 (문서화만) — 신뢰 판정 두 경로의 불일치
- **내용**: 신뢰 판정이 두 곳에 있다.
  - `guardfs/stage1/trust.py :: is_trusted_pid` — 선제-MEDIUM 게이트
    (`_resolve_effective_state`)에서 사용. **exe 경로만** 본다. 따라서
    `/usr/bin/python3 evil.py` 는 exe 가 `/usr/bin/python3` 라 **신뢰**로 분류된다.
  - `guardfs/fuse_fs/passthrough.py :: _resolve_trust_target` (→ `is_trusted_process`)
    — SUSPICIOUS→실효상태 매핑·샘플링 게이트에서 사용. 인터프리터면 **스크립트
    인자 경로**로 판정해 `/usr/bin/python3 evil.py` 를 **비신뢰**로 본다.
  - 두 경로가 인터프리터 실행 스크립트에서 **상반된 결론**을 낼 수 있다.
- **영향**: DarkRadiation(②) 재현에서 "신뢰 여부"가 실행 방식에 따라 달라진다.
  신뢰 시연의 재현성을 위해 시뮬레이터에 `--engine openssl`(실제 `/usr/bin/openssl`
  이 쓰기 주체)을 두어, 두 경로 모두 신뢰로 수렴하는 구성을 제공했다.
- **왜 지금 고치지 않았나**: 수정하려면 두 판정 중 하나로 통일해야 하는데, 이는
  선제-MEDIUM 게이트와 ML 재평가 분기 전반에 영향을 준다. 본 환경에서는
  pyfuse3/trio 미설치로 실제 FUSE 회귀를 돌릴 수 없어, **충분히 검토·테스트하지
  못한 코어 정책 변경은 보류**한다(요청의 "기존 기능 영향 충분히 검토" 원칙).
  통일 방향(두 경로 모두 인터프리터는 스크립트 경로로 판정)을 후속 PR 후보로 제안.

### 발견 3 (문서화만, 기존 문서와 일치) — 읽기 기반 탈취 사각지대
- **내용**: Huntress Actor C 처럼 **쓰기 없이 읽기만** 하는 정보 탈취는
  Stage1 게이트(쓰기/엔트로피/삭제 기반)와 PID 피처(write/entropy/rename 중심)에
  신호를 거의 남기지 않아 LOW 에 머문다. HIGH 정책도 read 를 일부만 차단한다.
- **조치**: 새 탐지기를 FUSE 회귀 없이 추가하는 것은 오탐/회귀 위험이 커 보류하고,
  **허니팟 배치**(`--honeypot`)로 탐지 가능한 경로를 시연·문서화했다. 이는
  README/설계 문서가 이미 밝힌 한계("외부 전송 자체는 FUSE 로 확인 불가",
  "읽기 기록 ≠ 유출 탐지")와 일치한다. 민감 경로 연속 읽기 기반 탐지기는 오탐
  대조군(백업·인덱서)을 포함한 별도 설계·평가가 필요하므로 후속 과제로 남긴다.

### 환경 편차 (이 작업공간 한정)
- 구현 환경에 **pyfuse3·trio 미설치 + 네트워크 차단**이라 실제 FUSE 마운트·탐지·
  차단·대시보드 end-to-end 는 **검증하지 못했다**. 본 작업공간에서 검증한 것은:
  문법/`compileall`, FUSE-비의존 단위 테스트(`test_scenario_sims.py` 19개,
  `test_stage1_rules.py` 89개), 각 시뮬레이터의 준비→변조→정리 스모크 실행.
- 실제 탐지·차단·대시보드 표시의 실측은 **VM(Ubuntu + pyfuse3)** 에서 수행해야 한다.

---

## 5. 재현 결과 기록 기준 (원 설계 문서 7.3)

VM 에서 실측할 때 ① 실험 환경 ② 프로세스 정보(PID·경로·부모) ③ 파일 이벤트
(open/read/write/rename/unlink/truncate/create) ④ 파일 변화(크기·확장자·엔트로피)
⑤ 탐지 결과(Stage1·ML·최종 판단) ⑥ 정책 동작 ⑦ 한계·누락 을 기록한다.
**실측과 예상을 반드시 구분하고, 미실행 시나리오의 탐지 여부·점수를 실험 결과처럼
쓰지 않는다.**
