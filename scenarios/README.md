# HoldFS 시나리오

## 웹 연동 예정 구성

| 웹 ID | 시나리오 | 추가 예정 모듈 |
| --- | --- | --- |
| S01 | IceFire 랜섬웨어 | `scenarios.s01_icefire` |
| S02 | DarkRadiation 랜섬웨어 | `scenarios.s02_darkradiation` |
| S03 | Huntress | `scenarios.s03_huntress` |
| S04 | Akira | `scenarios.s04_akira` |

위 모듈은 아직 추가되지 않았다. 현재 catalog와 runner는 기존 S01 정상 작업을 사용한다.
새 모듈은 각 연동 단계에서 실제 구현하며, 구현·검증 전에는 웹 실행을 활성화하지 않는다.
실행 옵션·PID 구성·완료 조건은 [연동 명세](../docs/demo-web-scenario-integration.md)를 참고한다.

`experiments/simulators/`의 원본과 공통 하네스는 기존 CLI 및 테스트를 위해 유지하고 웹 모듈에서 재사용한다.
`common.py`, `workers.py`, `child_gate.py`는 공통 실행 제어 도구이며 관련 테스트도 유지한다.
기존 `s01_normal.py`와 테스트는 정상 파일 연산 회귀 검증용으로 보존한다. 아래 기존 명령은 새 S01 IceFire 실행 명령이 아니다.

## 기존 정상 파일 연산 회귀 검증

Run on Linux from the repository root after starting GuardFS:

```bash
python3 -m scenarios.s01_normal
```

If multiple GuardFS processes exist, specify the process serving this mount:

```bash
python3 -m scenarios.s01_normal --guardfs-pid <PID> \
  --mount "$HOME/guardfs_runtime/mount" \
  --underlay "$HOME/guardfs_runtime/underlay"
```

The scenario runs CREATE, WRITE, READ, MKDIR, RENAME, READ_AFTER_RENAME,
UNLINK and RMDIR in a unique `s01_<uuid>` directory. Writes and deletions
use only the mount. Every step checks underlay propagation and mount/process
health. A successful run removes its own directory; a failed run stops and
retains artifacts for inspection (no recursive cleanup).

Progress goes to stderr. The final JSON report goes to stdout:

```bash
python3 -m scenarios.s01_normal > /tmp/s01-result.json
```

Exit code: 0 for verified file operations, 1 for failure. The report includes
the test PID, GuardFS PID, run ID, per-step results and content SHA-256.
`passed` refers to file operations only: LOW state and absence of false
positives are **not yet verified** (`detection_verification: not_checked`).
No state overrides or detection thresholds are changed. The supplied underlay
must correspond to the mounted GuardFS instance; specify the correct PID when
auto-discovery is ambiguous. The caller should impose a process timeout when
integrating with the web runner, since an unresponsive FUSE call can block.
