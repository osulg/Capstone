# S04 LOLBin 웹 실행

실제 작업은 `/usr/bin/python3 /usr/local/bin/holdfs_sim.py`로 수행한다.
백엔드 Python은 관리자와 등록 게이트에만 사용하며, 게이트가 같은 PID에서
시스템 Python으로 exec한 뒤 실제 파일 작업을 시작한다.

Ubuntu 코드 반영 후 관리자가 다음을 실행한다. 웹에서 sudo 설치를 하지 않는다.

```bash
cd ~/Capstone
sudo cp experiments/simulators/sim_highentropy.py /usr/local/bin/holdfs_sim.py
bash scripts/run_demo_web.sh
```

S04를 선택해 실행한다. 준비, mount·underlay 공개 확인, 공격, 양쪽 사후 관찰을
각각 등록된 PID에서 수행한다. 작업 폴더는 `s04_<실행 ID>`이며 더미 파일 20개,
파일당 64KB, 난수 쓰기 청크 16KB, 파일 간 대기 0.15초, 한 번의 순회다.
관리자 전체 제한은 150초이며 runner 외부 제한은 155초다.

공격 PID가 정지 상태이고 시작 tick이 일치하면 자기 자식만 SIGKILL로 회수하고
별도 프로세스로 파일 상태를 관찰한다. 사용자 중단은 기존 runner 그룹 정리를
사용한다. 파일과 GuardFS의 후속 작업은 임의로 삭제하거나 취소하지 않는다.

`worker_outcome.status`는 `completed`, `stopped_reaped`, `permission_denied`다.
공격의 읽기·덮어쓰기 또는 rename에서 EACCES/EPERM이 반환되면 원래 오류와
errno를 보존하고 사후 관찰로 진행한다. EIO 등 다른 오류와 준비·검증 작업의
접근 거부는 실행 실패로 유지한다. 접근 거부 자체는 ML 차단 성공을 뜻하지 않는다.
SIGSTOP만으로 GuardFS 또는 ML 차단이라고 확정하지 않는다.
동일 실행 범위의 HIGH BLOCKED 정책 기록을 찾으면 `policy_event`에 보존한다.
일치하는 기록이 없으면 null이다.

공격은 덮어쓴 파일을 실행마다 새로 정한 무작위 확장자(예: `.k3x9qa`)로 이름을
바꾼다. `.locked` 같은 알려진 랜섬웨어 확장자는 Stage1 사전 검사가 첫 rename에서
바로 거부해 공격이 첫 파일에서 끝나므로, 목록에 없는 확장자를 쓰는 변형으로
MEDIUM 재평가 동안의 행동까지 관찰한다. 확장자는 사전 차단·정상·실행 확장자
목록과 겹치지 않으며, 결과의 `rename_ext`와 각 작업 결과에 같은 값으로 남는다.

`task_results`의 inspect 작업은 각 파일의 원래 이름과 변경 확장자 이름을
matched, changed, missing으로 구분한다. 관찰 실패는 실행 실패로 보존한다.

화면의 관찰 완료는 ML 탐지 성공이나 원본 보존 성공을 뜻하지 않는다.
ML 판단은 해당 공격 PID의 `[TRIGGER HIGH]`와
`ml_score`, `dyn_only`, `watch_*`, `reeval_*` 사유를 별도로 대조한다.
이번 구현에서는 GuardFS 표준 출력의 ML 점수 이력을 자동 파싱하지 않는다.
정책·ML 임계값과 신뢰 목록은 변경하지 않는다.
