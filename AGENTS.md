# AGENTS.md

## 프로젝트 개요

GuardFS는 FUSE 기반 랜섬웨어 탐지 및 보호 시스템이다.

주요 구성은 다음과 같다.

- Python
- pyfuse3
- trio
- Stage 1 경량 탐지
- Stage 2 ML 기반 탐지
- LOW / SUSPICIOUS / MEDIUM / HIGH 프로세스 상태

GuardFS는 underlay 디렉터리를 FUSE mountpoint를 통해 노출한다.

일반적인 런타임 경로:

- mount: `~/guardfs_runtime/mount`
- underlay: `~/guardfs_runtime/underlay`

GuardFS 정책이 명시적으로 차단하거나 staging 처리하지 않는 한,
mount 디렉터리에서 수행한 정상 파일 연산은 underlay에 올바르게 반영되어야 한다.


## 현재 프로젝트 구조

중요한 디렉터리와 파일:

```text
guardfs/
├── common/
│   ├── config.py
│   └── paths.py
│
├── fuse_fs/
│   └── passthrough.py
│
├── stage1/
│   ├── detector.py
│   ├── entropy.py
│   ├── ext_change.py
│   ├── honeypot.py
│   └── logger.py
│
├── stage2/
│   ├── stage2_worker.py
│   ├── states.py
│   └── policy/
│       ├── low.py
│       ├── medium.py
│       └── high.py
│
└── main.py
```

핵심 FUSE 구현 파일:

```text
guardfs/fuse_fs/passthrough.py
```


## 공통 설정 관리 규칙

`passthrough.py`에 GuardFS 설정값을 새로 하드코딩하지 않는다.

공통 설정값은 다음 파일을 사용한다.

```text
guardfs/common/config.py
```

예:

- entropy 임계값
- entropy 검사 크기
- Stage 1 통계 임계값
- 확장자 변경 탐지 임계값
- Stage 2 ML 임계값
- Stage 2 모델 가중치
- MEDIUM 재평가 시간
- MEDIUM 정책 임계값

공통 경로는 다음 파일을 사용한다.

```text
guardfs/common/paths.py
```

예:

- 모델 경로
- staging 디렉터리
- GuardFS 이벤트 로그 경로
- 강제 상태 파일 경로
- honeypot 디렉터리

동일한 값을 `passthrough.py`에 다시 작성하지 않는다.

잘못된 예:

```python
ent = shannon_entropy(buf[:256])
```

권장:

```python
ent = shannon_entropy(buf[:ENTROPY_HEADER_SIZE])
```

잘못된 예:

```python
staging_dir = "/tmp/guardfs_staging"
```

권장:

```python
staging_dir = STAGING_DIR
```


## 프로세스 상태 관리 규칙

프로세스 상태 정의는 다음 파일을 기준으로 한다.

```text
guardfs/stage2/states.py
```

정의된 상태:

```python
ProcState.LOW
ProcState.SUSPICIOUS
ProcState.MEDIUM
ProcState.HIGH
```

다른 파일에서 `ProcState`를 새로 정의하지 않는다.

현재 PID 상태 관리 로직은 `Passthrough` 내부에 유지한다.

작업 요청에 명시되지 않는 한
새로운 state manager를 만들거나 상태 관리 구조를 이동하지 않는다.


## passthrough.py의 역할

`passthrough.py`는 GuardFS의 FUSE 연산 계층이다.

주요 역할:

1. FUSE inode 요청을 실제 underlay 경로로 변환
2. inode/path 매핑 관리
3. file handle 관리
4. 파일 시스템 연산 구현
5. 파일 시스템 이벤트 전달
6. PID 상태 추적
7. suspicious PID를 Stage 2로 전달
8. LOW / MEDIUM / HIGH 정책 분기
9. 제한 상태에서 staging 파일 관리

중요한 FUSE 연산:

```text
lookup
create
mkdir
rmdir
opendir
readdir
open
read
write
truncate
ftruncate
unlink
rename
release
```


## FUSE 수정 시 가장 중요한 규칙

하나의 FUSE 연산 수정은 이후 연산에도 영향을 줄 수 있다.

예:

```text
create
  ↓
write
  ↓
rename
  ↓
read
  ↓
unlink
```

전체 흐름이 일관되게 동작해야 한다.

`rename`, `unlink`, inode mapping, file handle mapping을 수정할 때
예외가 발생한 한 줄만 고치지 말고 전체 파일 생명주기를 추적한다.


## 내부 매핑 구조

`self._inode_path`

```text
inode -> 실제 underlay 경로
```

`self._fd_map`

```text
FUSE file handle -> OS file descriptor
```

`self._fh_info`

```text
file handle -> (pid, path, flags)
```

`self._dir_fh_path`

```text
directory file handle -> 디렉터리 경로
```

파일 경로가 바뀌는 연산에서는
이 내부 매핑들도 함께 갱신되어야 하는지 반드시 확인한다.

`os.rename()` 호출이 성공했다고 해서
GuardFS 내부 상태까지 자동으로 정상화된다고 가정하지 않는다.


## rename 문제 분석 규칙

`rename` 문제를 수정할 때 다음 항목을 확인한다.

1. `oldp`
2. `newp`
3. `self._inode_path`
4. `self._fh_info`
5. 이미 열린 file handle
6. rename 이후 `lookup`
7. rename 이후 `getattr`
8. rename 이후 `read`
9. rename 이후 `unlink`

`os.rename(oldp, newp)` 호출 성공만으로
rename 구현이 올바르다고 판단하지 않는다.

내부 path / inode / file handle 상태까지 분석한 뒤 수정한다.


## unlink 문제 분석 규칙

`unlink` 문제를 수정할 때 다음 항목을 확인한다.

1. FUSE 요청 경로가 올바르게 해석되는지
2. 실제 underlay 경로에 파일이 존재하는지
3. rename 또는 삭제 이후 오래된 inode mapping이 남아 있지 않은지
4. 열린 file handle이 올바르게 처리되는지
5. unlink 이후 GuardFS 프로세스가 계속 살아있는지

다음 메시지가 나타난 경우:

```text
Transport endpoint is not connected
```

이 메시지 자체를 근본 원인으로 판단하지 않는다.

먼저 GuardFS 실행 터미널의 traceback을 확인한다.

이 메시지는 FUSE userspace 프로세스가 먼저 종료된 이후
클라이언트 측에서 후속으로 나타날 수 있다.


## FUSE 예외 처리 규칙

예상 가능한 OS 오류는 가능하면 다음 형태로 변환한다.

```python
raise pyfuse3.FUSEError(e.errno)
```

예상하지 못한 예외를 조용히 무시하지 않는다.

다음과 같은 광범위한 예외 처리는 가급적 피한다.

```python
except Exception:
    pass
```

의도적으로 필요한 경우에만 사용하고 이유를 명확히 한다.


## Stage 1 이벤트 매핑

`PidStats`는 파일 시스템 이벤트를 ML feature용 코드로 변환한다.

현재 의미:

```text
C = create / mkdir
D = unlink / rmdir
E = high-entropy write
O = 기타 파일 접근
```

이 매핑을 임의로 변경하지 않는다.

Stage 2 ML feature schema와 연결되어 있으므로
변경 시 모델 호환성에 영향을 줄 수 있다.


## 현재 알려진 논리적 주의사항

rename 통계 처리에는 의미상 불일치 가능성이 있다.

현재 `rename`은 `O`로 매핑되지만,
일부 통계 로직에서는 rename 관련 임계값 판단 시
`D_sum`을 사용할 수 있다.

이 문제를 unrelated FUSE 수정에 섞어서 조용히 변경하지 않는다.

수정이 필요하다면:

1. 의도한 feature 의미 확인
2. ML 학습 feature와의 호환성 확인
3. 별도의 명시적인 수정으로 처리


## Stage 2 상태 흐름

Stage 1에서 suspicious로 판단된 PID는 Stage 2로 전달된다.

기본 흐름:

```text
LOW
 ↓
SUSPICIOUS
 ↓
Stage 2 평가
 ├── LOW
 ├── MEDIUM
 └── HIGH
```

FUSE 연산 내부에서 임의로 상태 전이를 추가해
Stage 2 판단 구조를 우회하지 않는다.

강제 상태 파일은 테스트 목적의 제어 기능으로 취급한다.


## LOW 정책

LOW 상태에서는 정상 파일 시스템처럼 동작해야 한다.

```text
mount 연산
    ↓
passthrough.py
    ↓
underlay 파일 시스템
```

정상적인 LOW 연산 때문에 FUSE 연결이 끊어져서는 안 된다.


## MEDIUM 정책

MEDIUM에서는 staging 또는 지연 쓰기가 사용될 수 있다.

MEDIUM 전용 staging 처리가
LOW 상태의 inode / file handle 동작을 망가뜨리지 않도록 주의한다.


## HIGH 정책

HIGH는 차단 상태다.

정상 FUSE 동작 문제를 수정하는 과정에서
HIGH 상태의 보호 기능을 약화시키지 않는다.


## passthrough.py 버그 수정 범위

`passthrough.py`를 수정할 때 다음 원칙을 따른다.

- 가장 작은 범위의 올바른 수정 우선
- 문제와 관련 없는 탐지 로직은 유지
- 불필요한 프로젝트 전체 리팩터링 금지
- 명시되지 않은 파일 이동 금지
- 공개 함수명 임의 변경 금지
- FUSE 버그 수정 중 ML threshold 변경 금지
- 학습 모델 파일 수정 금지
- dataset 수정 금지
- 불필요한 신규 dependency 추가 금지
- pyfuse3 또는 trio 교체 금지


## 수정 전에 확인할 파일

`passthrough.py`를 수정하기 전에 다음 파일을 확인한다.

```text
guardfs/fuse_fs/passthrough.py
guardfs/common/config.py
guardfs/common/paths.py
guardfs/stage2/states.py
guardfs/stage2/stage2_worker.py
guardfs/stage2/policy/low.py
guardfs/stage2/policy/medium.py
guardfs/stage2/policy/high.py
```

문제가 Stage 1 탐지와 관련된 경우 다음도 확인한다.

```text
guardfs/stage1/detector.py
guardfs/stage1/entropy.py
guardfs/stage1/ext_change.py
guardfs/stage1/honeypot.py
```


## 필수 디버깅 순서

FUSE 문제를 수정할 때 첫 번째로 의심되는 코드부터 바로 수정하지 않는다.

다음 순서를 따른다.

1. 어떤 FUSE 연산에서 실패했는지 확인
2. 마지막으로 정상 수행된 연산 확인
3. GuardFS traceback 확인
4. path / inode / file handle 상태 추적
5. 실제 근본 원인 판단
6. 최소 수정안 작성
7. 수정 적용
8. 회귀 테스트 수행


## 기본 회귀 테스트

`passthrough.py` 수정 후 최소한 다음 테스트를 수행한다.

```bash
MOUNT=~/guardfs_runtime/mount
UNDERLAY=~/guardfs_runtime/underlay

echo "hello guardfs" > "$MOUNT/test.txt"

cat "$MOUNT/test.txt"
cat "$UNDERLAY/test.txt"

mkdir "$MOUNT/test_dir"

mv \
    "$MOUNT/test.txt" \
    "$MOUNT/test_renamed.txt"

cat "$MOUNT/test_renamed.txt"
cat "$UNDERLAY/test_renamed.txt"

rm "$MOUNT/test_renamed.txt"

rmdir "$MOUNT/test_dir"
```

중요한 연산마다 mount와 underlay 양쪽 상태를 확인한다.


## 반드시 테스트할 연산

최소 테스트 항목:

```text
CREATE
WRITE
READ
MKDIR
RENAME
READ AFTER RENAME
UNLINK
RMDIR
```

각 연산 이후 GuardFS FUSE 프로세스가 계속 실행 중인지 확인한다.


## 정적 검사

수정을 완료하기 전에 다음 검사를 수행한다.

```bash
python -m compileall guardfs
git diff --check
```

이 검사는 필수지만,
실제 FUSE 동작 테스트를 대신할 수는 없다.


## 실제 실행 환경

실제 FUSE 동작은 pyfuse3를 사용할 수 있는 Linux/Ubuntu 환경에서 테스트한다.

일반적인 실행:

```bash
./scripts/run_guardfs.sh
```

첫 번째 터미널에서는 GuardFS를 계속 실행한다.

두 번째 터미널에서 mount 경로를 대상으로 파일 연산 테스트를 수행한다.


## 완료 조건

`passthrough.py` 수정은 다음 조건을 만족해야 완료로 본다.

1. 근본 원인이 확인됨
2. 변경 범위가 최소이며 설명 가능함
3. Python compilation 성공
4. `git diff --check` 성공
5. GuardFS mount 성공
6. 정상 LOW 연산 성공
7. rename 이후 read 정상
8. unlink 이후 FUSE 프로세스가 종료되지 않음
9. mount와 underlay 상태 일치
10. unrelated 탐지 / ML 동작을 변경하지 않음


## Git / PR 규칙

프로젝트 구조 및 설정 리팩터링과
FUSE 기능 버그 수정은 별도의 관심사로 취급한다.

passthrough 연산 수정 브랜치:

```text
fix/passthrough-ops
```

권장 커밋 예시:

```text
fix: passthrough 파일 연산 오류 수정
```

기능 버그 수정 커밋에 unrelated cleanup을 함께 넣지 않는다.


## Codex 응답 및 작업 방식

버그 작업 시 다음 순서로 정리한다.

1. 추정되는 근본 원인 설명
2. 관련 함수 이름 제시
3. 어떤 부분을 수정할지 설명
4. 최소한의 패치 적용
5. 중요한 diff 설명
6. 가능한 검사 실행
7. 실제 테스트 결과 보고
8. 테스트하지 못한 항목은 명확히 표시

Python 코드가 컴파일된다는 이유만으로
FUSE 버그가 해결되었다고 판단하지 않는다.
