# Ubuntu 웹 시연 빠른 실행

프로젝트 코드를 준비한 뒤 Ubuntu 일반 사용자 터미널에서 실행한다.
저장소 브랜치 전환과 코드 업데이트는 별도로 진행한다.

## 최초 설치

```bash
cd ~/Capstone
bash scripts/setup_demo_web.sh
```

HoldFS용 Python 3.12 환경, FastAPI용 별도 Python 3.12 환경,
Node.js 24와 프런트 의존성을 준비하고 API import와 빌드를 확인한다.
기존 환경은 재사용한다. API requirements나 프런트 lockfile이 변경되면
`setup`을 다시 실행해 의존성을 반영한다. 최초 도입 시에는 의존성 확인을 위해
API 패키지 설치와 `npm ci`가 한 번 수행될 수 있다.

시스템 패키지 설치 중 sudo 비밀번호를 요청할 수 있다.
스크립트 전체를 `sudo bash`로 실행하지 않는다.
기존 API 가상환경이 Python 3.12 환경이 아니면 덮어쓰지 않고 중단한다.
nvm 설치 시 셸 프로필은 수정하지 않으며 실행기가 직접 nvm을 불러온다.

## 평소 실행

```bash
cd ~/Capstone
bash scripts/run_demo_web.sh
```

기존 `run_demo_web.sh`를 통해 HoldFS·대시보드, API, React를 순서대로 실행한다.
설치나 프런트 빌드는 반복하지 않는다. 설치 이후의 실행에는 인터넷이 필요하지 않다.
GNOME 데스크톱에서 실행하며, 기존 서비스나 포트가 사용 중이면 자동 종료하지 않는다.

- 웹: http://127.0.0.1:5173
- API 문서: http://127.0.0.1:8000/docs
- 대시보드: http://127.0.0.1:5000

종료할 때에는 실행 중인 시나리오를 먼저 완료·중단한 뒤
React → API → HoldFS/대시보드 터미널에서 각각 Ctrl+C를 누른다.

실행기 터미널만 닫으면 별도 창의 서비스는 계속 실행된다.
재실행 시 5173 포트 오류가 나면 아래 명령으로 실제 서버가 남았는지 확인한다.

```bash
ss -ltnp 'sport = :5173'
```

LISTEN 중인 서버가 있으면 해당 서비스 창에서 Ctrl+C로 종료한다.
포트 사전 검사는 종료 후 TIME_WAIT 연결을 고려해 재바인딩을 허용하며,
실제로 사용 중인 포트나 기존 프로세스는 자동으로 종료하지 않는다.

## 코드 반영 후 확인

```bash
cd ~/Capstone
bash scripts/setup_demo_web.sh check
```

의존성을 설치하지 않고 Python 환경, API 전체 import, TypeScript 검사와
프런트 빌드를 확인한다. 단위 테스트나 실제 시나리오는 자동 실행하지 않는다.

도움말: `bash scripts/setup_demo_web.sh --help`
