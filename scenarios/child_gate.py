"""부모의 시작 신호를 받은 뒤 실제 작업 프로그램으로 전환한다."""

import os
import sys


def main() -> int:
    # "--" 뒤에 실제 실행할 프로그램과 인자를 전달한다.
    if len(sys.argv) < 3 or sys.argv[1] != "--":
        print(
            "사용법: python -m scenarios.child_gate -- PROGRAM [ARGS...]",
            file=sys.stderr,
        )
        return 2

    # 이 stdin은 부모와의 시작 제어에만 사용한다.
    # 부모가 통로를 닫으면 EOF가 되어 작업을 시작하지 않는다.
    signal = sys.stdin.buffer.readline(16)

    if signal != b"START\n":
        print("시작 신호가 없어 작업을 중단합니다.", file=sys.stderr)
        return 1

    command = sys.argv[2:]

    # 제어용 stdin을 실제 작업 프로그램에 넘기지 않는다.
    with open(os.devnull, "rb") as reader:
        os.dup2(reader.fileno(), 0)

    # 새 프로세스를 추가 생성하지 않고 현재 프로세스를 교체한다.
    # 따라서 등록한 PID와 실제 작업 프로그램의 PID가 동일하다.
    os.execvpe(command[0], command, os.environ.copy())

    return 1  # exec 성공 시 이 줄에는 도달하지 않는다.


if __name__ == "__main__":
    raise SystemExit(main())
