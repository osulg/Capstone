"""표준입력 각 줄 앞에 받은 순간의 시각("YYYY-MM-DD HH:MM:SS.mmm ")을 붙여 표준출력으로 내보낸다.

run_all.sh 가 HoldFS 실행 출력을 로그 파일에 쓸 때 쓴다. 에이전트가 이 시각을 이벤트 시각으로 쓰므로,
filesecurity.log(HoldFS 가 직접 밀리초 시각을 적음)와 같은 기준으로 정렬된다.

bash 의 'while read' 반복문은 파이프를 한 바이트씩 읽어, HoldFS 가 짧은 시간에 줄을 많이 찍으면
시각이 실제보다 밀려 찍혔다(예: HIGH 격상이 그 뒤의 '보류 쓰기 폐기'보다 늦게 찍힘). 그래서 파이썬으로
줄 단위로 읽어 바로 시각을 붙인다.
"""

import sys
import time


def main() -> None:
    out = sys.stdout.buffer
    for raw in sys.stdin.buffer:            # 줄이 들어오는 즉시 돌려준다 (파이프는 쌓인 만큼 읽음)
        t = time.time()
        stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(t)) + f".{int(t * 1000) % 1000:03d} "
        if not raw.endswith(b"\n"):
            raw += b"\n"
        out.write(stamp.encode() + raw)
        out.flush()


if __name__ == "__main__":
    try:
        main()
    except (KeyboardInterrupt, BrokenPipeError):
        pass
