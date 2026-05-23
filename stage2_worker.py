# stage2_worker.py
import os
import trio
from states import ProcState

# medium에서 직접 import 말고 함수 안에서 import
MEDIUM_THRESHOLD = 0.3
HIGH_THRESHOLD   = 0.7
REEVAL_S         = 1.0

async def stage2_worker(recv_chan, ops) -> None:
    medium_pids = {}
    risk_scores = {}
    next_reeval = trio.current_time() + REEVAL_S

    async with recv_chan:
        while True:
            timeout = max(0.0, next_reeval - trio.current_time())

            with trio.move_on_after(timeout) as scope:
                try:
                    item = await recv_chan.receive()
                except trio.EndOfChannel:
                    return

            if not scope.cancelled_caught:
                # 새 이벤트 처리
                pid = item["pid"]
                score = 0.5
                risk_scores[pid] = score
                print(f"[STAGE2] pid={pid} score={score:.3f} (고정)")

                if score >= MEDIUM_THRESHOLD:
                    await ops.set_proc_state(pid, ProcState.MEDIUM)
                    medium_pids[pid] = trio.current_time()
                    print(f"[STAGE2] pid={pid} → MEDIUM 진입")

            # ← continue 제거! 항상 재평가 실행
            # 1초마다 Medium PID 재평가
            if medium_pids:
                sorted_pids = sorted(
                    medium_pids,
                    key=lambda p: risk_scores.get(p, 0.0),
                    reverse=True,
                )

                for pid in list(sorted_pids):
                    score = risk_scores.get(pid, 0.0)
                    elapsed = trio.current_time() - medium_pids[pid]
                    print(f"[REEVAL] pid={pid} score={score:.3f} elapsed={elapsed:.1f}s")

                    if elapsed > 10.0:
                        print(f"[REEVAL] pid={pid} 10초 경과 → Low 복귀")
                        await ops.set_proc_state(pid, ProcState.LOW)
                        from medium import commit_buffers
                        await commit_buffers(pid, ops)
                        medium_pids.pop(pid, None)
                        continue

                    from medium import validate_medium_buffers, drop_buffers
                    need_high = await validate_medium_buffers(pid, ops)
                    if need_high:
                        print(f"[REEVAL] pid={pid} 구조 깨짐 → 버퍼 드롭")
                        await drop_buffers(pid, ops)
                        medium_pids.pop(pid, None)

            next_reeval += REEVAL_S