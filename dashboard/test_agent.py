"""agent.py StdoutParser 단위 테스트: python3 -m pytest dashboard/test_agent.py

입력 줄은 GuardFS(guardfs/fuse_fs/passthrough.py, guardfs/stage2/stage2_worker.py)가
실제로 출력하는 형식 그대로다.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from agent import StdoutParser  # noqa: E402


def feed_all(lines):
    p = StdoutParser()
    return [ev for ev in (p.feed(line) for line in lines) if ev]


def test_untrusted_preemptive_medium_and_return():
    evs = feed_all([
        "[STATE] pid=4896 ProcState.LOW → ProcState.MEDIUM",
        "[REEVAL] pid=4896 dyn=0.000 stat=0.080 score=0.040 elapsed=10.6s",
        "[STATE] pid=4896 ProcState.MEDIUM → ProcState.LOW",
        "[REEVAL] pid=4896 관찰 시간 종료 → LOW 복귀",
    ])
    assert [(e["level"], e["action"]) for e in evs] == [("MEDIUM", "ESCALATE"), ("LOW", "RETURN")]
    assert "untrusted_origin" in evs[0]["reason"]
    assert "score=0.040" in evs[1]["reason"]


def test_stage2_medium_is_not_reported_twice():
    evs = feed_all([
        "[STATE] pid=11241 LOW -> SUSPICIOUS reason=EntropyDetector",
        "[STAGE2] pid=11241 dyn=0.450 stat=0.295 final=0.372",
        "[STATE] pid=11241 ProcState.SUSPICIOUS → ProcState.MEDIUM",
        "[STAGE2] pid=11241 → MEDIUM (score=0.372)",
        "[REEVAL] pid=11241 관찰 시간 종료 → LOW 복귀",
    ])
    assert [(e["level"], e["action"]) for e in evs] == [("MEDIUM", "ESCALATE"), ("LOW", "RETURN")]
    assert "stage1=EntropyDetector" in evs[0]["reason"]
    assert "dyn=0.450" in evs[0]["reason"]


def test_high_and_suspend():
    evs = feed_all([
        "[STATE] pid=10594 LOW -> SUSPICIOUS reason=EntropyDetector",
        "[WATCH] pid=10594 dyn=0.215 stat=0.295 score=0.255 elapsed=0.3s",
        "[TRIGGER HIGH] pid=10594 reason=magic_mismatch",
        "[HIGH] pid=10594 suspend 완료",
    ])
    assert [(e["level"], e["result"]) for e in evs] == [("HIGH", "HIGH"), ("HIGH", "SUSPENDED")]
    assert evs[0]["reason"].startswith("magic_mismatch")


def test_low_return_without_escalation_is_hidden():
    evs = feed_all([
        "[STATE] pid=6586 LOW -> SUSPICIOUS reason=EntropyDetector",
        "[WATCH] pid=6586 관찰 종료 → 현재 상태=ProcState.LOW (score=0.016)",
    ])
    assert evs == []


def test_line_time_prefix_is_used_as_event_time():
    # run_all.sh 가 실행 출력 각 줄 앞에 붙이는 출력 시각을 이벤트 시각으로 쓴다
    evs = feed_all([
        "2026-11-07 18:04:27 [TRIGGER HIGH] pid=4242 reason=high_entropy_write(ext=PLAIN_TEXT)",
        "2026-11-07 18:04:27 [HIGH] pid=4242 suspend 완료",
    ])
    assert [(e["time"], e["result"]) for e in evs] == [
        ("2026-11-07 18:04:27", "HIGH"), ("2026-11-07 18:04:27", "SUSPENDED")]
    assert evs[0]["reason"].startswith("high_entropy_write")


def test_line_without_time_prefix_uses_read_time():
    # 시각이 안 붙은 로그(직접 실행한 HoldFS 출력)도 예전처럼 읽는다
    evs = feed_all(["[TRIGGER HIGH] pid=4243 reason=ml_score=0.900"])
    assert len(evs) == 1 and len(evs[0]["time"]) == 19


def test_sampling_then_untrusted_medium_is_reported():
    # stage1_sampling 으로 먼저 SUSPICIOUS 가 된 비신뢰 프로세스가 신뢰 검사에서 MEDIUM 이 된 경우
    evs = feed_all([
        "[STATE] pid=5310 LOW -> SUSPICIOUS reason=stage1_sampling",
        "[STATE] pid=5310 ProcState.SUSPICIOUS → ProcState.MEDIUM",
        "[TRIGGER HIGH] pid=5310 reason=high_entropy_write(ext=PLAIN_TEXT)",
    ])
    assert [(e["level"], e["action"]) for e in evs] == [("MEDIUM", "ESCALATE"), ("HIGH", "ESCALATE")]
    assert evs[0]["reason"].startswith("untrusted_origin")
    assert "stage1=stage1_sampling" in evs[0]["reason"]


def test_untrusted_medium_then_stage2_medium_is_not_reported_twice():
    evs = feed_all([
        "[STATE] pid=5320 LOW -> SUSPICIOUS reason=stage1_sampling",
        "[STATE] pid=5320 ProcState.SUSPICIOUS → ProcState.MEDIUM",
        "[STAGE2] pid=5320 dyn=0.450 stat=0.295 final=0.372",
        "[STATE] pid=5320 ProcState.MEDIUM → ProcState.MEDIUM",
        "[STAGE2] pid=5320 → MEDIUM (score=0.372)",
    ])
    assert [(e["level"], e["action"]) for e in evs] == [("MEDIUM", "ESCALATE")]


def test_other_pid_line_between_score_and_state_does_not_confuse():
    # 다른 PID 의 줄이 끼어들어도 같은 PID 기준으로 '바로 앞 줄'을 본다
    evs = feed_all([
        "[STATE] pid=5330 LOW -> SUSPICIOUS reason=EntropyDetector",
        "[STAGE2] pid=5330 dyn=0.450 stat=0.295 final=0.372",
        "[MEDIUM] pid=9999 path=/x truncate size=0 → 지연 작업 보관",
        "[STATE] pid=5330 ProcState.SUSPICIOUS → ProcState.MEDIUM",
        "[STAGE2] pid=5330 → MEDIUM (score=0.372)",
    ])
    assert [(e["level"], e["action"]) for e in evs] == [("MEDIUM", "ESCALATE")]
    assert "Stage2 최초 평가" in evs[0]["reason"]
