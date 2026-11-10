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


def test_medium_entry_from_policy_record():
    # stage1_sampling 으로 SUSPICIOUS 가 된 비신뢰 프로세스: 실행 출력에는 MEDIUM 진입 줄이 없고
    # filesecurity.log 의 MEDIUM 정책 기록(폴더 생성 등)만 남는다
    p = StdoutParser()
    assert p.feed("2026-11-07 18:22:35 [STATE] pid=6100 LOW -> SUSPICIOUS reason=stage1_sampling") is None
    sec = {"time": "2026-11-07 18:22:35", "pid": 6100, "level": "MEDIUM", "action": "MKDIR", "result": "ALLOWED"}
    ev = p.medium_entry(sec)
    assert ev and (ev["level"], ev["action"], ev["time"]) == ("MEDIUM", "ESCALATE", "2026-11-07 18:22:35")
    assert "stage1=stage1_sampling" in ev["reason"]
    assert p.medium_entry(dict(sec, result="BUFFERED")) is None   # 두 번 보내지 않음


def test_medium_entry_skipped_after_stage2_medium_or_for_commit():
    p = StdoutParser()
    p.feed("[STATE] pid=6200 LOW -> SUSPICIOUS reason=EntropyDetector")
    p.feed("[STAGE2] pid=6200 dyn=0.450 stat=0.295 final=0.372")
    p.feed("[STATE] pid=6200 ProcState.SUSPICIOUS → ProcState.MEDIUM")
    assert p.feed("[STAGE2] pid=6200 → MEDIUM (score=0.372)")["level"] == "MEDIUM"
    assert p.medium_entry({"pid": 6200, "level": "MEDIUM", "result": "BUFFERED"}) is None
    # 판정 뒤에 남는 반영 기록으로는 MEDIUM 격상을 만들지 않는다
    q = StdoutParser()
    assert q.medium_entry({"pid": 6300, "level": "MEDIUM", "action": "COMMIT", "result": "FILE_APPLIED"}) is None


def test_medium_entry_even_if_high_was_read_first():
    # 같은 초에 HIGH 격상까지 끝나 실행 출력을 먼저 읽은 경우에도 MEDIUM 진입을 남긴다
    p = StdoutParser()
    p.feed("[STATE] pid=6400 LOW -> SUSPICIOUS reason=stage1_sampling")
    p.feed("[TRIGGER HIGH] pid=6400 reason=high_entropy_write(ext=PLAIN_TEXT)")
    ev = p.medium_entry({"time": "2026-11-07 18:22:35", "pid": 6400, "level": "MEDIUM",
                         "action": "MKDIR", "result": "ALLOWED"})
    assert ev and ev["level"] == "MEDIUM"
    assert p.level[6400] == "HIGH"
    assert p.medium_entry({"pid": 6400, "level": "MEDIUM", "result": "ESCALATED_TO_HIGH"}) is None


def test_process_name_uses_thread_group_leader():
    # FUSE 가 넘겨주는 스레드 번호를 넣어도, 스레드 이름('pool')이 아니라 프로세스 이름이 나온다
    import threading
    from agent import _read_comm, process_name

    ready, done, out = threading.Event(), threading.Event(), {}

    def worker():
        tid = threading.get_native_id()
        with open(f"/proc/self/task/{tid}/comm", "w") as f:
            f.write("pool")
        out["tid"] = tid
        ready.set()
        done.wait(2)

    t = threading.Thread(target=worker)
    t.start()
    ready.wait(2)
    try:
        assert _read_comm(out["tid"]) == "pool"
        assert process_name(out["tid"]) == _read_comm(os.getpid())
    finally:
        done.set()
        t.join()
    assert process_name(999999999) == "-"


def test_line_time_with_milliseconds():
    evs = feed_all(["2026-11-08 12:04:45.212 [TRIGGER HIGH] pid=4250 reason=ml_score=0.900"])
    assert evs[0]["time"] == "2026-11-08 12:04:45.212"


def test_lineage_burst_detect_and_parent_stop():
    # 신뢰 도구 반복 실행(lineage) → 부모 PID 탐지 → HIGH → 부모 정지
    evs = feed_all([
        "[STATE] pid=7000 LOW -> SUSPICIOUS reason=lineage_burst",
        "[TRIGGER HIGH] pid=7000 reason=reeval_dyn_only=0.712",
        "[HIGH] pid=7000 진입 정리 완료 (reason=reeval_dyn_only=0.712)",
        "[LINEAGE] pid=7000 lineage 격상 → 부모 프로세스 정지",
        "[HIGH] pid=7000 suspend 완료",
    ])
    assert [(e["action"], e["result"]) for e in evs] == [
        ("DETECT", "SUSPICIOUS"), ("ESCALATE", "HIGH"), ("SIGSTOP", "SUSPENDED")]   # 정지는 한 번만
    assert evs[0]["reason"].startswith("lineage_burst")
    assert "stage1=lineage_burst" in evs[1]["reason"]


def test_lineage_session_leader_stop_skipped():
    evs = feed_all([
        "[TRIGGER HIGH] pid=7100 reason=reeval_dyn_only=0.700",
        "[LINEAGE] pid=7100 세션 리더 → SIGSTOP 보류(로그만). 자식 신규 write는 차단됨.",
    ])
    assert [(e["action"], e["result"]) for e in evs] == [("ESCALATE", "HIGH"), ("SIGSTOP", "SKIPPED")]


def test_precheck_rename_block_is_reported():
    # 알려진 랜섬웨어 확장자(.akiranew)로 이름 변경 → Stage1 사전 차단
    evs = feed_all([
        "[STATE] pid=8000 ProcState.LOW → ProcState.MEDIUM",
        "[PRECHECK] pid=8000 op=rename path=/u/sim_akira/a/vm_000.vmdk "
        "new_path=/u/sim_akira/a/vm_000.vmdk.akiranew reason=ExtChangeDetector blocked",
    ])
    assert [(e["level"], e["action"], e["result"]) for e in evs] == [
        ("MEDIUM", "ESCALATE", "MEDIUM"), ("MEDIUM", "RENAME", "BLOCKED")]
    assert evs[1]["target"] == "/u/sim_akira/a/vm_000.vmdk → /u/sim_akira/a/vm_000.vmdk.akiranew"
    assert evs[1]["reason"].startswith("ExtChangeDetector")


def test_precheck_without_medium_is_detect_level():
    evs = feed_all([
        "[PRECHECK] pid=8100 op=rename path=/u/x.doc new_path=/u/x.doc.lockbit reason=ExtChangeDetector blocked",
    ])
    assert [(e["level"], e["result"]) for e in evs] == [("SUSPICIOUS", "BLOCKED")]
