# stage2_worker.py
import json
import os
import warnings
from typing import Tuple

import joblib
import pandas as pd
import trio

from guardfs.common.config import (
    DYNAMIC_MODEL_WEIGHT,
    STAGE2_DYN_ONLY_HIGH_THRESHOLD,
    STAGE2_HIGH_THRESHOLD,
    STAGE2_MEDIUM_THRESHOLD,
    STAGE2_MEDIUM_TIMEOUT_SEC,
    STAGE2_REEVAL_INTERVAL_SEC,
    STAGE2_WATCH_TIMEOUT_SEC,
    STATIC_MODEL_WEIGHT,
)
from guardfs.common.paths import (
    DYNAMIC_FEATURE_COLS_PATH,
    DYNAMIC_MODEL_PATH,
    STATIC_MODEL_PATH,
    STATIC_VOCAB_PATH,
)
from guardfs.stage2.states import ProcState
from guardfs.stage2.static_analyzer import StaticAnalyzer

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

# NOTE: 동적 피처 순서의 단일 출처는 models/dynamic/feature_cols_v5.json 이다
#       (FUSE-only · PID 단위, 22개). 런타임 PidStats.to_feature_row() 와
#       학습 추출기(extract_perpid_fuse.py)가 같은 스키마를 공유한다.


def load_models():
    """
    동적/정적 모델과 동적 피처 목록을 로드한다.

    반환: (dyn_model, dyn_cols, stat_model)
    """
    try:
        dyn = joblib.load(DYNAMIC_MODEL_PATH)

        with open(DYNAMIC_FEATURE_COLS_PATH, encoding="utf-8") as f:
            dyn_cols = json.load(f)

        # 모델이 학습된 피처 순서와 json 목록이 어긋나면 점수가
        # 조용히 엉터리로 나오므로, 기동 자체를 실패시킨다.
        expected = list(getattr(dyn, "feature_names_in_", []))
        if expected and expected != dyn_cols:
            raise RuntimeError(
                f"동적 모델 피처 불일치: "
                f"model={len(expected)}개 / json={len(dyn_cols)}개"
            )

        print(f"[ML] 동적 모델 로드 완료 (v5, FUSE·PID, {len(dyn_cols)} features)")
    except Exception as e:
        print(f"[ML] 동적 모델 로드 실패: {e}\n")
        dyn, dyn_cols = None, []

    try:
        stat = StaticAnalyzer(STATIC_VOCAB_PATH, STATIC_MODEL_PATH)
        print(f"[ML] 정적 모델 로드 완료 (byte 3-gram k={stat.k})\n")
    except Exception as e:
        print(f"[ML] 정적 모델 로드 실패: {e}\n")
        stat = None

    # 정적 분석기는 내부에서 예외를 삼키고 None(→0.5 sentinel)을 반환하므로,
    # sklearn 버전 불일치 등으로 죽어 있어도 로그에 아무것도 남지 않는다.
    # 기동 시 자기 자신(python3)을 한 번 채점해 파이프라인 생존을 확인한다.
    if stat is not None:
        probe = stat.predict_pid(os.getpid())
        if probe is None:
            print(
                "[ML] 경고: 정적 모델 sanity check 실패 — "
                "모든 정적 점수가 0.5(판단 불가)로 처리됩니다. "
                "sklearn 버전을 requirements.txt(1.3.2)와 맞추세요."
            )
        else:
            print(f"[ML] 정적 모델 sanity check OK (self={probe:.3f})")

    return dyn, dyn_cols, stat


def get_exe_path(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""


def predict_dynamic(model, cols, features: dict) -> float:
    if model is None:
        return 0.5
    try:
        # 피처 생성기(PidStats)의 스키마가 모델과 어긋나면 결측이
        # 전부 0으로 채워져 예외 없이 잘못된 점수가 나온다.
        missing = [c for c in cols if c not in features]
        if len(missing) > len(cols) // 2:
            print(
                f"[ML] 경고: 동적 피처 {len(missing)}/{len(cols)}개 결측 "
                f"(예: {missing[:5]}) — 피처 생성기 스키마 확인 필요"
            )

        row = {c: features.get(c, 0) for c in cols}
        df = pd.DataFrame([row], columns=cols)
        prob = model.predict_proba(df)[0]
        # 악성(1) 클래스 확률 반환
        classes = list(model.classes_)
        mal_idx = classes.index(1) if 1 in classes else -1
        return float(prob[mal_idx]) if mal_idx >= 0 else float(prob[-1])
    except Exception as e:
        print(f"[ML] 동적 예측 오류: {e}")
        return 0.5


def predict_static(analyzer, pid: int, exe_path: str = "") -> float:
    """
    byte 3-gram 정적 분석. 분석 불가(ELF 아님/접근 불가)면 0.5 반환
    (기존 worker의 sentinel 규약 유지: 0.5 = 판단 불가 → stat_cache 폴백).

    exe_path는 프로세스가 이미 종료돼 /proc/<pid>/exe 를 읽지 못할 때의
    폴백 경로다. Passthrough._pid_exe 가 이벤트 발생 시점에 캐싱해 둔다.
    exe 단위 캐시는 analyzer 내부에서 처리된다.
    """
    if analyzer is None:
        return 0.5
    try:
        prob = analyzer.predict_pid(pid, exe_path or None)
        return 0.5 if prob is None else prob
    except Exception as e:
        print(f"[ML] 정적 예측 오류: {e}")
        return 0.5


def fuse_score(dyn_model, dyn_cols, stat_model, stat_cache, ops, pid, features):
    """
    (dyn, stat, 가중합 score)를 계산한다. 정적 점수는 프로세스가 살아 있을 때만
    캐싱하고, 죽었으면 캐시를 쓴다(초기 판정/재평가와 동일한 규약).
    """
    dyn_score = predict_dynamic(dyn_model, dyn_cols, features)
    stat_score = predict_static(stat_model, pid, ops._pid_exe.get(pid, ""))
    if stat_score != 0.5:
        stat_cache[pid] = stat_score
    else:
        stat_score = stat_cache.get(pid, 0.5)
    score = DYNAMIC_MODEL_WEIGHT * dyn_score + STATIC_MODEL_WEIGHT * stat_score
    return dyn_score, stat_score, score


async def stage2_worker(recv_chan, ops) -> None:
    """신규 PID 평가와 주기적 재평가를 별도 태스크로 실행한다."""
    dyn_model, dyn_cols, stat_model = load_models()

    # 첫 점수가 낮은 SUSPICIOUS PID의 관찰 시작 시각
    watch_pids: dict = {}

    # 두 태스크가 공유하는 상태 (동일 프로세스 내 단일 trio 스레드에서만 값이 바뀜,
    # to_thread.run_sync로 오프로드된 부분은 순수 함수라 상태를 직접 건드리지 않음)
    medium_pids: dict = ops._medium_pids
    risk_scores: dict = {}
    stat_cache: dict = {}  # 프로세스 종료 후에도 static 점수 유지

    # 상태와 MEDIUM 재평가 목록은 같은 잠금으로 보호
    medium_lock = ops._pid_lock

    async def score_pid(pid: int, features: dict) -> Tuple[float, float, float]:
        dyn_score = predict_dynamic(dyn_model, dyn_cols, features)
        stat_score = await trio.to_thread.run_sync(
            predict_static,
            stat_model,
            pid,
            ops._pid_exe.get(pid, ""),
        )

        if stat_score != 0.5:  # 프로세스 살아있을 때만 캐싱
            stat_cache[pid] = stat_score
        else:
            stat_score = stat_cache.get(pid, 0.5)  # 죽었으면 캐시 사용

        score = DYNAMIC_MODEL_WEIGHT * dyn_score + STATIC_MODEL_WEIGHT * stat_score
        risk_scores[pid] = score

        return dyn_score, stat_score, score

    async def discard_if_high(pid: int) -> bool:
        """HIGH PID의 관찰·MEDIUM 재평가를 종료"""

        async with ops._pid_lock:
            if ops._proc_state.get(pid, ProcState.LOW) != ProcState.HIGH:
                return False

            watch_pids.pop(pid, None)
            medium_pids.pop(pid, None)

            return True

    async def intake_loop(nursery: trio.Nursery) -> None:
        async with recv_chan:
            while True:
                try:
                    item = await recv_chan.receive()
                except trio.EndOfChannel:
                    nursery.cancel_scope.cancel()  # intake 종료 시 reeval_loop도 함께 정리
                    return

                pid = item["pid"]
                features = item.get("features") or {}

                if await discard_if_high(pid):
                    continue

                dyn_score, stat_score, score = await score_pid(pid, features)

                # 정적 점수를 계산하는 동안 HIGH가 될 수 있음
                if await discard_if_high(pid):
                    print(f"[STAGE2] pid={pid} 이미 HIGH → 평가 결과 적용 생략")
                    continue

                print(
                    f"[STAGE2] pid={pid} dyn={dyn_score:.3f} "
                    f"stat={stat_score:.3f} final={score:.3f}"
                )

                # 가중합이 HIGH에 도달하거나, 동적(행동)만으로도 충분히 확신하면 격상.
                # 후자는 실행 파일이 양성 인터프리터라 stat 점수가 낮아
                # 가중합이 눌리는 스크립트형 랜섬웨어를 잡기 위함.
                if (
                    score >= STAGE2_HIGH_THRESHOLD
                    or dyn_score >= STAGE2_DYN_ONLY_HIGH_THRESHOLD
                ):
                    reason = (
                        f"ml_score={score:.3f}"
                        if score >= STAGE2_HIGH_THRESHOLD
                        else f"dyn_only={dyn_score:.3f}"
                    )
                    await ops.trigger_high(pid, reason=reason)
                elif score >= STAGE2_MEDIUM_THRESHOLD:
                    changed = await ops.set_proc_state(
                        pid,
                        ProcState.MEDIUM,
                        preserve_high=True,
                        register_medium=True,
                    )

                    if not changed:
                        await discard_if_high(pid)
                        continue

                    watch_pids.pop(pid, None)

                    print(f"[STAGE2] pid={pid} → MEDIUM (score={score:.3f})")
                else:
                    # HIGH 여부 확인과 WATCH 등록을 같은 잠금에서 처리
                    async with ops._pid_lock:
                        current = ops._proc_state.get(pid, ProcState.LOW)

                        if current == ProcState.HIGH:
                            continue

                        # 신뢰도 gate로 이미 MEDIUM에 등록됐다면
                        # MEDIUM 재평가만 사용
                        if pid in medium_pids:
                            watch_pids.pop(pid, None)
                            print(
                                f"[STAGE2] pid={pid} → MEDIUM 재평가 유지 "
                                f"(score={score:.3f})"
                            )
                            continue

                        watch_pids.setdefault(pid, trio.current_time())

                    print(
                        f"[STAGE2] pid={pid} → 관찰 시작 "
                        f"(score={score:.3f}, "
                        f"{STAGE2_WATCH_TIMEOUT_SEC:.0f}초간 재평가)"
                    )

    async def reeval_loop() -> None:
        from guardfs.stage2.policy.low import handle_low_return
        from guardfs.stage2.policy.medium import (
            commit_buffers,
            validate_medium_buffers,
        )

        next_reeval = trio.current_time() + STAGE2_REEVAL_INTERVAL_SEC

        while True:
            await trio.sleep(max(0.0, next_reeval - trio.current_time()))
            next_reeval += STAGE2_REEVAL_INTERVAL_SEC

            # SUSPICIOUS 관찰 창: 최신 피처로 재채점해 올라가면 승격, 끝까지 낮으면 LOW 복귀
            for pid in list(watch_pids):
                if await discard_if_high(pid):
                    continue

                # 관찰 중 실제 쓰기로 MEDIUM 재평가에 등록되었다면
                # WATCH 관리는 종료
                async with medium_lock:
                    if pid in medium_pids:
                        watch_pids.pop(pid, None)
                        continue

                features = ops._pid_features.get(pid, {})
                dyn_score, stat_score, score = await score_pid(pid, features)

                if await discard_if_high(pid):
                    continue

                started_at = watch_pids.get(pid)
                if started_at is None:
                    continue

                elapsed = trio.current_time() - started_at

                print(
                    f"[WATCH] pid={pid} dyn={dyn_score:.3f} stat={stat_score:.3f} "
                    f"score={score:.3f} elapsed={elapsed:.1f}s"
                )

                if (
                    score >= STAGE2_HIGH_THRESHOLD
                    or dyn_score >= STAGE2_DYN_ONLY_HIGH_THRESHOLD
                ):
                    reason = (
                        f"watch_score={score:.3f}"
                        if score >= STAGE2_HIGH_THRESHOLD
                        else f"watch_dyn_only={dyn_score:.3f}"
                    )
                    watch_pids.pop(pid, None)

                    await ops.trigger_high(pid, reason=reason)

                elif score >= STAGE2_MEDIUM_THRESHOLD:
                    watch_pids.pop(pid, None)

                    changed = await ops.set_proc_state(
                        pid,
                        ProcState.MEDIUM,
                        preserve_high=True,
                        register_medium=True,
                    )

                    if not changed:
                        await discard_if_high(pid)
                        continue

                    print(f"[WATCH] pid={pid} → MEDIUM (score={score:.3f})")

                elif elapsed > STAGE2_WATCH_TIMEOUT_SEC:
                    watch_pids.pop(pid, None)

                    changed = await ops.set_proc_state(
                        pid,
                        ProcState.LOW,
                        preserve_high=True,
                    )

                    if not changed:
                        await discard_if_high(pid)
                        continue

                    # SUSPICIOUS 관찰 중 선제 보호로 버퍼링된 내용을 확정한다.
                    await commit_buffers(pid, ops)
                    await handle_low_return(pid, ops)

                    print(
                        f"[WATCH] pid={pid} 관찰 종료 "
                        f"→ 현재 상태={await ops.get_proc_state(pid)} "
                        f"(score={score:.3f})"
                    )

            async with medium_lock:
                sorted_pids = sorted(
                    medium_pids,
                    key=lambda p: risk_scores.get(p, 0.0),
                    reverse=True,
                )

            for pid in sorted_pids:
                if await discard_if_high(pid):
                    continue

                async with medium_lock:
                    started_at = medium_pids.get(pid)

                if started_at is None:
                    continue  # intake_loop이 그 사이 이미 정리함

                features = ops._pid_features.get(pid, {})
                dyn_score, stat_score, score = await score_pid(pid, features)

                if await discard_if_high(pid):
                    continue

                # 평가 중 목록에서 제외된 경우 오래된 결과를 적용하지 않음
                async with medium_lock:
                    if medium_pids.get(pid) != started_at:
                        continue

                elapsed = trio.current_time() - started_at

                print(
                    f"[REEVAL] pid={pid} dyn={dyn_score:.3f} "
                    f"stat={stat_score:.3f} score={score:.3f} "
                    f"elapsed={elapsed:.1f}s"
                )

                if (
                    score >= STAGE2_HIGH_THRESHOLD
                    or dyn_score >= STAGE2_DYN_ONLY_HIGH_THRESHOLD
                ):
                    reason = (
                        f"reeval_score={score:.3f}"
                        if score >= STAGE2_HIGH_THRESHOLD
                        else f"reeval_dyn_only={dyn_score:.3f}"
                    )

                    print(
                        f"[REEVAL] pid={pid} score={score:.3f} "
                        f"dyn={dyn_score:.3f} → HIGH 격상 ({reason})"
                    )

                    await ops.trigger_high(pid, reason=reason)
                    await discard_if_high(pid)
                    continue

                if elapsed > STAGE2_MEDIUM_TIMEOUT_SEC:
                    changed = await ops.set_proc_state(
                        pid,
                        ProcState.LOW,
                        preserve_high=True,
                    )

                    if not changed:
                        await discard_if_high(pid)
                        continue

                    print(f"[REEVAL] pid={pid} 관찰 시간 종료 → LOW 복귀")

                    await commit_buffers(pid, ops)
                    await handle_low_return(pid, ops)
                    continue

                need_high = await validate_medium_buffers(pid, ops)

                if need_high:
                    print(f"[REEVAL] pid={pid} 구조 깨짐 → 버퍼 드롭 + HIGH 격상")

                    await ops.trigger_high(pid, reason="magic_mismatch_reeval")
                    await discard_if_high(pid)
                    continue

                elif ops._write_buffer.get(pid):
                    print(
                        f"[REEVAL] pid={pid} 헤더 정상 → MEDIUM 유지, "
                        f"{STAGE2_MEDIUM_TIMEOUT_SEC:.0f}초 후 커밋 예정"
                    )

            # 처리 지연으로 지난 재평가가 연속 실행되는 것을 방지
            next_reeval = max(next_reeval, trio.current_time())

    async with trio.open_nursery() as nursery:
        nursery.start_soon(intake_loop, nursery)
        nursery.start_soon(reeval_loop)
