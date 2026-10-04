# stage2_worker.py
import os
import json
import warnings
import trio
import joblib
import pandas as pd
from guardfs.stage2.states import ProcState

from guardfs.common.config import (
    STAGE2_MEDIUM_THRESHOLD,
    STAGE2_HIGH_THRESHOLD,
    STAGE2_DYN_ONLY_HIGH_THRESHOLD,
    DYNAMIC_MODEL_WEIGHT,
    STATIC_MODEL_WEIGHT,
    STAGE2_REEVAL_INTERVAL_SEC,
    STAGE2_MEDIUM_TIMEOUT_SEC,
)

from guardfs.common.paths import (
    DYNAMIC_MODEL_PATH,
    DYNAMIC_FEATURE_COLS_PATH,
    STATIC_MODEL_PATH,
    STATIC_VOCAB_PATH,
)

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
        print(f"[ML] 동적 모델 로드 실패: {e}")
        dyn, dyn_cols = None, []

    try:
        stat = StaticAnalyzer(STATIC_VOCAB_PATH, STATIC_MODEL_PATH)
        print(f"[ML] 정적 모델 로드 완료 (byte 3-gram k={stat.k})")
    except Exception as e:
        print(f"[ML] 정적 모델 로드 실패: {e}")
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


async def stage2_worker(recv_chan, ops) -> None:
    dyn_model, dyn_cols, stat_model = load_models()

    medium_pids = {}
    risk_scores = {}
    stat_cache  = {}   # 프로세스 종료 후에도 static 점수 유지
    next_reeval = trio.current_time() + STAGE2_REEVAL_INTERVAL_SEC

    async with recv_chan:
        while True:
            timeout = max(0.0, next_reeval - trio.current_time())

            with trio.move_on_after(timeout) as scope:
                try:
                    item = await recv_chan.receive()
                except trio.EndOfChannel:
                    return

            if not scope.cancelled_caught:
                pid = item["pid"]
                features = item.get("features") or {}

                dyn_score  = predict_dynamic(dyn_model, dyn_cols, features)
                stat_score = predict_static(
                    stat_model, pid, ops._pid_exe.get(pid, "")
                )
                if stat_score != 0.5:          # 프로세스 살아있을 때만 캐싱
                    stat_cache[pid] = stat_score
                else:
                    stat_score = stat_cache.get(pid, 0.5)  # 죽었으면 캐시 사용
                score = (
                    DYNAMIC_MODEL_WEIGHT * dyn_score
                    + STATIC_MODEL_WEIGHT * stat_score
                )

                risk_scores[pid] = score

                print(f"[STAGE2] pid={pid} dyn={dyn_score:.3f} stat={stat_score:.3f} final={score:.3f}")

                # 가중합이 HIGH에 도달하거나, 동적(행동)만으로도 충분히 확신하면 격상.
                # 후자는 실행 파일이 양성 인터프리터라 stat 점수가 낮아
                # 가중합이 눌리는 스크립트형 랜섬웨어를 잡기 위함.
                if (score >= STAGE2_HIGH_THRESHOLD
                        or dyn_score >= STAGE2_DYN_ONLY_HIGH_THRESHOLD):
                    reason = (
                        f"ml_score={score:.3f}"
                        if score >= STAGE2_HIGH_THRESHOLD
                        else f"dyn_only={dyn_score:.3f}"
                    )
                    await ops.trigger_high(pid, reason=reason)
                elif score >= STAGE2_MEDIUM_THRESHOLD:
                    await ops.set_proc_state(pid, ProcState.MEDIUM)
                    medium_pids[pid] = trio.current_time()
                    print(f"[STAGE2] pid={pid} → MEDIUM (score={score:.3f})")
                else:
                    await ops.set_proc_state(pid, ProcState.LOW)
                    print(f"[STAGE2] pid={pid} → LOW (score={score:.3f})")

            # 1초마다 Medium PID 재평가
            if medium_pids:
                sorted_pids = sorted(
                    medium_pids,
                    key=lambda p: risk_scores.get(p, 0.0),
                    reverse=True,
                )

                for pid in list(sorted_pids):
                    # 최신 피처로 ML 재평가 (stat은 캐시 우선)
                    features = ops._pid_features.get(pid, {})
                    dyn_score  = predict_dynamic(dyn_model, dyn_cols, features)
                    stat_score = predict_static(
                        stat_model, pid, ops._pid_exe.get(pid, "")
                    )

                    if stat_score != 0.5:
                        stat_cache[pid] = stat_score
                    else:
                        stat_score = stat_cache.get(pid, 0.5)
                    # 초기 판정과 동일한 가중치를 쓰도록 config 상수로 통일
                    score = (
                        DYNAMIC_MODEL_WEIGHT * dyn_score
                        + STATIC_MODEL_WEIGHT * stat_score
                    )
                    risk_scores[pid] = score

                    elapsed = trio.current_time() - medium_pids[pid]

                    print(f"[REEVAL] pid={pid} dyn={dyn_score:.3f} stat={stat_score:.3f} score={score:.3f} elapsed={elapsed:.1f}s")

                    if elapsed > STAGE2_MEDIUM_TIMEOUT_SEC:
                        print(f"[REEVAL] pid={pid} 10초 경과 → Low 복귀")
                        await ops.set_proc_state(pid, ProcState.LOW)
                        from guardfs.stage2.policy.medium import commit_buffers
                        await commit_buffers(pid, ops)
                        from guardfs.stage2.policy.low import handle_low_return
                        await handle_low_return(pid, ops)
                        medium_pids.pop(pid, None)
                        continue

                    # HIGH 임계치 초과(가중합) 또는 동적 단독 확신 시 즉시 격상.
                    # 초기 판정과 동일한 OR 규칙을 재평가에도 적용한다.
                    if (score >= STAGE2_HIGH_THRESHOLD
                            or dyn_score >= STAGE2_DYN_ONLY_HIGH_THRESHOLD):
                        reason = (
                            f"reeval_score={score:.3f}"
                            if score >= STAGE2_HIGH_THRESHOLD
                            else f"reeval_dyn_only={dyn_score:.3f}"
                        )
                        print(
                            f"[REEVAL] pid={pid} "
                            f"score={score:.3f} dyn={dyn_score:.3f} → HIGH 격상 ({reason})"
                        )

                        from guardfs.stage2.policy.medium import drop_buffers
                        await ops.trigger_high(pid, reason=reason)
                        await drop_buffers(pid, ops)
                        medium_pids.pop(pid, None)

                        continue

                    from guardfs.stage2.policy.medium import validate_medium_buffers, drop_buffers

                    need_high = await validate_medium_buffers(pid, ops)

                    if need_high:
                        print(f"[REEVAL] pid={pid} 구조 깨짐 → 버퍼 드롭 + HIGH 격상")
                        await ops.trigger_high(pid, reason="magic_mismatch_reeval")
                        await drop_buffers(pid, ops)
                        medium_pids.pop(pid, None)
                    elif ops._write_buffer.get(pid):
                        print(
                            f"[REEVAL] pid={pid} 헤더 정상 → MEDIUM 유지, "
                            f"{STAGE2_MEDIUM_TIMEOUT_SEC:.0f}초 후 커밋 예정"
                        )

            next_reeval += STAGE2_REEVAL_INTERVAL_SEC
