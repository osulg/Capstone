# stage2_worker.py
import os
import warnings
import trio
import joblib
import pandas as pd
from guardfs.stage2.states import ProcState

from guardfs.common.config import (
    STAGE2_MEDIUM_THRESHOLD,
    STAGE2_HIGH_THRESHOLD,
    DYNAMIC_MODEL_WEIGHT,
    STATIC_MODEL_WEIGHT,
    STAGE2_REEVAL_INTERVAL_SEC,
    STAGE2_MEDIUM_TIMEOUT_SEC,
)

from guardfs.common.paths import (
    DYNAMIC_MODEL_PATH,
    DYNAMIC_SCALER_PATH,
    STATIC_MODEL_PATH,
)

warnings.filterwarnings("ignore", category=UserWarning, module="sklearn")

DYNAMIC_FEATURES = [
    "O_sum", "C_sum", "D_sum", "E_sum",
    "Is_System_Path", "Is_Test_Path", "is_dev",
    "CCC", "CCD", "CCO", "CDC", "CDD", "CDO",
    "COC", "COD", "COO", "DCC", "DCD", "DCO",
    "DDC", "DDD", "DDO", "DOC", "DOD", "DOO",
    "EEE", "EEO", "EOE", "EOO", "OCC", "OCD",
    "OCO", "ODC", "ODD", "ODO", "OEE", "OOC",
    "OOD", "OOO"
]

STATIC_FEATURES = None  # 모델 로딩 후 채움


def load_models():
    try:
        dyn = joblib.load(DYNAMIC_MODEL_PATH)
        print(f"[ML] 동적 모델 로드 완료")
    except Exception as e:
        print(f"[ML] 동적 모델 로드 실패: {e}")
        dyn = None

    try:
        dyn_scaler = joblib.load(DYNAMIC_SCALER_PATH)
        print(f"[ML] 동적 모델 스케일러 로드 완료")
    except Exception as e:
        print(f"[ML] 동적 모델 스케일러 로드 실패: {e}")
        dyn_scaler = None

    try:
        stat = joblib.load(STATIC_MODEL_PATH)
        global STATIC_FEATURES
        STATIC_FEATURES = list(stat.feature_names_in_)
        print(f"[ML] 정적 모델 로드 완료 ({len(STATIC_FEATURES)} features)")
    except Exception as e:
        print(f"[ML] 정적 모델 로드 실패: {e}")
        stat = None

    return dyn, dyn_scaler, stat


def get_exe_path(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""


def predict_dynamic(model, scaler, features: dict) -> float:
    """
    best_model.pkl은 학습 시 StandardScaler로 정규화된 값으로 학습됐다
    (model.py의 X_train_s = scaler.fit_transform(X_train)).
    RandomForest의 분기점은 정규화된 분포 기준으로 학습되므로,
    추론 시에도 반드시 동일한 scaler.transform()을 거쳐야 한다.
    scaler 없이 원본 카운트값을 그대로 넣으면 예측이 어긋난다.
    """
    if model is None:
        return 0.5
    try:
        row = {f: features.get(f, 0) for f in DYNAMIC_FEATURES}
        df = pd.DataFrame([row], columns=DYNAMIC_FEATURES)
        X = scaler.transform(df.values) if scaler is not None else df.values
        prob = model.predict_proba(X)[0]
        # 악성(1) 클래스 확률 반환
        classes = list(model.classes_)
        mal_idx = classes.index(1) if 1 in classes else -1
        return float(prob[mal_idx]) if mal_idx >= 0 else float(prob[-1])
    except Exception as e:
        print(f"[ML] 동적 예측 오류: {e}")
        return 0.5


def predict_static(model, pid: int) -> float:
    """
    블로킹 I/O(exe 파일 읽기)를 포함한다.
    호출부에서 반드시 trio.to_thread.run_sync로 오프로드해서 호출해야
    trio 이벤트 루프(FUSE 처리 포함)가 이 호출 동안 멈추지 않는다.
    """
    if model is None or STATIC_FEATURES is None:
        return 0.5
    try:
        exe_path = get_exe_path(pid)
        if not exe_path or not os.path.exists(exe_path):
            return 0.5

        # 기본값 0으로 채우고 계산 가능한 값만 채움
        row = {f: 0 for f in STATIC_FEATURES}
        row["file_size"] = os.path.getsize(exe_path)
        row["is_64bit"] = 1

        with open(exe_path, "rb") as f:
            header = f.read(16)

            if header[:4] == b'\x7fELF':
                row["is_64bit"] = 1 if header[4] == 2 else 0
                # ELF type (ET_EXEC=2, ET_DYN=3)
                f.seek(16)
                e_type = int.from_bytes(f.read(2), 'little')
                if "elf_type_ET_EXEC" in row:
                    row["elf_type_ET_EXEC"] = 1 if e_type == 2 else 0
                if "elf_type_ET_DYN" in row:
                    row["elf_type_ET_DYN"] = 1 if e_type == 3 else 0

            # byte frequency features
            f.seek(0)

            data = f.read(4096)
            freq = [0] * 256

            for b in data:
                freq[b] += 1
            for feat in STATIC_FEATURES:
                if feat.startswith("byte_f_"):
                    idx = int(feat.split("_")[-1])
                    if idx < 256:
                        row[feat] = freq[idx] / max(len(data), 1)

        df = pd.DataFrame([row])
        prob = model.predict_proba(df)[0]
        classes = list(model.classes_)
        mal_idx = classes.index(1) if 1 in classes else -1

        return float(prob[mal_idx]) if mal_idx >= 0 else float(prob[-1])

    except Exception as e:
        print(f"[ML] 정적 예측 오류: {e}")
        return 0.5


async def stage2_worker(recv_chan, ops) -> None:
    """
    Stage2 워커. 신규 이벤트 수신(intake)과 MEDIUM PID 재평가(reeval)를
    독립된 trio 태스크 두 개로 분리해서 실행한다.

    분리 전에는 둘이 같은 while 루프 안에서 순차 실행되어, MEDIUM PID가
    여러 개면 그 재평가가 끝날 때까지 신규 이벤트 처리가 밀렸다.
    predict_static의 블로킹 파일 I/O도 trio.to_thread.run_sync로 오프로드해서
    reeval 중에도 intake(및 FUSE 이벤트 처리 전반)가 멈추지 않게 한다.
    """
    dyn_model, dyn_scaler, stat_model = load_models()

    # 두 태스크가 공유하는 상태 (동일 프로세스 내 단일 trio 스레드에서만 값이 바뀜,
    # to_thread.run_sync로 오프로드된 부분은 순수 함수라 상태를 직접 건드리지 않음)
    medium_pids: dict = {}
    risk_scores: dict = {}
    stat_cache:  dict = {}   # 프로세스 종료 후에도 static 점수 유지
    medium_lock = trio.Lock()

    async def score_pid(pid: int, features: dict) -> float:
        dyn_score = predict_dynamic(dyn_model, dyn_scaler, features)
        stat_score = await trio.to_thread.run_sync(predict_static, stat_model, pid)

        if stat_score != 0.5:          # 프로세스 살아있을 때만 캐싱
            stat_cache[pid] = stat_score
        else:
            stat_score = stat_cache.get(pid, 0.5)  # 죽었으면 캐시 사용

        score = DYNAMIC_MODEL_WEIGHT * dyn_score + STATIC_MODEL_WEIGHT * stat_score
        risk_scores[pid] = score

        return dyn_score, stat_score, score

    async def intake_loop(nursery: trio.Nursery) -> None:
        from guardfs.stage2.policy.medium import commit_buffers
        from guardfs.stage2.policy.low import handle_low_return

        async with recv_chan:
            while True:
                try:
                    item = await recv_chan.receive()
                except trio.EndOfChannel:
                    nursery.cancel_scope.cancel()  # intake 종료 시 reeval_loop도 함께 정리
                    return

                pid = item["pid"]
                features = item.get("features") or {}

                dyn_score, stat_score, score = await score_pid(pid, features)

                print(f"[STAGE2] pid={pid} dyn={dyn_score:.3f} stat={stat_score:.3f} final={score:.3f}")

                if score >= STAGE2_HIGH_THRESHOLD:
                    await ops.trigger_high(pid, reason=f"ml_score={score:.3f}")
                elif score >= STAGE2_MEDIUM_THRESHOLD:
                    await ops.set_proc_state(pid, ProcState.MEDIUM)
                    async with medium_lock:
                        medium_pids[pid] = trio.current_time()
                    print(f"[STAGE2] pid={pid} → MEDIUM (score={score:.3f})")
                else:
                    await ops.set_proc_state(pid, ProcState.LOW)
                    # SUSPICIOUS 대기 중 선제 보호(④)로 버퍼링됐을 수 있으므로 커밋하고,
                    # _queued_stage2에서 빼서 이후에 다시 의심스러운 행동을 하면
                    # 재평가될 수 있게 한다 (안 하면 이 pid는 영구히 재평가 대상에서 제외됨).
                    await commit_buffers(pid, ops)
                    await handle_low_return(pid, ops)
                    print(f"[STAGE2] pid={pid} → LOW (score={score:.3f})")

    async def reeval_loop() -> None:
        from guardfs.stage2.policy.medium import (
            commit_buffers,
            validate_medium_buffers,
        )
        from guardfs.stage2.policy.low import handle_low_return

        next_reeval = trio.current_time() + STAGE2_REEVAL_INTERVAL_SEC

        while True:
            await trio.sleep(max(0.0, next_reeval - trio.current_time()))
            next_reeval += STAGE2_REEVAL_INTERVAL_SEC

            async with medium_lock:
                sorted_pids = sorted(
                    medium_pids,
                    key=lambda p: risk_scores.get(p, 0.0),
                    reverse=True,
                )

            for pid in sorted_pids:
                async with medium_lock:
                    started_at = medium_pids.get(pid)
                if started_at is None:
                    continue  # intake_loop이 그 사이 이미 정리함

                features = ops._pid_features.get(pid, {})
                dyn_score, stat_score, score = await score_pid(pid, features)

                elapsed = trio.current_time() - started_at

                print(f"[REEVAL] pid={pid} dyn={dyn_score:.3f} stat={stat_score:.3f} score={score:.3f} elapsed={elapsed:.1f}s")

                if elapsed > STAGE2_MEDIUM_TIMEOUT_SEC:
                    print(f"[REEVAL] pid={pid} 10초 경과 → Low 복귀")
                    await ops.set_proc_state(pid, ProcState.LOW)
                    await commit_buffers(pid, ops)
                    await handle_low_return(pid, ops)
                    async with medium_lock:
                        medium_pids.pop(pid, None)
                    continue

                if score >= STAGE2_HIGH_THRESHOLD:
                    print(f"[REEVAL] pid={pid} score={score:.3f} → HIGH 격상")
                    # trigger_high → handle_high_enter가 내부적으로 drop_buffers를
                    # 호출해 버퍼 폐기/전역 카운트 반영/unlink 복원을 전담한다.
                    await ops.trigger_high(pid, reason=f"reeval_score={score:.3f}")
                    async with medium_lock:
                        medium_pids.pop(pid, None)
                    continue

                need_high = await validate_medium_buffers(pid, ops)

                if need_high:
                    print(f"[REEVAL] pid={pid} 구조 깨짐 → 버퍼 드롭 + HIGH 격상")
                    await ops.trigger_high(pid, reason="magic_mismatch_reeval")
                    async with medium_lock:
                        medium_pids.pop(pid, None)
                elif ops._write_buffer.get(pid):
                    print(
                        f"[REEVAL] pid={pid} 헤더 정상 → MEDIUM 유지, "
                        f"{STAGE2_MEDIUM_TIMEOUT_SEC:.0f}초 후 커밋 예정"
                    )

    async with trio.open_nursery() as nursery:
        nursery.start_soon(intake_loop, nursery)
        nursery.start_soon(reeval_loop)
