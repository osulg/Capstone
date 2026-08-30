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
        stat = joblib.load(STATIC_MODEL_PATH)
        global STATIC_FEATURES
        STATIC_FEATURES = list(stat.feature_names_in_)
        print(f"[ML] 정적 모델 로드 완료 ({len(STATIC_FEATURES)} features)\n")
    except Exception as e:
        print(f"[ML] 정적 모델 로드 실패: {e}")
        stat = None

    return dyn, stat


def get_exe_path(pid: int) -> str:
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except Exception:
        return ""


def predict_dynamic(model, features: dict) -> float:
    if model is None:
        return 0.5
    try:
        row = {f: features.get(f, 0) for f in DYNAMIC_FEATURES}
        df = pd.DataFrame([row])
        prob = model.predict_proba(df)[0]
        # 악성(1) 클래스 확률 반환
        classes = list(model.classes_)
        mal_idx = classes.index(1) if 1 in classes else -1
        return float(prob[mal_idx]) if mal_idx >= 0 else float(prob[-1])
    except Exception as e:
        print(f"[ML] 동적 예측 오류: {e}")
        return 0.5


def predict_static(model, pid: int) -> float:
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
    dyn_model, stat_model = load_models()

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

                dyn_score  = predict_dynamic(dyn_model, features)
                stat_score = predict_static(stat_model, pid)
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

                if score >= STAGE2_HIGH_THRESHOLD:
                    await ops.trigger_high(pid, reason=f"ml_score={score:.3f}")
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
                    dyn_score  = predict_dynamic(dyn_model, features)
                    stat_score = predict_static(stat_model, pid)
                    
                    if stat_score != 0.5:
                        stat_cache[pid] = stat_score
                    else:
                        stat_score = stat_cache.get(pid, 0.5)
                    score = 0.5 * dyn_score + 0.5 * stat_score
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

                    # HIGH 임계치 초과 시 즉시 격상
                    if score >= STAGE2_HIGH_THRESHOLD:
                        print(
                            f"[REEVAL] pid={pid} "
                            f"{STAGE2_MEDIUM_TIMEOUT_SEC:.0f}초 경과 → LOW 복귀"
                        )
                        
                        from guardfs.stage2.policy.medium import drop_buffers
                        await ops.trigger_high(pid, reason=f"reeval_score={score:.3f}")
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
