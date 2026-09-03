#!/usr/bin/env python3
"""
Stage 2 Worker
- Stage 1(경량 탐지)이 큐에 올린 의심 PID를 받아
  동적 ML + 정적 ML 예측 후 fusion으로 최종 risk score를 계산한다.
- 정적 예측은 exe 단위로 캐시된다 (StaticAnalyzer 내장).
"""
from guardfs.common import paths
from guardfs import config
from guardfs.stage2.calculation.ml_risk import (
    StaticAnalyzer,
    DynamicAnalyzer,
    FusionCalculator,
)


async def stage2_worker(recv_chan, ops):
    # -----------------------
    # 모델 로드
    # -----------------------
    dynamic = DynamicAnalyzer()

    static = None
    try:
        static = StaticAnalyzer()
        print(f"[STAGE2] static analyzer loaded "
              f"(byte 3-gram k={static.extractor.k})")
    except Exception as e:
        print(f"[STAGE2] static analyzer unavailable, dynamic-only mode: {e}")

    # -----------------------
    # 메인 루프
    # -----------------------
    async with recv_chan:
        async for item in recv_chan:
            pid = item["pid"]
            reason = item["reason"]
            path = item["path"]
            features = item["features"]
            exe_path = item.get("exe_path")

            print(
                f"[STAGE1.5] pid={pid} reason={reason} "
                f"path={path} exe={exe_path}"
            )

            # -----------------------
            # 1. Dynamic ML
            # -----------------------
            dynamic_prob = dynamic.predict_proba(features)
            dynamic_pred = 1 if dynamic_prob >= config.MEDIUM_THRESHOLD else 0

            # -----------------------
            # 2. Static ML (byte 3-gram, exe 단위 캐시)
            # -----------------------
            static_prob = None
            static_pred = None
            static_cached = False

            if static is not None:
                try:
                    static_prob, static_cached = static.predict_cached(
                        pid, exe_path
                    )
                    if static_prob is not None:
                        static_pred = (
                            1 if static_prob >= config.MEDIUM_THRESHOLD else 0
                        )
                except Exception as e:
                    print(f"[STATIC ERROR] pid={pid} exe={exe_path} error={e}")

            # -----------------------
            # 3. Fusion
            # -----------------------
            final_score = FusionCalculator.fuse(dynamic_prob, static_prob)
            final_pred = 1 if final_score >= config.MEDIUM_THRESHOLD else 0

            # -----------------------
            # 출력
            # -----------------------
            print(
                f"[RESULT] pid={pid} "
                f"dynamic_pred={dynamic_pred} dynamic_prob={dynamic_prob:.4f} "
                f"static_pred={static_pred} "
                f"static_prob={static_prob if static_prob is not None else 'N/A'}"
                f"{' (cached)' if static_cached else ''} "
                f"final_score={final_score:.4f} final_pred={final_pred}"
            )

            # -----------------------
            # 큐 정리
            # -----------------------
            async with ops._pid_lock:
                ops._queued_stage2.discard(pid)
