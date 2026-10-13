#!/usr/bin/env python3
"""
정적 분석기 (byte 3-gram, n=3, k=1000)

학습 파이프라인(static_test/byte_ngram.py)과 비트 단위로 동일한 전처리:
- ELF 전체 바이트의 3-gram 빈도 → vocab 상위 1000개 → k개 합으로 정규화
- 학습 데이터셋: 501개 (정상 288 / 악성 213), sklearn 1.3.2

기존 final_rf_model.pkl(200 feature 임시 구현)을 대체한다.
검증 근거: LOFO macro recall 0.997 / FPR 0.0,
런타임 sanity — /bin/ls 0.005, /bin/tar 0.010, lockbit 0.99, Conti 0.98.
"""
import os
import json
from typing import Optional, List, Dict

import numpy as np
import joblib


class StaticAnalyzer:
    """byte 3-gram 정적 모델 추론 (exe 단위 캐시 내장)"""

    N = 3

    def __init__(self, vocab_path: str, model_path: str,
                 feature_prefix: str = "f_"):
        with open(vocab_path, "r", encoding="utf-8") as f:
            vocab_hex: List[str] = json.load(f)
        # vocab: f_0~f_999 순서의 hex 3-gram 리스트 (예: "7f454c")
        self._vocab_idx = np.array(
            [int(h, 16) for h in vocab_hex], dtype=np.int64
        )
        self.k = len(self._vocab_idx)

        self.model = joblib.load(model_path)
        self._columns = [f"{feature_prefix}{i}" for i in range(self.k)]

        # exe 실제 경로 → 악성 확률. 같은 바이너리는 결과가 불변이므로 1회만 계산.
        self._cache: Dict[str, Optional[float]] = {}

    # ------------------------------------------------ feature 추출

    def _extract_bytes(self, data: bytes) -> Optional[np.ndarray]:
        if len(data) < self.N or not data.startswith(b"\x7fELF"):
            return None

        arr = np.frombuffer(data, dtype=np.uint8).astype(np.uint32)
        grams = (arr[:-2] << 16) | (arr[1:-1] << 8) | arr[2:]
        counts = np.bincount(grams, minlength=1 << 24)

        vec = counts[self._vocab_idx].astype(np.float64)

        # 파일 크기 편향 제거: 선택된 k개 feature 합으로 정규화 (학습 CSV와 동일)
        total = vec.sum()
        if total > 0:
            vec /= total
        return vec

    def _extract_path(self, path: str) -> Optional[np.ndarray]:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            return None
        return self._extract_bytes(data)

    # ------------------------------------------------ 예측

    def _predict(self, vec: Optional[np.ndarray]) -> Optional[float]:
        if vec is None:
            return None
        try:
            import pandas as pd
            X = pd.DataFrame([vec], columns=self._columns)
            prob = self.model.predict_proba(X)[0]
            classes = list(self.model.classes_)
            mal_idx = classes.index(1) if 1 in classes else -1
            return float(prob[mal_idx]) if mal_idx >= 0 else float(prob[-1])
        except Exception:
            return None

    def predict_pid(self, pid: int,
                    exe_path: Optional[str] = None) -> Optional[float]:
        """
        캐시 우선 추론. 악성 확률 float 또는 분석 불가 시 None 반환.

        /proc/{pid}/exe 를 '경로로' 직접 열어 읽으므로,
        self-deleting 악성코드도 프로세스 생존 중에는 원본을 읽을 수 있다.
        프로세스 종료 시에는 exe_path 인자로 폴백한다.
        """
        try:
            real_exe = os.path.realpath(f"/proc/{pid}/exe")
            if real_exe.startswith("/proc/"):
                real_exe = None  # 링크 미해석 = 프로세스 이미 종료
        except OSError:
            real_exe = None
        cache_key = real_exe or exe_path

        if cache_key is not None and cache_key in self._cache:
            return self._cache[cache_key]

        prob = self._predict(self._extract_path(f"/proc/{pid}/exe"))

        if prob is None and exe_path and os.path.exists(exe_path):
            prob = self._predict(self._extract_path(exe_path))

        if cache_key is not None:
            self._cache[cache_key] = prob
        return prob
