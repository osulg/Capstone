#!/usr/bin/env python3
"""
ML 기반 Risk Score 계산 (Stage 2 / calculation)

- StaticFeatureExtractor / StaticAnalyzer:
    byte 3-gram (n=3, k=1000, k-feature 합 정규화) 정적 모델 추론.
    학습 파이프라인(static_test/byte_ngram.py)과 비트 단위로 동일한 전처리.

- DynamicAnalyzer:
    O/C/D/E 행동 feature 기반 동적 모델 추론 (scaler + model).

- FusionCalculator:
    config의 가중치로 정적/동적 확률을 결합해 최종 risk score 산출.
"""
import os
import json
from typing import Optional, List, Dict

import numpy as np
import joblib

from guardfs import config
from guardfs.common import paths


class StaticFeatureExtractor:
    """파일 → byte 3-gram k차원 정규화 벡터"""

    N = 3  # 실험에서 확정한 n-gram 길이

    def __init__(self, vocab_path=None):
        vocab_path = str(vocab_path or paths.STATIC_VOCAB_PATH)
        with open(vocab_path, "r", encoding="utf-8") as f:
            vocab_hex: List[str] = json.load(f)

        # vocab JSON: f_i 순서의 hex 문자열 리스트 (예: "7f454c")
        self._vocab_idx = np.array(
            [int(h, 16) for h in vocab_hex], dtype=np.int64
        )
        self.k = len(self._vocab_idx)

    def extract_bytes(self, data: bytes) -> Optional[np.ndarray]:
        """바이트열 → k차원 정규화 벡터. ELF가 아니거나 너무 짧으면 None."""
        if len(data) < self.N or not data.startswith(b"\x7fELF"):
            return None

        # 실험 코드와 동일한 bincount 방식 (n=3)
        arr = np.frombuffer(data, dtype=np.uint8).astype(np.uint32)
        grams = (arr[:-2] << 16) | (arr[1:-1] << 8) | arr[2:]
        counts = np.bincount(grams, minlength=1 << 24)

        vec = counts[self._vocab_idx].astype(np.float64)

        # 파일 크기 편향 제거: 선택된 k개 feature 합으로 정규화 (학습 CSV와 동일)
        total = vec.sum()
        if total > 0:
            vec /= total

        return vec

    def extract_path(self, path: str) -> Optional[np.ndarray]:
        try:
            with open(path, "rb") as f:
                data = f.read()
        except Exception:
            return None
        return self.extract_bytes(data)


class StaticAnalyzer:
    """정적 모델 추론 진입점 (exe 단위 캐시 내장)"""

    def __init__(self, vocab_path=None, model_path=None,
                 feature_prefix: str = "f_"):
        self.extractor = StaticFeatureExtractor(vocab_path)
        self.model = joblib.load(str(model_path or paths.STATIC_MODEL_PATH))
        self._columns = [f"{feature_prefix}{i}"
                         for i in range(self.extractor.k)]

        # exe 경로 → 악성 확률. 같은 바이너리는 결과가 불변이므로 재계산하지 않는다.
        self._cache: Dict[str, Optional[float]] = {}

    def _predict(self, vec: Optional[np.ndarray]) -> Optional[float]:
        if vec is None:
            return None
        try:
            import pandas as pd
            X = pd.DataFrame([vec], columns=self._columns)
            return float(self.model.predict_proba(X)[0][1])
        except Exception:
            try:
                return float(self.model.predict_proba(vec.reshape(1, -1))[0][1])
            except Exception:
                return None

    def predict_proba_path(self, exe_path: str) -> Optional[float]:
        return self._predict(self.extractor.extract_path(exe_path))

    def predict_proba_pid(self, pid: int) -> Optional[float]:
        """
        /proc/{pid}/exe 를 '경로로' 직접 연다.
        악성코드가 자기 자신을 unlink한 뒤에도 프로세스 생존 중엔
        원본 바이너리를 읽을 수 있다 (self-deleting malware 대응).
        """
        return self._predict(
            self.extractor.extract_path(f"/proc/{pid}/exe")
        )

    def predict_cached(self, pid: int, exe_path: Optional[str]):
        """
        캐시 우선 추론.
        반환: (악성 확률 또는 None, 캐시 히트 여부)
        """
        try:
            real_exe = os.path.realpath(f"/proc/{pid}/exe")
            if real_exe.startswith("/proc/"):
                real_exe = None  # 링크 미해석 = 프로세스 이미 종료
        except OSError:
            real_exe = None
        cache_key = real_exe or exe_path

        if cache_key is not None and cache_key in self._cache:
            return self._cache[cache_key], True

        # 1순위: /proc/{pid}/exe 직접 읽기
        prob = self.predict_proba_pid(pid)

        # 2순위: 프로세스가 이미 죽었으면 기록해둔 exe_path로
        if prob is None and exe_path and os.path.exists(exe_path):
            prob = self.predict_proba_path(exe_path)

        if cache_key is not None:
            self._cache[cache_key] = prob

        return prob, False


class DynamicAnalyzer:
    """동적 모델 추론 진입점 (O/C/D/E feature)"""

    def __init__(self, model_path=None, scaler_path=None):
        self.model = joblib.load(str(model_path or paths.DYNAMIC_MODEL_PATH))
        self.scaler = joblib.load(str(scaler_path or paths.DYNAMIC_SCALER_PATH))

    def predict_proba(self, features: dict) -> float:
        import pandas as pd
        X = pd.DataFrame([features])
        X_scaled = self.scaler.transform(X.values)
        return float(self.model.predict_proba(X_scaled)[0][1])


class FusionCalculator:
    """정적/동적 확률 → 최종 risk score"""

    @staticmethod
    def fuse(dynamic_prob: float, static_prob: Optional[float]) -> float:
        if static_prob is not None:
            return (
                config.DYNAMIC_MODEL_WEIGHT * dynamic_prob
                + config.STATIC_MODEL_WEIGHT * static_prob
            )
        return dynamic_prob
