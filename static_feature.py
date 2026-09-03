#!/usr/bin/env python3
"""
정적 분석 추론 모듈 (Stage 2)

byte 3-gram (n=3, k=1000, 정규화) 기반 정적 모델의 런타임 인터페이스.
실험 코드(byte_ngram.py)에서 확정한 vocab/전처리와 동일해야 한다.

사용법:
    from static_feature import StaticAnalyzer

    analyzer = StaticAnalyzer(
        vocab_path="models/static/byte_ngram_vocab_n3_k1000.json",
        model_path="models/static/static_rf_n3_k1000.pkl",
    )
    prob = analyzer.predict_proba_pid(pid)   # /proc/{pid}/exe 직접 읽기
    prob = analyzer.predict_proba_path(exe_path)  # 경로로 읽기
    # 반환: 악성 확률 float, 분석 불가 시 None
"""
import os
import json
from typing import Optional, List

import numpy as np
import joblib


class StaticFeatureExtractor:
    """파일 → byte 3-gram k차원 정규화 벡터"""

    N = 3  # 실험에서 확정한 n-gram 길이

    def __init__(self, vocab_path: str):
        with open(vocab_path, "r", encoding="utf-8") as f:
            vocab_hex: List[str] = json.load(f)

        # vocab JSON: 빈도 내림차순 hex 문자열 리스트 (예: "7f454c")
        # hex → 24bit 정수 인덱스로 변환해 둔다
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

        # 파일 크기 편향 제거: 선택된 k개 feature 합으로 정규화 (실험 CSV와 동일)
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
    """vocab + 학습된 모델을 묶은 추론 진입점"""

    def __init__(self, vocab_path: str, model_path: str,
                 feature_prefix: str = "f_"):
        self.extractor = StaticFeatureExtractor(vocab_path)
        self.model = joblib.load(model_path)
        # 학습 시 DataFrame 컬럼명 (f_0 ... f_{k-1}) — 학습 스크립트와 일치 필요
        self._columns = [f"{feature_prefix}{i}"
                         for i in range(self.extractor.k)]

    def _predict(self, vec: Optional[np.ndarray]) -> Optional[float]:
        if vec is None:
            return None
        try:
            import pandas as pd
            X = pd.DataFrame([vec], columns=self._columns)
            return float(self.model.predict_proba(X)[0][1])
        except Exception:
            # 컬럼명 없이 학습된 모델이면 배열로 재시도
            try:
                return float(self.model.predict_proba(vec.reshape(1, -1))[0][1])
            except Exception:
                return None

    def predict_proba_path(self, exe_path: str) -> Optional[float]:
        return self._predict(self.extractor.extract_path(exe_path))

    def predict_proba_pid(self, pid: int) -> Optional[float]:
        """
        /proc/{pid}/exe 를 '경로로' 직접 연다.

        readlink 결과(원본 경로)가 아니라 proc 링크 자체를 열기 때문에,
        악성코드가 자기 자신을 unlink한 뒤에도 프로세스가 살아 있는 동안은
        원본 바이너리를 읽을 수 있다 (self-deleting malware 대응).
        """
        return self._predict(
            self.extractor.extract_path(f"/proc/{pid}/exe")
        )
