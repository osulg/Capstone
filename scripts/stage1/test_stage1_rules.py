#!/usr/bin/env python3
"""
> GuardFS Stage 1 경량 탐지 규칙 단위·경계·우회 테스트

1. Shannon entropy 계산의 수학적 정확성
2. EntropyDetector의 연산 종류, 최소 크기, 임계값 경계
3. ExtChangeDetector의 즉시 탐지, 누적 횟수, 시간 창, PID 격리
4. HoneypotDetector의 경로 경계, 정규화, rename 목적지 검사
5. Stage1Detector의 통합 결과와 탐지기 우선순위
6. 공통 설정값이 탐지기 기본값에 정확히 반영되는지 여부

실행:
    python scripts/test_stage1_rules.py
    python scripts/test_stage1_rules.py -v
    python scripts/test_stage1_rules.py EntropyDetectorTests
"""

from __future__ import annotations

import argparse
import asyncio
import math
import os
import sys
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest.mock import patch

# 어느 디렉터리에서 실행하더라도 guardfs 패키지를 찾을 수 있도록 설정
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from guardfs.common.config import (  # noqa: E402
    ENTROPY_ACCUMULATION_SIZE,
    ENTROPY_ACCUMULATION_WINDOW_SEC,
    ENTROPY_HEADER_SIZE,
    ENTROPY_MIN_SAMPLE_SIZE,
    ENTROPY_SHORT_SAMPLE_THRESHOLD,
    ENTROPY_THRESHOLD,
    EXT_CHANGE_THRESHOLD,
    EXT_CHANGE_WINDOW_SEC,
)
from guardfs.stage1.detector import Stage1Detector  # noqa: E402
from guardfs.stage1.entropy import (  # noqa: E402
    EntropyDetector,
    shannon_entropy,
)
from guardfs.stage1.ext_change import ExtChangeDetector  # noqa: E402
from guardfs.stage1.honeypot import HoneypotDetector  # noqa: E402


@dataclass
class FakeEvent:
    """실제 ``FsEvent``와 같은 필드를 갖는 가벼운 테스트 이벤트.

    Stage 1 detector는 객체의 필드만 사용하므로 pyfuse3를 불러오지 않아도
    실제 이벤트 계약을 그대로 검증
    """

    pid: int = 1000
    op: str = "write"
    path: str = "/underlay/document.txt"
    size: int = 0
    off: int = 0
    flags: int = 0
    entropy: float | None = None
    new_path: str | None = None
    sample_data: bytes | None = None
    ts_ns: int = 0


@dataclass
class FakeEvent:
    pid: int = 1000
    op: str = "write"
    path: str = "/underlay/document.txt"
    size: int = 0
    off: int = 0
    flags: int = 0
    entropy: float | None = None
    new_path: str | None = None
    sample_data: bytes | None = None
    applied: bool = True
    ts_ns: int = 0


def event(**changes) -> FakeEvent:
    """읽기 쉬운 테스트를 위한 이벤트 생성 helper."""

    return FakeEvent(**changes)


def run_check(detector: Stage1Detector, ev: FakeEvent):
    """Stage1Detector.check() 코루틴을 동기식 unittest에서 실행"""

    return asyncio.run(detector.check(ev))


class ShannonEntropyTests(unittest.TestCase):
    """엔트로피 계산 함수가 알려진 분포에서 정확한 값을 내는지 검사"""

    def test_empty_input_is_zero(self):
        self.assertEqual(shannon_entropy(b""), 0.0)

    def test_single_repeated_byte_is_zero(self):
        self.assertEqual(shannon_entropy(b"A" * 1024), 0.0)

    def test_two_equally_likely_bytes_have_one_bit_entropy(self):
        self.assertAlmostEqual(shannon_entropy(b"AB" * 128), 1.0, places=12)

    def test_all_byte_values_have_maximum_entropy(self):
        # 0~255가 같은 횟수로 나타나면 Shannon entropy는 정확히 8
        self.assertAlmostEqual(shannon_entropy(bytes(range(256))), 8.0, places=12)

    def test_result_always_stays_in_byte_entropy_range(self):
        samples = [b"", b"abc", bytes(range(256)), os.urandom(4096)]
        for sample in samples:
            with self.subTest(size=len(sample)):
                value = shannon_entropy(sample)
                self.assertGreaterEqual(value, 0.0)
                self.assertLessEqual(value, 8.0)

    def test_known_uneven_distribution(self):
        # P(A)=3/4, P(B)=1/4인 분포의 이론값과 비교
        expected = -(0.75 * math.log2(0.75) + 0.25 * math.log2(0.25))
        self.assertAlmostEqual(shannon_entropy(b"AAAB"), expected, places=12)


class EntropyDetectorTests(unittest.TestCase):
    """단일 write 이벤트에 대한 entropy 규칙의 정상·경계 동작"""

    def setUp(self):
        self.detector = EntropyDetector()

    def test_defaults_follow_common_config(self):
        self.assertEqual(self.detector.threshold, ENTROPY_THRESHOLD)
        self.assertEqual(self.detector.header_size, ENTROPY_HEADER_SIZE)
        self.assertEqual(
            self.detector.accumulation_window_sec,
            ENTROPY_ACCUMULATION_WINDOW_SEC,
        )
        self.assertEqual(
            self.detector.min_sample_size,
            ENTROPY_MIN_SAMPLE_SIZE,
        )
        self.assertEqual(
            self.detector.short_sample_threshold,
            ENTROPY_SHORT_SAMPLE_THRESHOLD,
        )

    def test_non_write_operation_is_ignored(self):
        for op in ("open", "read", "create", "rename", "unlink", "truncate"):
            with self.subTest(op=op):
                ev = event(op=op, size=ENTROPY_HEADER_SIZE, entropy=8.0)
                self.assertFalse(self.detector.check(ev))

    def test_write_smaller_than_header_is_ignored(self):
        ev = event(size=ENTROPY_HEADER_SIZE - 1, entropy=8.0)
        self.assertFalse(self.detector.check(ev))

    def test_write_at_header_size_is_examined(self):
        data = bytes(range(128)) * 2
        ev = event(
            size=ENTROPY_HEADER_SIZE,
            entropy=ENTROPY_THRESHOLD,
            sample_data=data,
        )
        self.assertTrue(self.detector.check(ev))

    def test_missing_entropy_is_ignored(self):
        ev = event(size=ENTROPY_HEADER_SIZE, entropy=None)
        self.assertFalse(self.detector.check(ev))

    def test_value_just_below_threshold_is_not_detected(self):
        data = bytes(range(128)) * 2
        detector = EntropyDetector(threshold=ENTROPY_THRESHOLD + 1e-9)
        ev = event(size=len(data), entropy=7.0, sample_data=data)
        self.assertFalse(detector.check(ev))

    def test_threshold_is_inclusive(self):
        data = bytes(range(128)) * 2
        ev = event(
            size=ENTROPY_HEADER_SIZE,
            entropy=ENTROPY_THRESHOLD,
            sample_data=data,
        )
        self.assertTrue(self.detector.check(ev))

    def test_value_above_threshold_is_detected(self):
        data = bytes(range(ENTROPY_HEADER_SIZE))
        ev = event(size=len(data), entropy=8.0, sample_data=data)
        self.assertTrue(self.detector.check(ev))

    def test_custom_limits_are_honored(self):
        detector = EntropyDetector(
            threshold=6.0,
            header_size=64,
            accumulation_size=64,
            min_sample_size=32,
        )
        self.assertTrue(
            detector.check(event(size=64, entropy=6.0, sample_data=bytes(range(64))))
        )
        self.assertFalse(detector.check(event(size=63, entropy=8.0)))

    def test_repeated_small_high_entropy_writes_are_eventually_detected(self):
        detector = EntropyDetector(
            threshold=7.0,
            header_size=256,
            accumulation_window_sec=1.0,
            accumulation_size=256,
        )

        data = bytes(range(256))
        detected = False
        last_event = None

        with patch(
            "guardfs.stage1.entropy.time.monotonic",
            side_effect=[0.0, 0.1, 0.2, 0.3],
        ):
            for offset in range(0, 256, 64):
                chunk = data[offset : offset + 64]

                last_event = event(
                    pid=1234,
                    path="/underlay/file.bin",
                    size=len(chunk),
                    off=offset,
                    entropy=shannon_entropy(chunk),
                    sample_data=chunk,
                )

                detected = detector.check(last_event)

        self.assertTrue(detected)
        self.assertIsNotNone(last_event)

        # 개별 64바이트 entropy가 아니라
        # 재구성된 256바이트 entropy가 저장되어야 한다.
        self.assertAlmostEqual(
            last_event.entropy,
            shannon_entropy(data),
            places=12,
        )

        self.assertEqual(last_event.entropy, 8.0)

    def test_partial_writes_are_isolated_by_pid_and_path(self):
        for offset in range(0, 192, 64):
            self.assertFalse(
                self.detector.check(
                    event(
                        pid=10,
                        path="/a",
                        size=64,
                        off=offset,
                        entropy=6.0,
                        sample_data=bytes(range(offset, offset + 64)),
                    )
                )
            )
        self.assertFalse(
            self.detector.check(
                event(pid=20, path="/a", size=64, sample_data=bytes(range(64)))
            )
        )
        self.assertFalse(
            self.detector.check(
                event(pid=10, path="/b", size=64, sample_data=bytes(range(64)))
            )
        )
        self.assertTrue(
            self.detector.check(
                event(
                    pid=10,
                    path="/a",
                    size=64,
                    off=192,
                    sample_data=bytes(range(192, 256)),
                )
            )
        )

    def test_completed_low_entropy_is_written_to_event(self):
        detector = EntropyDetector()
        data = b"A" * 256

        ev = event(
            size=len(data),
            off=0,
            entropy=shannon_entropy(data),
            sample_data=data,
        )

        detected = detector.check(ev)

        self.assertFalse(detected)
        self.assertEqual(ev.entropy, 0.0)

    def test_low_entropy_fragment_dilutes_partial_accumulation(self):
        path = "/underlay/reset.bin"
        self.assertFalse(
            self.detector.check(
                event(path=path, size=128, sample_data=bytes(range(128)))
            )
        )
        self.assertFalse(
            self.detector.check(
                event(path=path, size=64, off=128, sample_data=b"A" * 64)
            )
        )
        self.assertFalse(
            self.detector.check(
                event(
                    path=path,
                    size=64,
                    off=192,
                    sample_data=bytes(range(64)),
                )
            )
        )

    def test_expired_partial_accumulation_is_removed(self):
        path = "/underlay/expiry.bin"
        # 구현은 FsEvent.ts_ns가 아니라 monotonic()을 사용하므로
        # 테스트에서는 monotonic 시간을 직접 고정해야 한다.
        with patch(
            "guardfs.stage1.entropy.time.monotonic",
            side_effect=[0.0, ENTROPY_ACCUMULATION_WINDOW_SEC + 0.1],
        ):
            self.assertFalse(
                self.detector.check(
                    event(path=path, size=128, sample_data=bytes(range(128)))
                )
            )
            self.assertFalse(
                self.detector.check(
                    event(
                        path=path,
                        size=128,
                        off=128,
                        sample_data=bytes(range(128, 256)),
                    )
                )
            )

        # 첫 write가 만료되어 폐기되었으므로 두 번째 write만 남아야 한다.
        key = (1000, os.path.realpath(path), 0)
        state = self.detector._blocks.get(key)
        self.assertIsNotNone(state)
        self.assertEqual(state.present_count, 128)

    def test_large_write_clears_previous_partial_state(self):
        """큰 write 뒤에 이전 작은 write가 다음 판정에 섞이지 않아야 한다.

        큰 write가 즉시 판정되면 기존 accumulator도 삭제되어야 한다.
        """
        detector = EntropyDetector(accumulation_size=256)
        path = "/underlay/large-write-reset.bin"

        with patch(
            "guardfs.stage1.entropy.time.monotonic",
            side_effect=[0.0, 0.1, 0.2],
        ):
            # 이전 작은 write를 누적한다.
            self.assertFalse(
                detector.check(
                    event(path=path, size=128, sample_data=bytes(range(128)))
                )
            )

            # 큰 write는 즉시 판정되고, 기존 누적 상태를 끊어야 한다.
            self.assertFalse(
                detector.check(event(path=path, size=256, sample_data=b"A" * 256))
            )

            # 이전 128B가 남아 있다면 이 write와 합쳐져 잘못 탐지된다.
            self.assertFalse(
                detector.check(
                    event(path=path, size=128, sample_data=bytes(range(128)))
                )
            )

    def test_accumulator_is_removed_after_non_detection_evaluation(self):
        """누적 크기에 도달해 판정한 뒤에는 상태가 다음 흐름으로 넘어가면 안 된다."""
        detector = EntropyDetector(accumulation_size=256)
        path = "/underlay/non-detected-evaluation.bin"

        with patch(
            "guardfs.stage1.entropy.time.monotonic",
            side_effect=[0.0, 0.1, 0.2, 0.3],
        ):
            for offset in range(0, 256, 64):
                self.assertFalse(
                    detector.check(
                        event(
                            path=path,
                            size=64,
                            off=offset,
                            sample_data=b"A" * 64,
                        )
                    )
                )

        key = (1000, os.path.realpath(path), 0)
        self.assertNotIn(key, detector._blocks)

    def test_repeated_same_offset_does_not_complete_header(self):
        chunk = bytes(range(64))

        for _ in range(4):
            self.assertFalse(
                self.detector.check(event(size=64, off=0, sample_data=chunk))
            )

        key = (1000, os.path.realpath("/underlay/document.txt"), 0)
        self.assertEqual(self.detector._blocks[key].present_count, 64)

    def test_out_of_order_writes_are_reassembled(self):
        data = bytes(range(256))
        detected = False

        for offset in (192, 128, 64, 0):
            detected = self.detector.check(
                event(
                    size=64,
                    off=offset,
                    sample_data=data[offset : offset + 64],
                )
            )

        self.assertTrue(detected)

    def test_write_outside_header_is_examined(self):
        data = bytes(range(256))
        ev = event(size=256, off=256, sample_data=data)

        self.assertTrue(self.detector.check(ev))
        self.assertEqual(ev.entropy, 8.0)

    def test_invalid_configuration_is_rejected(self):
        invalid_arguments = (
            {"threshold": -0.1},
            {"threshold": 8.1},
            {"header_size": 0},
            {"accumulation_window_sec": 0},
            {"accumulation_size": 0},
            {"header_size": 64, "accumulation_size": 65},
            {"min_sample_size": 0},
            {"min_sample_size": ENTROPY_ACCUMULATION_SIZE},
            {"short_sample_threshold": -0.1},
            {"short_sample_threshold": 8.1},
        )

        for arguments in invalid_arguments:
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    EntropyDetector(**arguments)

    def test_release_detects_short_high_entropy_file(self):
        path = "/underlay/short.bin"
        data = bytes(range(ENTROPY_MIN_SAMPLE_SIZE))

        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=path,
                    size=len(data),
                    off=0,
                    sample_data=data,
                )
            )
        )

        release_event = event(
            pid=1234,
            op="release",
            path=path,
            size=len(data),
        )

        self.assertTrue(self.detector.check(release_event))
        self.assertEqual(release_event.entropy, 7.0)

    def test_release_ignores_sample_below_minimum_size(self):
        path = "/underlay/tiny.bin"
        data = bytes(range(ENTROPY_MIN_SAMPLE_SIZE - 1))

        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=path,
                    size=len(data),
                    off=0,
                    sample_data=data,
                )
            )
        )

        release_event = event(
            pid=1234,
            op="release",
            path=path,
            size=len(data),
        )

        self.assertFalse(self.detector.check(release_event))
        self.assertIsNone(release_event.entropy)

    def test_release_ignores_short_low_entropy_file(self):
        path = "/underlay/short.txt"
        data = b"A" * ENTROPY_MIN_SAMPLE_SIZE

        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=path,
                    size=len(data),
                    off=0,
                    sample_data=data,
                )
            )
        )

        release_event = event(
            pid=1234,
            op="release",
            path=path,
            size=len(data),
        )

        self.assertFalse(self.detector.check(release_event))
        self.assertEqual(release_event.entropy, 0.0)

    def test_release_does_not_finalize_partial_sample_from_large_file(self):
        path = "/underlay/large.bin"
        data = bytes(range(ENTROPY_MIN_SAMPLE_SIZE))

        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=path,
                    size=len(data),
                    off=0,
                    sample_data=data,
                )
            )
        )

        release_event = event(
            pid=1234,
            op="release",
            path=path,
            size=4096,
        )

        self.assertFalse(self.detector.check(release_event))
        self.assertIsNone(release_event.entropy)

    def test_release_requires_a_contiguous_prefix(self):
        path = "/underlay/gapped.bin"

        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=path,
                    size=64,
                    off=0,
                    sample_data=bytes(range(64)),
                )
            )
        )
        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=path,
                    size=64,
                    off=128,
                    sample_data=bytes(range(128, 192)),
                )
            )
        )

        release_event = event(
            pid=1234,
            op="release",
            path=path,
            size=192,
        )

        self.assertFalse(self.detector.check(release_event))
        self.assertIsNone(release_event.entropy)

    def test_release_requires_the_complete_short_file(self):
        path = "/underlay/partially-observed-short.bin"
        observed_data = bytes(range(ENTROPY_MIN_SAMPLE_SIZE))
        actual_file_size = ENTROPY_MIN_SAMPLE_SIZE + 64

        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=path,
                    size=len(observed_data),
                    off=0,
                    sample_data=observed_data,
                )
            )
        )

        release_event = event(
            pid=1234,
            op="release",
            path=path,
            size=actual_file_size,
        )

        self.assertFalse(self.detector.check(release_event))
        self.assertIsNone(release_event.entropy)

    def test_discard_removes_only_matching_accumulator(self):
        target_path = "/underlay/target.bin"
        other_path = "/underlay/other.bin"

        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=target_path,
                    size=128,
                    off=0,
                    sample_data=bytes(range(128)),
                )
            )
        )
        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=other_path,
                    size=128,
                    off=0,
                    sample_data=bytes(range(128)),
                )
            )
        )

        self.detector.discard(pid=1234, path=target_path)

        target_key = (1234, os.path.realpath(target_path), 0)
        other_key = (1234, os.path.realpath(other_path), 0)
        self.assertNotIn(target_key, self.detector._blocks)
        self.assertIn(other_key, self.detector._blocks)

    def test_discard_missing_accumulator_is_safe(self):
        self.detector.discard(pid=1234, path="/underlay/missing.bin")
        self.assertEqual(self.detector._blocks, {})

    def test_move_transfers_accumulator_to_new_path(self):
        old_path = "/underlay/old.bin"
        new_path = "/underlay/new.bin"

        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=old_path,
                    size=128,
                    off=0,
                    sample_data=bytes(range(128)),
                )
            )
        )

        old_key = (1234, os.path.realpath(old_path), 0)
        new_key = (1234, os.path.realpath(new_path), 0)
        original_state = self.detector._blocks[old_key]

        self.detector.move(
            pid=1234,
            old_path=old_path,
            new_path=new_path,
        )

        self.assertNotIn(old_key, self.detector._blocks)
        self.assertIs(self.detector._blocks[new_key], original_state)

    def test_move_replaces_existing_destination_accumulator(self):
        old_path = "/underlay/old.bin"
        new_path = "/underlay/new.bin"

        for path in (old_path, new_path):
            self.assertFalse(
                self.detector.check(
                    event(
                        pid=1234,
                        path=path,
                        size=64,
                        off=0,
                        sample_data=bytes(range(64)),
                    )
                )
            )

        old_key = (1234, os.path.realpath(old_path), 0)
        new_key = (1234, os.path.realpath(new_path), 0)
        source_state = self.detector._blocks[old_key]
        destination_state = self.detector._blocks[new_key]

        self.detector.move(1234, old_path, new_path)

        self.assertIs(self.detector._blocks[new_key], source_state)
        self.assertIsNot(self.detector._blocks[new_key], destination_state)

    def test_partial_accumulation_continues_after_move(self):
        old_path = "/underlay/old.bin"
        new_path = "/underlay/new.bin"
        data = bytes(range(256))

        self.assertFalse(
            self.detector.check(
                event(
                    pid=1234,
                    path=old_path,
                    size=128,
                    off=0,
                    sample_data=data[:128],
                )
            )
        )

        self.detector.move(1234, old_path, new_path)

        final_event = event(
            pid=1234,
            path=new_path,
            size=128,
            off=128,
            sample_data=data[128:],
        )
        self.assertTrue(self.detector.check(final_event))
        self.assertEqual(final_event.entropy, 8.0)


class ExtensionChangeDetectorTests(unittest.TestCase):
    """확장자 변경의 즉시 탐지와 PID별 시간 창 누적을 검사"""

    def rename_event(
        self,
        old: str,
        new: str | None,
        *,
        pid: int = 1000,
        op: str = "rename",
    ) -> FakeEvent:
        return event(pid=pid, op=op, path=old, new_path=new)

    def test_default_window_follows_common_config(self):
        detector = ExtChangeDetector()
        self.assertEqual(detector.window_sec, EXT_CHANGE_WINDOW_SEC)

    def test_default_threshold_follows_common_config(self):
        """알려진 결함: 현재 기본 threshold가 window 값에 잘못 연결됨 (해결)"""

        detector = ExtChangeDetector()
        self.assertEqual(detector.threshold, EXT_CHANGE_THRESHOLD)

    def test_non_rename_operation_is_ignored(self):
        detector = ExtChangeDetector(threshold=1)
        ev = self.rename_event("a.txt", "a.enc", op="write")
        self.assertFalse(detector.check(ev))

    def test_rename_without_destination_is_ignored(self):
        detector = ExtChangeDetector(threshold=1)
        self.assertFalse(detector.check(self.rename_event("a.txt", None)))

    def test_same_extension_is_ignored(self):
        detector = ExtChangeDetector(threshold=1)
        self.assertFalse(detector.check(self.rename_event("a.txt", "b.txt")))

    def test_extension_comparison_is_case_insensitive(self):
        detector = ExtChangeDetector(threshold=1)
        self.assertFalse(detector.check(self.rename_event("a.TXT", "b.txt")))

    def test_blacklisted_extension_is_detected_immediately(self):
        detector = ExtChangeDetector(threshold=999)
        for extension in (".enc", ".locked", ".wnry", ".payload"):
            with self.subTest(extension=extension):
                ev = self.rename_event("report.txt", f"report{extension}")
                self.assertTrue(detector.check(ev))

    def test_blacklisted_extension_is_case_insensitive(self):
        detector = ExtChangeDetector(threshold=999)
        self.assertTrue(detector.check(self.rename_event("a.txt", "a.ENC")))

    def test_suspicious_double_extension_is_detected_immediately(self):
        detector = ExtChangeDetector(threshold=999)
        self.assertTrue(
            detector.check(self.rename_event("report.pdf", "report.pdf.exe"))
        )

    def test_new_double_extension_is_detected_when_final_extension_is_unchanged(self):
        detector = ExtChangeDetector(threshold=999)
        self.assertTrue(
            detector.check(self.rename_event("report.exe", "report.pdf.exe"))
        )

    def test_existing_double_extension_is_not_detected_again(self):
        detector = ExtChangeDetector(threshold=999)
        self.assertFalse(
            detector.check(self.rename_event("report.pdf.exe", "renamed.pdf.exe"))
        )

    def test_normal_to_normal_change_is_not_detected(self):
        detector = ExtChangeDetector(threshold=1)
        self.assertFalse(detector.check(self.rename_event("a.txt", "a.pdf")))

    def test_unknown_to_unknown_change_is_not_counted(self):
        detector = ExtChangeDetector(threshold=1)
        self.assertFalse(detector.check(self.rename_event("a.foo", "a.bar")))
        self.assertEqual(detector.history, {})

    def test_unknown_extension_detects_exactly_at_threshold(self):
        detector = ExtChangeDetector(window_sec=10, threshold=3)
        with patch(
            "guardfs.stage1.ext_change.time.monotonic",
            side_effect=[1.0, 2.0, 3.0],
        ):
            self.assertFalse(detector.check(self.rename_event("a.txt", "a.x1")))
            self.assertFalse(detector.check(self.rename_event("b.txt", "b.x2")))
            self.assertTrue(detector.check(self.rename_event("c.txt", "c.x3")))
        self.assertNotIn(1000, detector.history)

    def test_same_path_does_not_fill_distinct_path_threshold(self):
        detector = ExtChangeDetector(window_sec=10, threshold=2)
        with patch(
            "guardfs.stage1.ext_change.time.monotonic",
            side_effect=[1.0, 2.0],
        ):
            self.assertFalse(detector.check(self.rename_event("a.txt", "a.x")))
            self.assertFalse(detector.check(self.rename_event("a.txt", "a.y")))

    def test_counts_are_isolated_by_pid(self):
        detector = ExtChangeDetector(window_sec=10, threshold=2)
        with patch(
            "guardfs.stage1.ext_change.time.monotonic",
            side_effect=[1.0, 2.0, 3.0],
        ):
            self.assertFalse(detector.check(self.rename_event("a.txt", "a.x", pid=10)))
            self.assertFalse(detector.check(self.rename_event("b.txt", "b.x", pid=20)))
            self.assertTrue(detector.check(self.rename_event("c.txt", "c.x", pid=10)))

    def test_expired_events_do_not_contribute(self):
        detector = ExtChangeDetector(window_sec=10, threshold=2)
        with patch(
            "guardfs.stage1.ext_change.time.monotonic",
            side_effect=[1.0, 12.1],
        ):
            self.assertFalse(detector.check(self.rename_event("a.txt", "a.x")))
            self.assertFalse(detector.check(self.rename_event("b.txt", "b.y")))
        self.assertEqual(len(detector.history[1000]), 1)

    def test_event_on_window_boundary_still_contributes(self):
        detector = ExtChangeDetector(window_sec=10, threshold=2)
        with patch(
            "guardfs.stage1.ext_change.time.monotonic",
            side_effect=[1.0, 11.0],
        ):
            self.assertFalse(detector.check(self.rename_event("a.txt", "a.x")))
            self.assertTrue(detector.check(self.rename_event("b.txt", "b.y")))

    def test_zero_threshold_is_rejected(self):
        with self.assertRaises(ValueError):
            ExtChangeDetector(threshold=0)

    def test_zero_window_is_rejected(self):
        with self.assertRaises(ValueError):
            ExtChangeDetector(window_sec=0)

    def test_extension_removal_contributes_to_threshold(self):
        detector = ExtChangeDetector(threshold=1)
        self.assertTrue(detector.check(self.rename_event("report.txt", "report")))

    def test_path_with_multiple_dots_uses_last_extension(self):
        detector = ExtChangeDetector(threshold=1)
        self.assertTrue(
            detector.check(
                self.rename_event("archive.backup.txt", "archive.backup.enc")
            )
        )


class HoneypotDetectorTests(unittest.TestCase):
    """honeypot 포함 관계가 문자열 prefix가 아닌 실제 경계로 판정되는지 검사"""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.root = Path(self.tempdir.name)
        self.honeypot = self.root / "honeypot"
        self.honeypot.mkdir()
        self.detector = HoneypotDetector(str(self.honeypot))

    def tearDown(self):
        self.tempdir.cleanup()

    def test_exact_honeypot_directory_is_detected(self):
        self.assertTrue(
            self.detector.check(event(op="lookup", path=str(self.honeypot)))
        )

    def test_supported_operations_inside_honeypot_are_detected(self):
        target = str(self.honeypot / "bait.txt")
        for op in (
            "open",
            "read",
            "write",
            "lookup",
            "create",
            "mkdir",
            "truncate",
            "ftruncate",
            "rename",
            "unlink",
            "rmdir",
        ):
            with self.subTest(op=op):
                self.assertTrue(self.detector.check(event(op=op, path=target)))

    def test_unsupported_operations_are_ignored(self):
        target = str(self.honeypot / "bait.txt")
        for op in ("getattr", "readdir", "release"):
            with self.subTest(op=op):
                self.assertFalse(self.detector.check(event(op=op, path=target)))

    def test_similar_sibling_prefix_is_not_detected(self):
        sibling = self.root / "honeypot_backup" / "ordinary.txt"
        self.assertFalse(self.detector.check(event(op="open", path=str(sibling))))

    def test_parent_traversal_is_normalized(self):
        disguised = self.root / "ordinary" / ".." / "honeypot" / "bait.txt"
        self.assertTrue(self.detector.check(event(op="read", path=str(disguised))))

    def test_rename_destination_inside_honeypot_is_detected(self):
        ev = event(
            op="rename",
            path=str(self.root / "normal.txt"),
            new_path=str(self.honeypot / "bait.txt"),
        )
        self.assertTrue(self.detector.check(ev))

    def test_rename_from_honeypot_is_detected(self):
        ev = event(
            op="rename",
            path=str(self.honeypot / "bait.txt"),
            new_path=str(self.root / "stolen.txt"),
        )
        self.assertTrue(self.detector.check(ev))

    def test_rename_completely_outside_is_not_detected(self):
        ev = event(
            op="rename",
            path=str(self.root / "a.txt"),
            new_path=str(self.root / "b.txt"),
        )
        self.assertFalse(self.detector.check(ev))

    def test_symlink_that_resolves_into_honeypot_is_detected(self):
        bait = self.honeypot / "bait.txt"
        bait.write_bytes(b"bait")
        link = self.root / "bait-link"
        try:
            link.symlink_to(bait)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        self.assertTrue(self.detector.check(event(op="read", path=str(link))))

    def test_symlink_inside_honeypot_that_escapes_is_not_detected(self):
        outside = self.root / "outside.txt"
        outside.write_bytes(b"safe")
        link = self.honeypot / "outside-link"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError) as exc:
            self.skipTest(f"symlink creation unavailable: {exc}")
        self.assertFalse(self.detector.check(event(op="read", path=str(link))))


class Stage1IntegrationTests(unittest.TestCase):
    """세 detector를 묶은 Stage1Detector의 반환 계약과 순서를 검사"""

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory()
        self.honeypot = Path(self.tempdir.name) / "honeypot"
        self.honeypot.mkdir()
        self.detector = Stage1Detector(str(self.honeypot))

    def tearDown(self):
        self.tempdir.cleanup()

    def test_benign_event_returns_false_and_no_reason(self):
        result = run_check(
            self.detector,
            event(op="read", path=str(Path(self.tempdir.name) / "normal.txt")),
        )
        self.assertEqual(result, (False, None))

    def test_entropy_detection_reports_detector_name(self):
        result = run_check(
            self.detector,
            event(
                size=ENTROPY_HEADER_SIZE,
                entropy=8.0,
                sample_data=bytes(range(ENTROPY_HEADER_SIZE)),
            ),
        )
        self.assertEqual(result, (True, "EntropyDetector"))

    def test_extension_detection_reports_detector_name(self):
        result = run_check(
            self.detector,
            event(op="rename", path="a.txt", new_path="a.enc"),
        )
        self.assertEqual(result, (True, "ExtChangeDetector"))

    def test_honeypot_detection_reports_detector_name(self):
        result = run_check(
            self.detector,
            event(op="read", path=str(self.honeypot / "bait.txt")),
        )
        self.assertEqual(result, (True, "HoneypotDetector"))

    def test_first_matching_detector_determines_reason(self):
        # honeypot write이면서 entropy도 높지만 등록 순서상 HoneypotDetector가 우선
        result = run_check(
            self.detector,
            event(
                op="write",
                path=str(self.honeypot / "bait.bin"),
                size=ENTROPY_HEADER_SIZE,
                entropy=8.0,
            ),
        )
        self.assertEqual(result, (True, "HoneypotDetector"))

    def test_successful_terminal_operations_discard_entropy_state(self):
        for op in ("unlink", "truncate", "ftruncate"):
            with self.subTest(op=op):
                detector = Stage1Detector(str(self.honeypot))
                path = str(Path(self.tempdir.name) / f"{op}.bin")
                key = (1234, os.path.realpath(path), 0)

                self.assertEqual(
                    run_check(
                        detector,
                        event(
                            pid=1234,
                            path=path,
                            size=128,
                            off=0,
                            sample_data=bytes(range(128)),
                        ),
                    ),
                    (False, None),
                )
                self.assertIn(key, detector.entropy._blocks)

                detector.update_lifecycle(
                    event(
                        pid=1234,
                        op=op,
                        path=path,
                        applied=True,
                    )
                )

                self.assertNotIn(key, detector.entropy._blocks)

    def test_release_is_finalized_instead_of_discarded_by_lifecycle(self):
        path = str(Path(self.tempdir.name) / "short.bin")
        data = bytes(range(ENTROPY_MIN_SAMPLE_SIZE))
        key = (1234, os.path.realpath(path), 0)

        self.assertEqual(
            run_check(
                self.detector,
                event(
                    pid=1234,
                    path=path,
                    size=len(data),
                    off=0,
                    sample_data=data,
                ),
            ),
            (False, None),
        )

        release_event = event(
            pid=1234,
            op="release",
            path=path,
            size=len(data),
            applied=True,
        )

        self.detector.update_lifecycle(release_event)
        self.assertIn(key, self.detector.entropy._blocks)

        self.assertEqual(
            run_check(self.detector, release_event),
            (True, "EntropyDetector"),
        )
        self.assertEqual(release_event.entropy, 7.0)
        self.assertNotIn(key, self.detector.entropy._blocks)

    def test_blocked_terminal_operation_preserves_entropy_state(self):
        path = str(Path(self.tempdir.name) / "blocked.bin")
        key = (1234, os.path.realpath(path), 0)

        self.assertEqual(
            run_check(
                self.detector,
                event(
                    pid=1234,
                    path=path,
                    size=128,
                    off=0,
                    sample_data=bytes(range(128)),
                ),
            ),
            (False, None),
        )

        self.detector.update_lifecycle(
            event(
                pid=1234,
                op="unlink",
                path=path,
                applied=False,
            )
        )

        self.assertIn(key, self.detector.entropy._blocks)

    def test_successful_rename_moves_entropy_state(self):
        old_path = str(Path(self.tempdir.name) / "old.bin")
        new_path = str(Path(self.tempdir.name) / "new.bin")
        old_key = (1234, os.path.realpath(old_path), 0)
        new_key = (1234, os.path.realpath(new_path), 0)

        self.assertEqual(
            run_check(
                self.detector,
                event(
                    pid=1234,
                    path=old_path,
                    size=128,
                    off=0,
                    sample_data=bytes(range(128)),
                ),
            ),
            (False, None),
        )

        self.detector.update_lifecycle(
            event(
                pid=1234,
                op="rename",
                path=old_path,
                new_path=new_path,
                applied=True,
            )
        )

        self.assertNotIn(old_key, self.detector.entropy._blocks)
        self.assertIn(new_key, self.detector.entropy._blocks)

    def test_blocked_rename_does_not_move_entropy_state(self):
        old_path = str(Path(self.tempdir.name) / "old.bin")
        new_path = str(Path(self.tempdir.name) / "old.enc")
        old_key = (1234, os.path.realpath(old_path), 0)
        new_key = (1234, os.path.realpath(new_path), 0)

        self.assertEqual(
            run_check(
                self.detector,
                event(
                    pid=1234,
                    path=old_path,
                    size=128,
                    off=0,
                    sample_data=bytes(range(128)),
                ),
            ),
            (False, None),
        )

        self.detector.update_lifecycle(
            event(
                pid=1234,
                op="rename",
                path=old_path,
                new_path=new_path,
                applied=False,
            )
        )

        self.assertIn(old_key, self.detector.entropy._blocks)
        self.assertNotIn(new_key, self.detector.entropy._blocks)


def build_suite(names: list[str]) -> unittest.TestSuite:
    """클래스명 또는 완전한 test id를 선택 실행할 수 있게 suite를 구성"""

    loader = unittest.defaultTestLoader
    if not names:
        return loader.loadTestsFromModule(sys.modules[__name__])

    normalized = []
    for name in names:
        if "." not in name:
            normalized.append(f"{__name__}.{name}")
        elif not name.startswith(f"{__name__}."):
            normalized.append(f"{__name__}.{name}")
        else:
            normalized.append(name)
    return loader.loadTestsFromNames(normalized)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="GuardFS Stage 1 경량 탐지 규칙 테스트",
    )
    parser.add_argument(
        "tests",
        nargs="*",
        help="선택 실행할 TestCase 클래스명 또는 test id",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="각 테스트 이름과 결과를 자세히 출력",
    )
    args = parser.parse_args()

    runner = unittest.TextTestRunner(verbosity=2 if args.verbose else 1)
    result = runner.run(build_suite(args.tests))

    print("\n[결과 해석]")
    print("  OK    : 현재 구현이 요구사항을 만족함")
    print("  FAIL  : 현재 구현의 결함 또는 요구사항 불일치")
    print("  ERROR : 테스트 실행 환경 또는 예외 처리 문제")
    print("  XFAIL : 알려진 탐지 공백이 현재도 재현됨")
    print("  XPASS : 알려진 공백이 해결됨; expectedFailure 표시 제거 필요")

    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
