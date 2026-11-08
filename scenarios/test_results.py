"""상세 결과의 부분 완료와 시간 초과 검증."""

import unittest

from scenarios.results import validate_result_details


class ResultDetailsTests(unittest.TestCase):
    def make_result(self, status="passed"):
        passed = status == "passed"
        return {
            "result_version": 2,
            "status": status,
            "termination_reason": {
                "passed": "completed",
                "failed": "operation_failed",
                "timed_out": "deadline_exceeded",
            }[status],
            "steps": [{
                "name": "WRITE",
                "status": "passed" if passed else "failed",
                "planned": 12,
                "attempted": 12 if passed else 3,
                "completed": 12 if passed else 2,
                "failure": None if passed else {
                    "operation": "write",
                    "path": "/runtime/mount/test/file.txt",
                    "errno": None,
                    "message": "작업을 완료하지 못했습니다.",
                },
            }],
        }

    def test_legacy_result_is_supported(self):
        validate_result_details({"status": "passed"})

    def test_completed_result(self):
        validate_result_details(self.make_result())

    def test_partial_failure_and_timeout(self):
        for status in ("failed", "timed_out"):
            with self.subTest(status=status):
                validate_result_details(self.make_result(status))

    def test_partial_completion_cannot_pass(self):
        result = self.make_result()
        result["steps"][0]["completed"] = 2
        with self.assertRaises(ValueError):
            validate_result_details(result)

    def test_invalid_counts_are_rejected(self):
        result = self.make_result("failed")
        result["steps"][0]["completed"] = 4
        with self.assertRaises(ValueError):
            validate_result_details(result)

    def test_wrong_termination_reason_is_rejected(self):
        result = self.make_result("timed_out")
        result["termination_reason"] = "completed"
        with self.assertRaises(ValueError):
            validate_result_details(result)

    def test_legacy_timeout_is_rejected(self):
        with self.assertRaises(ValueError):
            validate_result_details({"status": "timed_out"})


if __name__ == "__main__":
    unittest.main()
