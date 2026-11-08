"""임시 파일을 사용한 원본 내용 비교 검사."""

import tempfile
import unittest
from pathlib import Path

from experiments.simulators.sim_scn_icefire import document_bytes
from scenarios.verify_icefire import compare_documents


class DocumentVerificationTests(unittest.TestCase):
    def test_full_content_comparison_detects_changes_and_missing_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            mount, underlay = root / "mount", root / "underlay"
            workspace = "s01_" + "a" * 32
            for side in (mount, underlay):
                (side / workspace).mkdir(parents=True)
                for i in range(10):
                    name = f"doc_{i:03d}{('.docx', '.pdf', '.xlsx')[i % 3]}"
                    (side / workspace / name).write_bytes(document_bytes(name, 64 * 1024))
            results = compare_documents(mount, underlay, workspace)
            self.assertEqual(len(results), 10)
            self.assertTrue(all(item["mount"] == item["underlay"] == "matched" for item in results))
            path = mount / workspace / "doc_000.docx"
            body = bytearray(path.read_bytes())
            body[-1] ^= 1
            path.write_bytes(body)
            (underlay / workspace / "doc_001.pdf").unlink()
            results = compare_documents(mount, underlay, workspace)
            self.assertEqual(results[0]["mount"], "changed")
            self.assertEqual(results[0]["underlay"], "matched")
            self.assertEqual(results[1]["underlay"], "missing")


if __name__ == "__main__":
    unittest.main()
