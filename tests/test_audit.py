"""Tests for audit trail functionality."""

import json
import unittest
import tempfile
from pathlib import Path

from agent.audit import AuditTrail, HypothesisRecord


class TestAuditTrail(unittest.TestCase):

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.audit = AuditTrail(log_dir=self.tmpdir, session_id="test001")

    def test_session_id(self):
        self.assertEqual(self.audit.session_id, "test001")

    def test_log_file_created_on_emit(self):
        self.audit.log_narrative("Test narrative", 1)
        self.assertTrue(self.audit._log_file.exists())

    def test_jsonl_format(self):
        self.audit.log_narrative("Test narrative", 1)
        with open(self.audit._log_file) as f:
            line = f.readline()
        event = json.loads(line)
        self.assertEqual(event["event_type"], "narrative")
        self.assertEqual(event["session_id"], "test001")
        self.assertIn("timestamp", event)

    def test_tool_start_end(self):
        exec_id = self.audit.log_tool_start("fls", "fls -r /cases/test", ["-r", "/cases/test"])
        self.assertEqual(exec_id, "tool_0000")
        self.audit.log_tool_end(exec_id, 0, "file1.txt\nfile2.txt")
        record = self.audit._tool_executions[0]
        self.assertEqual(record.exit_code, 0)
        self.assertGreater(record.duration_ms, 0)

    def test_hypothesis_logging(self):
        h = HypothesisRecord(
            id="H1_0",
            iteration=1,
            hypothesis="Credential dumping via lsass",
            mitre_technique="T1003",
            confidence_before=0.7,
            status="pending",
        )
        self.audit.log_hypothesis(h)
        self.assertEqual(len(self.audit._hypotheses), 1)

    def test_self_correction_logging(self):
        self.audit.log_self_correction(
            original="Assumed lateral movement",
            corrected="Actually data exfiltration",
            reason="Network analysis showed outbound data",
        )
        with open(self.audit._log_file) as f:
            events = [json.loads(line) for line in f]
        self.assertEqual(events[-1]["event_type"], "self_correction")

    def test_export_session(self):
        self.audit.log_narrative("Test", 1)
        self.audit.log_llm_call("gemma-4", {"total_tokens": 100}, 500.0, "test")
        export = self.audit.export_session()
        self.assertEqual(export["session_id"], "test001")
        self.assertEqual(export["total_llm_calls"], 1)
        self.assertEqual(export["total_tokens"], 100)

    def test_save_report(self):
        self.audit.log_narrative("Test", 1)
        path = self.audit.save_report()
        self.assertTrue(path.exists())
        with open(path) as f:
            report = json.load(f)
        self.assertEqual(report["session_id"], "test001")


if __name__ == "__main__":
    unittest.main()
