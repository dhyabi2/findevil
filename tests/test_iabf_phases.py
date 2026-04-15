"""Unit tests for the IABF 4-phase loop using FakeLLMClient.

These tests exercise each phase independently with scripted LLM responses and
dry-run tool execution. They run offline (no OpenRouter, no subprocess).
"""

import json
import tempfile
import unittest
from pathlib import Path

from agent.iabf import IABFAgent, Hypothesis
from agent.llm_client import FakeLLMClient


CONFIG_PATH = str(Path(__file__).parent.parent / "config.yaml")


def make_agent(script):
    """Build an IABFAgent with a FakeLLMClient and dry-run tool execution."""
    with tempfile.TemporaryDirectory() as _:
        pass  # just get a fresh tmp; AuditTrail uses its own ./logs
    return IABFAgent(
        config_path=CONFIG_PATH,
        llm=FakeLLMClient(script),
        dry_run=True,
    )


class TestPhase1Narrative(unittest.TestCase):

    def test_narrative_stored_and_returned(self):
        agent = make_agent(["NARRATIVE: user ran powershell. KEY UNKNOWNS: target."])
        narrative = agent.phase1_narrative("EDR alert: powershell.exe spawned cmd.exe")
        self.assertIn("NARRATIVE", narrative)
        self.assertEqual(agent.state.narrative, narrative)

    def test_narrative_update_uses_prior_state(self):
        agent = make_agent([
            "NARRATIVE: initial.",
            "NARRATIVE: updated after evidence.",
        ])
        agent.phase1_narrative("alert A")
        agent.state.iteration = 1
        # Seed a prior assistant turn so the "update" branch has something to reference.
        agent._conversation.append({"role": "user", "content": "ignored"})
        agent._conversation.append({"role": "assistant", "content": "prior finding"})
        updated = agent.phase1_narrative("alert A")
        self.assertIn("updated", updated)


class TestPhase2Hypotheses(unittest.TestCase):

    def test_hypotheses_parsed_from_json(self):
        agent = make_agent([{
            "hypotheses": [
                {"description": "Credential dumping",
                 "mitre_technique": "T1003 - OS Credential Dumping",
                 "confidence": 0.8,
                 "investigation_plan": "grep lsass",
                 "tool_commands": ["echo test"]},
                {"description": "Lateral movement",
                 "mitre_technique": "T1021 - Remote Services",
                 "confidence": 0.4,
                 "tool_commands": ["echo test2"]},
            ]
        }])
        hyps = agent.phase2_hypotheses()
        self.assertEqual(len(hyps), 2)
        self.assertEqual(hyps[0].mitre_technique, "T1003 - OS Credential Dumping")
        self.assertAlmostEqual(hyps[0].confidence, 0.8)
        self.assertIn("echo test", hyps[0].tool_commands)

    def test_empty_hypotheses_returns_empty(self):
        agent = make_agent([{"hypotheses": []}])
        hyps = agent.phase2_hypotheses()
        self.assertEqual(hyps, [])


class TestPhase3Investigate(unittest.TestCase):

    def test_confirmed_verdict_updates_state(self):
        agent = make_agent([{
            "verdict": "confirmed",
            "confidence_after": 0.95,
            "evidence_for": ["artifact X"],
            "evidence_against": [],
        }])
        h = Hypothesis(id="H0_0", description="Test hyp",
                       tool_commands=["echo probe"], confidence=0.6)
        result = agent.phase3_investigate(h)
        self.assertEqual(result["verdict"], "confirmed")
        self.assertEqual(h.status, "confirmed")
        self.assertIn("Test hyp", agent.state.confirmed_findings)
        self.assertAlmostEqual(h.confidence, 0.95)

    def test_disproved_verdict_updates_state(self):
        agent = make_agent([{
            "verdict": "disproved",
            "confidence_after": 0.05,
            "evidence_for": [],
            "evidence_against": ["no artifact"],
        }])
        h = Hypothesis(id="H0_0", description="Wrong hyp",
                       tool_commands=["echo probe"], confidence=0.6)
        agent.phase3_investigate(h)
        self.assertEqual(h.status, "disproved")
        self.assertIn("Wrong hyp", agent.state.disproved_assumptions)

    def test_dry_run_skips_real_exec(self):
        agent = make_agent([{"verdict": "inconclusive", "confidence_after": 0.5}])
        # `ls` is on the binary whitelist; in dry_run, no subprocess is spawned
        # and a synthetic output is returned with exit 0.
        code, out = agent._exec_tool("ls /cases")
        self.assertEqual(code, 0)
        self.assertIn("DRY-RUN", out)

    def test_guardrails_still_block_in_dry_run(self):
        """Dry-run must NOT bypass security guardrails."""
        agent = make_agent([])
        code, out = agent._exec_tool("rm -rf /")
        self.assertEqual(code, -1)
        self.assertIn("BLOCKED", out)


class TestPhase4Feedback(unittest.TestCase):

    def test_root_cause_detected(self):
        agent = make_agent([{
            "narrative_update": "Root cause found.",
            "root_cause_reached": True,
            "root_cause": "Phishing -> credential theft -> lateral move",
            "confidence_in_root_cause": 0.92,
            "investigation_complete": True,
        }])
        out = agent.phase4_feedback([{"hypothesis": "H0", "result": {"verdict": "confirmed"}}])
        parsed = json.loads(out)
        self.assertTrue(parsed["root_cause_reached"])
        self.assertEqual(agent.state.root_cause,
                         "Phishing -> credential theft -> lateral move")


class TestFullLoop(unittest.TestCase):

    def test_minimal_end_to_end_dry_run(self):
        """Drives phase1 -> phase2 -> phase3 -> phase4 through investigate()."""
        script = [
            "NARRATIVE: suspicious activity. KEY UNKNOWNS: root cause.",
            {"hypotheses": [{
                "description": "Test hypothesis",
                "mitre_technique": "T1000 - Test",
                "confidence": 0.8,
                "tool_commands": ["echo probe"],
            }]},
            {"verdict": "confirmed", "confidence_after": 0.95,
             "evidence_for": ["synthetic evidence"]},
            {"narrative_update": "Done.",
             "root_cause_reached": True,
             "root_cause": "Synthetic root cause",
             "confidence_in_root_cause": 0.95,
             "investigation_complete": True},
        ]
        agent = IABFAgent(config_path=CONFIG_PATH,
                          llm=FakeLLMClient(script),
                          dry_run=True)
        report = agent.investigate("Scripted test incident", evidence_paths=[])
        self.assertEqual(report["root_cause"], "Synthetic root cause")
        self.assertGreaterEqual(len(report["confirmed_findings"]), 1)
        self.assertEqual(report["total_iterations"], 1)


if __name__ == "__main__":
    unittest.main()
