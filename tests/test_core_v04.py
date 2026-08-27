import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from honey_agent_lab.cli import _is_loopback, main
from honey_agent_lab.models import Message, PolicyAction
from honey_agent_lab.orchestrator import run_scenario
from honey_agent_lab.risk import RiskScorer


class CoreRegressionTests(unittest.TestCase):
    def test_baselines(self):
        self.assertEqual(run_scenario("scenario_001").final_decision.action, PolicyAction.QUARANTINE)
        self.assertEqual(run_scenario("scenario_002").final_decision.action, PolicyAction.QUARANTINE)
        self.assertEqual(run_scenario("scenario_003").final_decision.action, PolicyAction.ISOLATE)
        self.assertEqual(run_scenario("scenario_004").final_decision.action, PolicyAction.ALLOW)

    def test_untrusted_auth_signal(self):
        assessment = RiskScorer().assess(Message("a", "b", "side-channel", "routine synthetic update"))
        self.assertIn("UNTRUSTED_TRANSPORT", assessment.triggered_codes)
        self.assertIn("NO_AUTHORIZATION_EVIDENCE", assessment.triggered_codes)

    def test_boundary(self):
        assessment = RiskScorer().assess(Message("a", "b", "authorized-bus", "alongside channel review"))
        self.assertNotIn("UNAUTHORIZED_CHANNEL", assessment.triggered_codes)

    def test_cli_fuzz_json(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(["fuzz", "--limit", "5", "--seed", "1", "--json"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["total_messages"], 5)

    def test_cli_rules_and_html(self):
        with tempfile.TemporaryDirectory() as directory:
            html = Path(directory) / "x.html"
            self.assertEqual(main(["run-scenario", "scenario_001", "--output-html", str(html)]), 0)
            self.assertIn("Risk findings", html.read_text(encoding="utf-8"))

    def test_loopback_guard(self):
        self.assertTrue(_is_loopback("127.0.0.1"))
        self.assertTrue(_is_loopback("::1"))
        self.assertTrue(_is_loopback("localhost"))
        self.assertFalse(_is_loopback("0.0.0.0"))

    def test_serve_refusal(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            status = main(["serve", "--host", "0.0.0.0"])
        self.assertEqual(status, 2)
        self.assertIn("Refusing", error.getvalue())

    def test_reload_refused_for_remote_even_when_allowed(self):
        error = io.StringIO()
        with contextlib.redirect_stderr(error):
            status = main(["serve", "--host", "0.0.0.0", "--allow-remote", "--reload"])
        self.assertEqual(status, 2)
        self.assertIn("reload", error.getvalue())


if __name__ == "__main__":
    unittest.main()
