import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from honey_agent_lab.cli import main


class CliTests(unittest.TestCase):
    def test_list_scenarios(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["list-scenarios"])
        self.assertEqual(status, 0)
        self.assertIn("scenario_001", output.getvalue())

    def test_run_scenario_json(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["run-scenario", "scenario_001", "--json"])
        self.assertEqual(status, 0)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["final"]["action"], "quarantine")
        self.assertTrue(payload["ledger_integrity"])

    def test_export_audit_and_verify(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main(["run-scenario", "scenario_001", "--export-audit", str(path)]), 0)
            self.assertTrue(path.exists())
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(main(["verify-audit", str(path)]), 0)
            self.assertIn("Audit integrity: True", output.getvalue())

    def test_output_html_contains_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "dashboard.html"
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                status = main(["run-scenario", "scenario_001", "--output-html", str(path)])
            self.assertEqual(status, 0)
            text = path.read_text(encoding="utf-8")
            self.assertIn("Risk findings", text)
            self.assertIn("LOG_SUPPRESSION", text)

    def test_unknown_scenario_returns_2(self):
        err = io.StringIO()
        with redirect_stderr(err):
            status = main(["run-scenario", "missing"])
        self.assertEqual(status, 2)
        self.assertIn("Unknown scenario", err.getvalue())


if __name__ == "__main__":
    unittest.main()
