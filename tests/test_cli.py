import io
import json
import unittest
from contextlib import redirect_stdout

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


if __name__ == "__main__":
    unittest.main()
