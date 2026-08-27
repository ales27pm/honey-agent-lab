import tempfile
import unittest
from pathlib import Path

from honey_agent_lab.cli import main
from honey_agent_lab.fuzzer import FuzzSummary
from honey_agent_lab.fuzz_report import render_fuzz_report


class FuzzReportTests(unittest.TestCase):
    def test_render_escapes_content(self):
        summary = FuzzSummary(
            total_messages=1,
            action_counts={"warn<script>": 1},
            severity_counts={"medium": 1},
            triggered_codes={"TEST_SIGNAL": 1},
            potential_false_negatives=("msg_<script>",),
            obfuscated_messages=1,
        )
        html = render_fuzz_report(summary, title="Report <script>")
        self.assertNotIn("<script>", html)
        self.assertIn("&lt;script&gt;", html)

    def test_cli_writes_fuzz_report(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "fuzz.html"
            status = main(["fuzz", "--limit", "5", "--seed", "1", "--output-html", str(output)])
            self.assertEqual(status, 0)
            text = output.read_text(encoding="utf-8")
            self.assertIn("Total messages", text)
            self.assertIn("Action counts", text)
            self.assertIn("Potential false negatives", text)


if __name__ == "__main__":
    unittest.main()
