import unittest

from honey_agent_lab.fuzzer import ATTACK_FRAGMENTS, Fuzzer
from honey_agent_lab.models import Message


class FuzzerTests(unittest.TestCase):
    def test_deterministic_with_obfuscation(self):
        first = Fuzzer(7, max_fragments=3, obfuscation_probability=0.7).generate_messages(5)
        second = Fuzzer(7, max_fragments=3, obfuscation_probability=0.7).generate_messages(5)
        self.assertEqual([item.to_dict() for item in first], [item.to_dict() for item in second])

    def test_fragment_count_and_synthetic_metadata(self):
        for message in Fuzzer(1, max_fragments=4).generate_messages(20):
            self.assertIsInstance(message, Message)
            self.assertEqual(message.sender, "simulated-fuzzer")
            self.assertTrue(message.metadata["synthetic"])
            self.assertGreaterEqual(len(message.metadata["attack_fragments"]), 1)
            self.assertLessEqual(len(message.metadata["attack_fragments"]), 4)

    def test_case_obfuscation_remains_detectable(self):
        fuzzer = Fuzzer(1, obfuscation_probability=1.0)
        rendered = fuzzer._swap_case(ATTACK_FRAGMENTS[0])
        assessment = fuzzer.scorer.assess(
            Message("simulated-fuzzer", "honey-agent-01", "authorized-bus", rendered)
        )
        self.assertTrue(assessment.triggered_codes)

    def test_summary_consistent(self):
        summary = Fuzzer(3, max_fragments=3, obfuscation_probability=0.5).run(25)
        self.assertEqual(sum(summary.action_counts.values()), 25)
        self.assertEqual(sum(summary.severity_counts.values()), 25)
        self.assertEqual(summary.total_messages, 25)
        self.assertGreaterEqual(summary.obfuscated_messages, 0)
        self.assertLessEqual(summary.obfuscated_messages, 25)

    def test_invalid_controls_fail_closed(self):
        with self.assertRaises(ValueError):
            Fuzzer(max_fragments=0)
        with self.assertRaises(ValueError):
            Fuzzer(obfuscation_probability=1.1)


if __name__ == "__main__":
    unittest.main()
