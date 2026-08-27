import json
import unittest

from honey_agent_lab.audit import AppendOnlyAuditLedger


class AuditLedgerTests(unittest.TestCase):
    def test_ledger_preserves_order_and_verifies(self):
        ledger = AppendOnlyAuditLedger()
        first = ledger.record("first", {"value": 1})
        second = ledger.record("second", {"value": 2})

        self.assertEqual(first.index, 0)
        self.assertEqual(second.index, 1)
        self.assertEqual(second.previous_hash, first.event_hash)
        self.assertTrue(ledger.verify_integrity())

    def test_jsonl_export_contains_events(self):
        ledger = AppendOnlyAuditLedger()
        ledger.record("event", {"value": "x"})
        rows = [json.loads(line) for line in ledger.to_jsonl().splitlines()]
        self.assertEqual(rows[0]["event_type"], "event")
        self.assertIn("event_hash", rows[0])

    def test_tampering_is_detected(self):
        ledger = AppendOnlyAuditLedger()
        ledger.record("event", {"value": "x"})
        ledger.events[0].payload["value"] = "tampered"
        self.assertFalse(ledger.verify_integrity())


if __name__ == "__main__":
    unittest.main()
