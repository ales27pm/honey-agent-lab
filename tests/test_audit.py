import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

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

    def test_tampering_is_detected_without_mutable_event(self):
        ledger = AppendOnlyAuditLedger()
        ledger.record("event", {"value": "x"})
        ledger._events[0] = replace(ledger.events[0], payload={"value": "tampered"})
        self.assertFalse(ledger.verify_integrity())

    def test_write_and_read_jsonl(self):
        ledger = AppendOnlyAuditLedger()
        ledger.record("event", {"value": "x"})
        with tempfile.TemporaryDirectory() as tmp:
            path = ledger.write_jsonl(Path(tmp) / "audit.jsonl")
            loaded = AppendOnlyAuditLedger.read_jsonl(path)
        self.assertTrue(loaded.verify_integrity())
        self.assertEqual(loaded.events, ledger.events)

    def test_persistent_ledger_continues_existing_chain(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.jsonl"
            first = AppendOnlyAuditLedger(path)
            first.record("one", {"value": 1})
            second = AppendOnlyAuditLedger(path)
            second.record("two", {"value": 2})
            self.assertEqual(len(second.events), 2)
            self.assertTrue(second.verify_integrity())

    def test_unsupported_payload_type_fails_closed(self):
        ledger = AppendOnlyAuditLedger()
        with self.assertRaises(TypeError):
            ledger.record("bad", object())


if __name__ == "__main__":
    unittest.main()
