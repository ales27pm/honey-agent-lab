from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .models import utc_now_iso

GENESIS_HASH = "0" * 64


def _jsonable(value: Any) -> Any:
    if hasattr(value, "to_dict"):
        return value.to_dict()
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [_jsonable(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


@dataclass
class LedgerEvent:
    index: int
    timestamp: str
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str

    def hash_source(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "payload": self.payload,
            "previous_hash": self.previous_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            **self.hash_source(),
            "event_hash": self.event_hash,
        }


class AppendOnlyAuditLedger:
    """Hash-chained append-only event ledger for simulations.

    This is not a blockchain and does not claim tamper-proof storage. It makes
    accidental or local in-memory tampering detectable during tests and exports.
    """

    def __init__(self) -> None:
        self._events: list[LedgerEvent] = []

    @property
    def events(self) -> tuple[LedgerEvent, ...]:
        return tuple(self._events)

    def record(self, event_type: str, payload: dict[str, Any] | Any) -> LedgerEvent:
        clean_payload = _jsonable(payload)
        if not isinstance(clean_payload, dict):
            clean_payload = {"value": clean_payload}

        previous_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
        event = LedgerEvent(
            index=len(self._events),
            timestamp=utc_now_iso(),
            event_type=event_type,
            payload=clean_payload,
            previous_hash=previous_hash,
            event_hash="",
        )
        event.event_hash = self._hash(event.hash_source())
        self._events.append(event)
        return event

    def verify_integrity(self) -> bool:
        previous_hash = GENESIS_HASH
        for expected_index, event in enumerate(self._events):
            if event.index != expected_index:
                return False
            if event.previous_hash != previous_hash:
                return False
            if self._hash(event.hash_source()) != event.event_hash:
                return False
            previous_hash = event.event_hash
        return True

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(event.to_dict(), sort_keys=True) for event in self._events)

    def write_jsonl(self, path: str | Path) -> Path:
        output = Path(path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.to_jsonl() + ("\n" if self._events else ""), encoding="utf-8")
        return output

    @classmethod
    def from_events(cls, events: Iterable[LedgerEvent]) -> "AppendOnlyAuditLedger":
        ledger = cls()
        ledger._events.extend(events)
        return ledger

    @staticmethod
    def _hash(source: dict[str, Any]) -> str:
        data = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
