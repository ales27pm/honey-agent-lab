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
        return _jsonable(value.to_dict())
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    if isinstance(value, set):
        return [_jsonable(item) for item in sorted(value, key=str)]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    raise TypeError(f"Unsupported audit payload type: {type(value).__name__}")


@dataclass(frozen=True)
class LedgerEvent:
    index: int
    timestamp: str
    event_type: str
    payload: dict[str, Any]
    previous_hash: str
    event_hash: str

    def hash_source(self) -> dict[str, Any]:
        return {"index": self.index, "timestamp": self.timestamp, "event_type": self.event_type,
                "payload": self.payload, "previous_hash": self.previous_hash}

    def to_dict(self) -> dict[str, Any]:
        return {**self.hash_source(), "event_hash": self.event_hash}

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "LedgerEvent":
        return cls(index=int(payload["index"]), timestamp=str(payload["timestamp"]),
                   event_type=str(payload["event_type"]), payload=dict(payload["payload"]),
                   previous_hash=str(payload["previous_hash"]), event_hash=str(payload["event_hash"]))


class AppendOnlyAuditLedger:
    """Hash-chained local audit ledger for defensive simulations."""

    def __init__(self, file_path: str | Path | None = None) -> None:
        self._events: list[LedgerEvent] = []
        self._file_path = Path(file_path) if file_path is not None else None
        if self._file_path and self._file_path.exists() and self._file_path.stat().st_size:
            loaded = self.read_jsonl(self._file_path)
            self._events.extend(loaded.events)
            if not self.verify_integrity():
                raise ValueError(f"Existing audit ledger failed integrity verification: {self._file_path}")

    @property
    def events(self) -> tuple[LedgerEvent, ...]:
        return tuple(self._events)

    def record(self, event_type: str, payload: dict[str, Any] | Any) -> LedgerEvent:
        clean_payload = _jsonable(payload)
        if not isinstance(clean_payload, dict):
            clean_payload = {"value": clean_payload}
        previous_hash = self._events[-1].event_hash if self._events else GENESIS_HASH
        source = {"index": len(self._events), "timestamp": utc_now_iso(), "event_type": event_type,
                  "payload": clean_payload, "previous_hash": previous_hash}
        event = LedgerEvent(**source, event_hash=self._hash(source))
        self._events.append(event)
        if self._file_path is not None:
            self._file_path.parent.mkdir(parents=True, exist_ok=True)
            with self._file_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event.to_dict(), sort_keys=True) + "\n")
        return event

    def verify_integrity(self) -> bool:
        previous_hash = GENESIS_HASH
        for expected_index, event in enumerate(self._events):
            if event.index != expected_index or event.previous_hash != previous_hash:
                return False
            if self._hash(event.hash_source()) != event.event_hash:
                return False
            previous_hash = event.event_hash
        return True

    def to_jsonl(self) -> str:
        return "\n".join(json.dumps(event.to_dict(), sort_keys=True) for event in self._events)

    def write_jsonl(self, path: str | Path, *, overwrite: bool = True) -> Path:
        output = Path(path)
        if output.exists() and not overwrite:
            raise FileExistsError(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(self.to_jsonl() + ("\n" if self._events else ""), encoding="utf-8")
        return output

    @classmethod
    def read_jsonl(cls, path: str | Path) -> "AppendOnlyAuditLedger":
        events: list[LedgerEvent] = []
        text = Path(path).read_text(encoding="utf-8")
        for lineno, line in enumerate(text.splitlines(), start=1):
            if not line.strip():
                continue
            try:
                payload = json.loads(line)
                events.append(LedgerEvent.from_dict(payload))
            except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"Invalid audit JSONL at line {lineno}: {exc}") from exc
        return cls.from_events(events)

    @classmethod
    def from_events(cls, events: Iterable[LedgerEvent]) -> "AppendOnlyAuditLedger":
        ledger = cls()
        ledger._events.extend(events)
        return ledger

    @staticmethod
    def _hash(source: dict[str, Any]) -> str:
        data = json.dumps(source, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(data.encode("utf-8")).hexdigest()
