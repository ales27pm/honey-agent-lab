from __future__ import annotations

from collections import deque
from typing import Deque, Iterable

from .models import Message


class SimulatedAgentBus:
    """In-memory message bus for synthetic scenarios only."""

    def __init__(self) -> None:
        self._queue: Deque[Message] = deque()
        self._history: list[Message] = []

    def publish(self, message: Message) -> None:
        self._queue.append(message)
        self._history.append(message)

    def extend(self, messages: Iterable[Message]) -> None:
        for message in messages:
            self.publish(message)

    def drain(self) -> tuple[Message, ...]:
        drained: list[Message] = []
        while self._queue:
            drained.append(self._queue.popleft())
        return tuple(drained)

    @property
    def history(self) -> tuple[Message, ...]:
        return tuple(self._history)
