"""Thread-safe event logger with bounded queue and TTL pruning."""

from __future__ import annotations

import threading
import time
import uuid
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, Deque, Dict, List, Optional


@dataclass
class TrapEvent:
    """One captured connection / payload interaction."""

    event_id: str
    timestamp: float
    src_ip: str
    src_port: int
    dst_port: int
    service: str
    payload: str
    bytes_received: int
    notes: str = ""
    analyzed: bool = False

    def summary(self) -> str:
        snippet = self.payload.replace("\n", "\\n")[:120]
        return (
            f"{self.src_ip}:{self.src_port} -> :{self.dst_port} "
            f"[{self.service}] bytes={self.bytes_received} payload={snippet!r}"
        )

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class EventLogger:
    """Bounded in-memory store. Never grows without limit (anti-memory-bomb)."""

    def __init__(self, max_queue_size: int = 500, event_ttl_sec: float = 3600.0) -> None:
        self._max_queue_size = max(1, max_queue_size)
        # Allow sub-second TTLs for tests; floor only avoids zero/negative.
        self._event_ttl_sec = max(0.01, event_ttl_sec)
        self._events: Deque[TrapEvent] = deque(maxlen=self._max_queue_size)
        self._lock = threading.RLock()
        self._total_captured = 0

    @property
    def total_captured(self) -> int:
        with self._lock:
            return self._total_captured

    def log_event(
        self,
        src_ip: str,
        src_port: int,
        dst_port: int,
        service: str,
        payload: bytes | str,
        notes: str = "",
    ) -> TrapEvent:
        if isinstance(payload, bytes):
            try:
                text = payload.decode("utf-8", errors="replace")
            except Exception:
                text = repr(payload)
        else:
            text = payload

        # Cap stored payload size defensively.
        text = text[:16_384]

        event = TrapEvent(
            event_id=uuid.uuid4().hex[:12],
            timestamp=time.time(),
            src_ip=src_ip,
            src_port=src_port,
            dst_port=dst_port,
            service=service,
            payload=text,
            bytes_received=len(payload) if isinstance(payload, (bytes, str)) else 0,
            notes=notes,
        )
        with self._lock:
            self._prune_locked()
            self._events.append(event)
            self._total_captured += 1
        return event

    def _prune_locked(self) -> None:
        cutoff = time.time() - self._event_ttl_sec
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()

    def pending_events(self, limit: int = 20) -> List[TrapEvent]:
        with self._lock:
            self._prune_locked()
            pending = [e for e in self._events if not e.analyzed]
            return pending[: max(1, limit)]

    def mark_analyzed(self, event_ids: List[str]) -> None:
        ids = set(event_ids)
        with self._lock:
            for event in self._events:
                if event.event_id in ids:
                    event.analyzed = True

    def recent(self, limit: int = 50) -> List[TrapEvent]:
        with self._lock:
            self._prune_locked()
            items = list(self._events)
            return items[-limit:]

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            self._prune_locked()
            return {
                "stored": len(self._events),
                "total_captured": self._total_captured,
                "pending": sum(1 for e in self._events if not e.analyzed),
                "max_queue_size": self._max_queue_size,
            }
