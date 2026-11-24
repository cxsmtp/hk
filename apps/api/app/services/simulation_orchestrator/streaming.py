from __future__ import annotations

import json
import queue
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, AsyncIterator
from uuid import uuid4

import anyio

SIMULATION_STREAM_EVENT_TYPES = {
    "simulation.run.started",
    "simulation.step.updated",
    "simulation.run.completed",
    "simulation.run.failed",
    "simulation.stream.connected",
}

HEARTBEAT_EVENT = ": keepalive\n\n"


@dataclass(frozen=True)
class SimulationStreamEnvelope:
    stream_event_id: str
    event_type: str
    tenant_id: str
    payload: dict[str, Any]
    created_at: float


def _encode_sse(envelope: SimulationStreamEnvelope) -> str:
    body = json.dumps(
        {
            "event_type": envelope.event_type,
            "tenant_id": envelope.tenant_id,
            "created_at": envelope.created_at,
            "payload": envelope.payload,
        },
        separators=(",", ":"),
    )
    return f"id: {envelope.stream_event_id}\nevent: {envelope.event_type}\ndata: {body}\n\n"


class SimulationStreamBroker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: dict[str, dict[str, queue.Queue[SimulationStreamEnvelope]]] = defaultdict(dict)

    def subscribe(self, *, tenant_id: str, queue_size: int = 256) -> tuple[str, queue.Queue[SimulationStreamEnvelope]]:
        subscriber_id = str(uuid4())
        q: queue.Queue[SimulationStreamEnvelope] = queue.Queue(maxsize=max(8, queue_size))
        with self._lock:
            self._subscribers[tenant_id][subscriber_id] = q
        return subscriber_id, q

    def unsubscribe(self, *, tenant_id: str, subscriber_id: str) -> None:
        with self._lock:
            bucket = self._subscribers.get(tenant_id)
            if not bucket:
                return
            bucket.pop(subscriber_id, None)
            if not bucket:
                self._subscribers.pop(tenant_id, None)

    def publish(self, *, tenant_id: str, event_type: str, payload: dict[str, Any]) -> bool:
        normalized_event_type = str(event_type or "").strip()
        if normalized_event_type not in SIMULATION_STREAM_EVENT_TYPES:
            return False

        envelope = SimulationStreamEnvelope(
            stream_event_id=str(uuid4()),
            event_type=normalized_event_type,
            tenant_id=str(tenant_id),
            payload=dict(payload or {}),
            created_at=time.time(),
        )
        with self._lock:
            queues = list(self._subscribers.get(str(tenant_id), {}).values())

        delivered = False
        for q in queues:
            delivered = self._enqueue_with_backpressure(q, envelope) or delivered
        return delivered

    @staticmethod
    def _enqueue_with_backpressure(q: queue.Queue[SimulationStreamEnvelope], envelope: SimulationStreamEnvelope) -> bool:
        try:
            q.put_nowait(envelope)
            return True
        except queue.Full:
            try:
                q.get_nowait()
            except queue.Empty:
                pass
            try:
                q.put_nowait(envelope)
                return True
            except queue.Full:
                return False

    async def stream_async(self, *, tenant_id: str, heartbeat_seconds: float = 15.0) -> AsyncIterator[str]:
        subscriber_id, q = self.subscribe(tenant_id=tenant_id)
        connected = SimulationStreamEnvelope(
            stream_event_id=str(uuid4()),
            event_type="simulation.stream.connected",
            tenant_id=tenant_id,
            payload={"status": "connected"},
            created_at=time.time(),
        )
        try:
            yield _encode_sse(connected)
            while True:
                try:
                    envelope = await anyio.to_thread.run_sync(q.get, True, max(1.0, heartbeat_seconds))
                    yield _encode_sse(envelope)
                except queue.Empty:
                    yield HEARTBEAT_EVENT
        finally:
            self.unsubscribe(tenant_id=tenant_id, subscriber_id=subscriber_id)


_BROKER = SimulationStreamBroker()


def stream_simulation_updates(*, tenant_id: str) -> AsyncIterator[str]:
    return _BROKER.stream_async(tenant_id=tenant_id)


def publish_simulation_update(*, tenant_id: str, event_type: str, payload: dict[str, Any]) -> bool:
    try:
        return _BROKER.publish(tenant_id=tenant_id, event_type=event_type, payload=payload)
    except Exception:
        return False

