from __future__ import annotations

import json
import queue
import threading
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, AsyncIterator, Iterator
from uuid import uuid4

import anyio

RUNTIME_STREAM_EVENT_TYPES = {
    "runtime.activity.created",
    "runtime.chain.updated",
    "runtime.pattern.detected",
    "runtime.recommendation.created",
    "runtime.risk.updated",
}

STREAM_CHANNELS = {
    "overview": {
        "runtime.activity.created",
        "runtime.chain.updated",
        "runtime.pattern.detected",
        "runtime.recommendation.created",
        "runtime.risk.updated",
    },
    "activity": {"runtime.activity.created"},
    "chains": {"runtime.chain.updated"},
    "patterns": {"runtime.pattern.detected", "runtime.risk.updated"},
    "recommendations": {"runtime.recommendation.created"},
}

HEARTBEAT_EVENT = ": keepalive\n\n"


@dataclass(frozen=True)
class RuntimeStreamEnvelope:
    stream_event_id: str
    event_type: str
    tenant_id: str
    payload: dict[str, Any]
    created_at: float


def _encode_sse(envelope: RuntimeStreamEnvelope) -> str:
    body = json.dumps(
        {
            "event_type": envelope.event_type,
            "tenant_id": envelope.tenant_id,
            "created_at": envelope.created_at,
            "payload": envelope.payload,
        },
        separators=(",", ":"),
    )
    return (
        f"id: {envelope.stream_event_id}\n"
        f"event: {envelope.event_type}\n"
        f"data: {body}\n\n"
    )


class RuntimeStreamBroker:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._subscribers: dict[tuple[str, str], dict[str, queue.Queue[RuntimeStreamEnvelope]]] = defaultdict(dict)

    def subscribe(
        self,
        *,
        tenant_id: str,
        channel: str,
        queue_size: int = 256,
    ) -> tuple[str, queue.Queue[RuntimeStreamEnvelope]]:
        if channel not in STREAM_CHANNELS:
            raise ValueError(f"unsupported stream channel: {channel}")
        subscriber_id = str(uuid4())
        q: queue.Queue[RuntimeStreamEnvelope] = queue.Queue(maxsize=max(8, queue_size))
        with self._lock:
            self._subscribers[(tenant_id, channel)][subscriber_id] = q
        return subscriber_id, q

    def unsubscribe(self, *, tenant_id: str, channel: str, subscriber_id: str) -> None:
        with self._lock:
            bucket = self._subscribers.get((tenant_id, channel))
            if not bucket:
                return
            bucket.pop(subscriber_id, None)
            if not bucket:
                self._subscribers.pop((tenant_id, channel), None)

    def publish(self, *, tenant_id: str, event_type: str, payload: dict[str, Any]) -> bool:
        normalized_event_type = str(event_type or "").strip()
        if normalized_event_type not in RUNTIME_STREAM_EVENT_TYPES:
            return False

        envelope = RuntimeStreamEnvelope(
            stream_event_id=str(uuid4()),
            event_type=normalized_event_type,
            tenant_id=str(tenant_id),
            payload=dict(payload or {}),
            created_at=time.time(),
        )

        with self._lock:
            queues = []
            for channel, channel_event_types in STREAM_CHANNELS.items():
                if normalized_event_type not in channel_event_types:
                    continue
                queues.extend(list(self._subscribers.get((tenant_id, channel), {}).values()))

        delivered = False
        for q in queues:
            delivered = self._enqueue_with_backpressure(q, envelope) or delivered
        return delivered

    @staticmethod
    def _enqueue_with_backpressure(
        q: queue.Queue[RuntimeStreamEnvelope],
        envelope: RuntimeStreamEnvelope,
    ) -> bool:
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

    def stream(
        self,
        *,
        tenant_id: str,
        channel: str,
        heartbeat_seconds: float = 15.0,
    ) -> Iterator[str]:
        subscriber_id, q = self.subscribe(tenant_id=tenant_id, channel=channel)
        connected = RuntimeStreamEnvelope(
            stream_event_id=str(uuid4()),
            event_type="runtime.stream.connected",
            tenant_id=tenant_id,
            payload={"channel": channel, "status": "connected"},
            created_at=time.time(),
        )
        try:
            yield _encode_sse(connected)
            while True:
                try:
                    envelope = q.get(timeout=max(1.0, heartbeat_seconds))
                    yield _encode_sse(envelope)
                except queue.Empty:
                    yield HEARTBEAT_EVENT
        finally:
            self.unsubscribe(tenant_id=tenant_id, channel=channel, subscriber_id=subscriber_id)

    async def stream_async(
        self,
        *,
        tenant_id: str,
        channel: str,
        heartbeat_seconds: float = 15.0,
    ) -> AsyncIterator[str]:
        subscriber_id, q = self.subscribe(tenant_id=tenant_id, channel=channel)
        connected = RuntimeStreamEnvelope(
            stream_event_id=str(uuid4()),
            event_type="runtime.stream.connected",
            tenant_id=tenant_id,
            payload={"channel": channel, "status": "connected"},
            created_at=time.time(),
        )
        try:
            yield _encode_sse(connected)
            while True:
                try:
                    envelope = await anyio.to_thread.run_sync(
                        q.get,
                        True,
                        max(1.0, heartbeat_seconds),
                    )
                    yield _encode_sse(envelope)
                except queue.Empty:
                    yield HEARTBEAT_EVENT
        finally:
            self.unsubscribe(tenant_id=tenant_id, channel=channel, subscriber_id=subscriber_id)


_BROKER = RuntimeStreamBroker()


def stream_runtime_updates(*, tenant_id: str, channel: str) -> AsyncIterator[str]:
    return _BROKER.stream_async(tenant_id=tenant_id, channel=channel)


def publish_runtime_update(*, tenant_id: str, event_type: str, payload: dict[str, Any]) -> bool:
    try:
        return _BROKER.publish(tenant_id=tenant_id, event_type=event_type, payload=payload)
    except Exception:
        return False
