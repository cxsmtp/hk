"""Bounded privacy-safe local evidence queue."""

from __future__ import annotations

import json
import os
from pathlib import Path
from threading import Lock
from typing import Any

from .privacy import redact_mapping, safe_reason_code

_RECEIPT_KINDS = {"decision_receipt", "execution_receipt"}


class EvidenceQueue:
    def __init__(self, path: str | Path, *, max_items: int = 500) -> None:
        self.path = Path(path).expanduser()
        self.max_items = max(1, int(max_items))
        self._lock = Lock()

    @property
    def dropped_monitor(self) -> int:
        with self._lock:
            return int(self._read().get("dropped_monitor") or 0)

    def append(self, item: dict[str, Any]) -> bool:
        clean, removed = redact_mapping(item)
        if "reason" in clean:
            clean["reason"] = safe_reason_code(clean["reason"])
        if removed:
            clean["redacted_fields"] = removed
        kind = str(clean.get("kind") or "monitor_observation")
        with self._lock:
            data = self._read()
            items = data.setdefault("items", [])
            if len(items) >= self.max_items:
                monitor_index = next(
                    (index for index, queued in enumerate(items) if queued.get("kind") not in _RECEIPT_KINDS),
                    None,
                )
                if monitor_index is None and kind not in _RECEIPT_KINDS:
                    data["dropped_monitor"] = int(data.get("dropped_monitor") or 0) + 1
                    self._write(data)
                    return False
                if monitor_index is not None:
                    items.pop(monitor_index)
                    data["dropped_monitor"] = int(data.get("dropped_monitor") or 0) + 1
                else:
                    items.pop(0)
                    data["dropped_receipt"] = int(data.get("dropped_receipt") or 0) + 1
            items.append(clean)
            self._write(data)
        return True

    def items(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(item) for item in self._read().get("items") or []]

    def pop_batch(self, limit: int = 50) -> list[dict[str, Any]]:
        count = max(0, int(limit))
        with self._lock:
            data = self._read()
            items = data.setdefault("items", [])
            batch = [dict(item) for item in items[:count]]
            del items[:count]
            self._write(data)
        return batch

    def acknowledge(self, item_id: str) -> bool:
        """Atomically remove one successfully uploaded evidence item by ID."""
        target = str(item_id or "")
        if not target:
            return False
        with self._lock:
            data = self._read()
            items = data.setdefault("items", [])
            index = next(
                (offset for offset, item in enumerate(items) if str(item.get("id") or "") == target),
                None,
            )
            if index is None:
                return False
            items.pop(index)
            self._write(data)
        return True

    def stats(self) -> dict[str, int]:
        with self._lock:
            data = self._read()
        return {
            "queued": len(data.get("items") or []),
            "max_items": self.max_items,
            "dropped_monitor": int(data.get("dropped_monitor") or 0),
            "dropped_receipt": int(data.get("dropped_receipt") or 0),
        }

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {"schema_version": 1, "dropped_monitor": 0, "dropped_receipt": 0, "items": []}

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return self._empty()
        return data if isinstance(data, dict) else self._empty()

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        os.chmod(self.path, 0o600)
