"""Bounded privacy-safe baseline aggregation and policy-pack proposals."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock
from typing import Any

from .decision import Action, Decision
from .privacy import bounded_label, safe_categories, stable_fingerprint


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class BaselineStore:
    def __init__(
        self,
        path: str | Path,
        *,
        tenant_key: str = "local",
        max_paths: int = 500,
    ) -> None:
        self.path = Path(path).expanduser()
        self.tenant_key = tenant_key or "local"
        self.max_paths = max(1, int(max_paths))
        self._lock = Lock()

    def observe(self, *, request: dict[str, Any], decision: Decision) -> None:
        feature = self._features(request, decision)
        now = _utcnow()
        with self._lock:
            data = self._read()
            paths = data.setdefault("paths", {})
            entry = paths.get(feature["path_id"])
            if entry is None:
                entry = {
                    **feature,
                    "first_seen": now,
                    "last_seen": now,
                    "observation_count": 0,
                    "decision_counts": {},
                }
                paths[feature["path_id"]] = entry
            entry["last_seen"] = now
            entry["observation_count"] = int(entry.get("observation_count") or 0) + 1
            counts = entry.setdefault("decision_counts", {})
            verdict = feature["policy_decision"]
            counts[verdict] = int(counts.get(verdict) or 0) + 1
            data["observation_count"] = int(data.get("observation_count") or 0) + 1
            data["updated_at"] = now
            self._evict(data)
            self._write(data)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            data = self._read()
        paths = data.get("paths") or {}
        return {
            "schema_version": 1,
            "observation_count": int(data.get("observation_count") or 0),
            "path_count": len(paths),
            "evicted_path_count": int(data.get("evicted_path_count") or 0),
            "updated_at": data.get("updated_at"),
            "paths": [dict(paths[key]) for key in sorted(paths)],
        }

    def reset(self) -> None:
        with self._lock:
            self._write(self._empty())

    def propose(self) -> dict[str, Any]:
        snapshot = self.snapshot()
        if snapshot["observation_count"] == 0:
            return {
                "status": "insufficient_evidence",
                "observation_count": 0,
                "path_count": 0,
                "rules": [],
            }

        rules: list[dict[str, Any]] = []
        for path in snapshot["paths"]:
            counts = path.get("decision_counts") or {}
            decision = self._proposed_decision(counts)
            rules.append(
                {
                    "id": f"endpoint-baseline-{path['path_id'].split(':', 1)[-1][:16]}",
                    "match": {
                        "surface": path["surface"],
                        "adapter_path": path["adapter_path"],
                        "destination_class": path["destination_class"],
                        "tool_fingerprint": path["tool_fingerprint"],
                        "action_category": path["action_category"],
                    },
                    "decision": decision,
                    "observation_count": path["observation_count"],
                    "decision_counts": dict(sorted(counts.items())),
                    "sensitive_categories": path["sensitive_categories"],
                }
            )
        rules.sort(key=lambda item: item["id"])
        return {
            "status": "ready",
            "observation_count": snapshot["observation_count"],
            "path_count": snapshot["path_count"],
            "rules": rules,
        }

    def _features(self, request: dict[str, Any], decision: Decision) -> dict[str, Any]:
        surface = bounded_label(request.get("surface"), default="unknown", limit=48)
        adapter = bounded_label(request.get("adapter_path") or surface, default="unknown", limit=48)
        destination = bounded_label(
            request.get("destination_class")
            or request.get("provider")
            or request.get("destination_domain")
            or "unknown",
            limit=120,
        )
        tool_value = request.get("tool_name") or request.get("action") or "none"
        tool_fp = stable_fingerprint(tool_value, key=self.tenant_key)
        action_category = bounded_label(request.get("action_category") or request.get("action"), default="unknown", limit=80)
        verdict = bounded_label(decision.detail.get("would_action") or decision.action, default=Action.ALLOW, limit=40)
        categories = safe_categories(decision.threat_types)
        material = "|".join((surface, adapter, destination, tool_fp, action_category))
        return {
            "path_id": stable_fingerprint(material, key=self.tenant_key),
            "surface": surface,
            "adapter_path": adapter,
            "destination_class": destination,
            "tool_fingerprint": tool_fp,
            "action_category": action_category,
            "sensitive_categories": categories,
            "policy_decision": verdict,
        }

    @staticmethod
    def _proposed_decision(counts: dict[str, Any]) -> str:
        for decision in (Action.BLOCK, Action.HOLD, Action.REDACT, Action.WARN, Action.SCOPE):
            if int(counts.get(decision) or 0) > 0:
                return decision
        return Action.ALLOW

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return self._empty()
        return data if isinstance(data, dict) else self._empty()

    @staticmethod
    def _empty() -> dict[str, Any]:
        return {
            "schema_version": 1,
            "observation_count": 0,
            "evicted_path_count": 0,
            "updated_at": None,
            "paths": {},
        }

    def _evict(self, data: dict[str, Any]) -> None:
        paths = data.setdefault("paths", {})
        while len(paths) > self.max_paths:
            oldest = min(paths, key=lambda key: (paths[key].get("last_seen") or "", key))
            paths.pop(oldest, None)
            data["evicted_path_count"] = int(data.get("evicted_path_count") or 0) + 1

    def _write(self, data: dict[str, Any]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(json.dumps(data, sort_keys=True, separators=(",", ":")), encoding="utf-8")
        os.chmod(tmp, 0o600)
        tmp.replace(self.path)
        os.chmod(self.path, 0o600)
