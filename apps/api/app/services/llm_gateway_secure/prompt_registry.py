from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class PromptTemplateRecord:
    template_id: str
    version: str
    task_type: str
    description: str
    allowed_data_types: tuple[str, ...]
    risk_level: str
    approved_for_providers: tuple[str, ...]
    template_text: str
    expected_output_schema: str
    status: str
    last_updated: str

    @property
    def key(self) -> str:
        return f"{self.template_id}.{self.version}"


_TEMPLATE_DIR = Path(__file__).resolve().parents[2] / "prompt_templates"


@lru_cache(maxsize=1)
def _load_registry() -> dict[str, PromptTemplateRecord]:
    records: dict[str, PromptTemplateRecord] = {}
    if not _TEMPLATE_DIR.exists() or not _TEMPLATE_DIR.is_dir():
        return records

    for path in sorted(_TEMPLATE_DIR.glob("*.json")):
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue
        if not isinstance(payload, dict):
            continue

        task_type = str(payload.get("task_type") or "").strip().lower()
        template_id = str(payload.get("template_id") or "").strip()
        version = str(payload.get("version") or "v1").strip()
        if not task_type or not template_id:
            continue

        record = PromptTemplateRecord(
            template_id=template_id,
            version=version,
            task_type=task_type,
            description=str(payload.get("description") or "").strip(),
            allowed_data_types=tuple(str(item).strip().lower() for item in (payload.get("allowed_data_types") or []) if str(item).strip()),
            risk_level=str(payload.get("risk_level") or "medium").strip().lower() or "medium",
            approved_for_providers=tuple(
                str(item).strip().lower() for item in (payload.get("approved_for_providers") or []) if str(item).strip()
            ),
            template_text=str(payload.get("template_text") or "").strip(),
            expected_output_schema=str(payload.get("expected_output_schema") or "").strip(),
            status=str(payload.get("status") or "active").strip().lower() or "active",
            last_updated=str(payload.get("last_updated") or "").strip(),
        )
        records[task_type] = record
    return records


def clear_prompt_registry_cache() -> None:
    _load_registry.cache_clear()  # type: ignore[attr-defined]


def get_prompt_template(task_type: str) -> PromptTemplateRecord | None:
    normalized = str(task_type or "").strip().lower()
    if not normalized:
        return None
    return _load_registry().get(normalized)


def get_prompt_template_metadata(task_type: str) -> dict[str, Any]:
    template = get_prompt_template(task_type)
    if template is None:
        return {}
    return {
        "template_id": template.template_id,
        "template_version": template.version,
        "task_type": template.task_type,
        "description": template.description,
        "allowed_data_types": list(template.allowed_data_types),
        "risk_level": template.risk_level,
        "approved_for_providers": list(template.approved_for_providers),
        "expected_output_schema": template.expected_output_schema,
        "status": template.status,
        "last_updated": template.last_updated,
    }
