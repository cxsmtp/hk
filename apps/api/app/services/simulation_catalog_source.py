from __future__ import annotations

import json
from collections import OrderedDict
from pathlib import Path
from typing import Any


CATALOG_FILE_CATEGORY_MAP: OrderedDict[str, str] = OrderedDict(
    [
        ("prompt_attacks.json", "prompt_instruction_attacks"),
        ("data_leakage.json", "data_leakage_inference"),
        ("tool_agent_abuse.json", "tool_agent_abuse"),
        ("ai_iam_abuse.json", "ai_identity_access_abuse"),
        ("rag_poisoning.json", "training_rag_poisoning"),
        ("model_integrity.json", "model_supply_chain_integrity"),
        ("resource_abuse.json", "resource_abuse_cost_exploitation"),
        ("unsafe_decisioning.json", "overreliance_unsafe_decisioning"),
    ]
)


REQUIRED_CATEGORY_COUNTS: OrderedDict[str, int] = OrderedDict(
    [
        ("prompt_instruction_attacks", 40),
        ("data_leakage_inference", 40),
        ("tool_agent_abuse", 35),
        ("ai_identity_access_abuse", 35),
        ("training_rag_poisoning", 30),
        ("model_supply_chain_integrity", 20),
        ("resource_abuse_cost_exploitation", 20),
        ("overreliance_unsafe_decisioning", 20),
    ]
)


ALLOWED_EXECUTION_STATUS = {"executable_now", "partially_executable", "not_yet_executable"}


def _catalog_dir() -> Path:
    # /repo/apps/api/app/services -> parents[4] == /repo
    return Path(__file__).resolve().parents[4] / "simulation_catalog"


def _normalize_str(value: Any) -> str:
    return str(value or "").strip()


def _normalize_lower(value: Any) -> str:
    return _normalize_str(value).lower()


def _validate_framework_mappings(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    for item in value:
        if not isinstance(item, dict):
            return False
        if not _normalize_str(item.get("framework")):
            return False
        if not _normalize_str(item.get("reference")):
            return False
    return True


def _validate_control_ids(value: Any) -> bool:
    if not isinstance(value, list) or not value:
        return False
    return any(_normalize_str(item) for item in value)


def _load_category_file(path: Path) -> list[dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError(f"catalog_file_invalid:{path.name}:expected_list")
    out: list[dict[str, Any]] = []
    for idx, row in enumerate(data, start=1):
        if not isinstance(row, dict):
            raise ValueError(f"catalog_file_invalid:{path.name}:row_{idx}:expected_object")
        out.append(dict(row))
    return out


def load_simulation_catalog_entries() -> list[dict[str, Any]]:
    base = _catalog_dir()
    if not base.exists() or not base.is_dir():
        raise ValueError(f"simulation_catalog_directory_missing:{base}")

    rows: list[dict[str, Any]] = []
    seen_sim_ids: set[str] = set()
    counts: dict[str, int] = {}
    errors: list[str] = []

    for file_name, expected_category in CATALOG_FILE_CATEGORY_MAP.items():
        path = base / file_name
        if not path.exists():
            errors.append(f"catalog_file_missing:{file_name}")
            continue

        for idx, entry in enumerate(_load_category_file(path), start=1):
            sim_id = _normalize_str(entry.get("simulation_id"))
            category = _normalize_lower(entry.get("category"))
            executable_status = _normalize_lower(entry.get("executable_status"))
            required_executor = _normalize_lower(entry.get("required_executor"))
            version = _normalize_str(entry.get("version"))

            if not sim_id:
                errors.append(f"catalog_entry_invalid:{file_name}:row_{idx}:missing_simulation_id")
                continue
            if sim_id in seen_sim_ids:
                errors.append(f"catalog_entry_invalid:{file_name}:row_{idx}:duplicate_simulation_id:{sim_id}")
                continue
            seen_sim_ids.add(sim_id)

            if category != expected_category:
                errors.append(
                    f"catalog_entry_invalid:{file_name}:row_{idx}:category_mismatch:{category}->{expected_category}"
                )

            if executable_status not in ALLOWED_EXECUTION_STATUS:
                errors.append(f"catalog_entry_invalid:{file_name}:row_{idx}:invalid_execution_status:{executable_status}")

            if not required_executor:
                errors.append(f"catalog_entry_invalid:{file_name}:row_{idx}:missing_required_executor")

            if not _validate_control_ids(entry.get("control_ids")):
                errors.append(f"catalog_entry_invalid:{file_name}:row_{idx}:missing_control_ids")

            if not _validate_framework_mappings(entry.get("framework_mappings")):
                errors.append(f"catalog_entry_invalid:{file_name}:row_{idx}:missing_framework_mappings")

            if not version:
                errors.append(f"catalog_entry_invalid:{file_name}:row_{idx}:missing_version")

            counts[expected_category] = counts.get(expected_category, 0) + 1
            rows.append(entry)

    for category, min_count in REQUIRED_CATEGORY_COUNTS.items():
        observed = int(counts.get(category, 0))
        if observed < int(min_count):
            errors.append(f"catalog_category_underfilled:{category}:{observed}<{min_count}")

    if errors:
        raise ValueError(";".join(errors))
    return rows

