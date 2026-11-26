#!/usr/bin/env python3
"""Write the attack-simulation catalogue's executability report (simulation_catalog/executability_report.json).

For every catalogued scenario: its status (executable_now / expected_gap / requires_environment), the runner and the
outcome it asserts, the gap or the environment it needs, and its status before the runners existed. The statuses come
from apps/api/app/services/simulation_catalog_runners.py; apps/api/tests/test_simulation_catalog_runners.py executes
every runner and recomputes this report, so CI fails if the file, the catalogue or a runner drift apart.

    python scripts/simulation_catalog_report.py                 # rewrite the report
    python scripts/simulation_catalog_report.py --write-catalog # also align the catalogue files' status fields
    python scripts/simulation_catalog_report.py --check         # exit 1 if the committed files are out of date
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
API_ROOT = REPO_ROOT / "apps" / "api"
if str(API_ROOT) not in sys.path:
    sys.path.insert(0, str(API_ROOT))

from app.services.simulation_catalog_runners import (  # noqa: E402
    STATUS_EXECUTABLE,
    STATUS_EXPECTED_GAP,
    STATUS_REQUIRES_ENVIRONMENT,
    catalog_runners,
    executability_report,
)
from app.services.simulation_catalog_source import CATALOG_FILE_CATEGORY_MAP  # noqa: E402

CATALOG_DIR = REPO_ROOT / "simulation_catalog"
REPORT_PATH = CATALOG_DIR / "executability_report.json"
SUMMARY_PATH = CATALOG_DIR / "catalog_summary.json"


def dump(value: Any) -> str:
    return json.dumps(value, indent=2) + "\n"


def baseline() -> tuple[dict[str, str], dict[str, str]]:
    """The statuses (and executors) before the runners: kept in the committed report, else read from the catalogue."""

    if REPORT_PATH.exists():
        rows = json.loads(REPORT_PATH.read_text(encoding="utf-8")).get("scenarios") or []
        before = {row["simulation_id"]: row["status_before"] for row in rows if row.get("status_before")}
        executors = {row["simulation_id"]: row.get("required_executor_before") or "" for row in rows}
        if before:
            return before, executors
    before, executors = {}, {}
    for file_name in CATALOG_FILE_CATEGORY_MAP:
        for entry in json.loads((CATALOG_DIR / file_name).read_text(encoding="utf-8")):
            before[entry["simulation_id"]] = entry["executable_status"]
            executors[entry["simulation_id"]] = entry["required_executor"]
    return before, executors


def build_report() -> dict[str, Any]:
    before, executors = baseline()
    report = executability_report(before=before, before_executors=executors)
    for row in report["scenarios"]:
        row["required_executor_before"] = executors.get(row["simulation_id"]) or ""
    return report


def catalog_files() -> dict[str, str]:
    """Catalogue files with each entry's status fields aligned to its runner."""

    runners = {runner.simulation_id: runner for runner in catalog_runners()}
    out: dict[str, str] = {}
    for file_name in CATALOG_FILE_CATEGORY_MAP:
        entries = json.loads((CATALOG_DIR / file_name).read_text(encoding="utf-8"))
        for entry in entries:
            runner = runners[entry["simulation_id"]]
            entry["executable_status"] = runner.status
            entry["required_executor"] = runner.required_executor
            entry["implemented"] = runner.has_runner
        out[file_name] = dump(entries)
    summary = json.loads(SUMMARY_PATH.read_text(encoding="utf-8"))
    body = summary["simulation_catalog_summary"]
    statuses = [runner.status for runner in runners.values()]
    body["total_simulations"] = len(statuses)
    categories: dict[str, int] = {}
    frameworks: dict[str, int] = {}
    controls: dict[str, int] = {}
    for file_name in CATALOG_FILE_CATEGORY_MAP:
        for entry in json.loads(out[file_name]):
            categories[entry["category"]] = categories.get(entry["category"], 0) + 1
            for name in {item["framework"] for item in entry.get("framework_mappings") or []}:
                frameworks[name] = frameworks.get(name, 0) + 1
            for name in set(entry.get("control_ids") or []):
                controls[name] = controls.get(name, 0) + 1
    body["coverage_by_category"] = dict(sorted(categories.items()))
    body["coverage_by_framework"] = dict(sorted(frameworks.items()))
    body["coverage_by_control"] = dict(sorted(controls.items()))
    body["executable_now_count"] = statuses.count(STATUS_EXECUTABLE)
    body["partially_executable_count"] = statuses.count("partially_executable")
    body["not_yet_executable_count"] = statuses.count("not_yet_executable")
    body["expected_gap_count"] = statuses.count(STATUS_EXPECTED_GAP)
    body["requires_environment_count"] = statuses.count(STATUS_REQUIRES_ENVIRONMENT)
    body["executability_report"] = "simulation_catalog/executability_report.json"
    out["catalog_summary.json"] = dump(summary)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true", help="exit 1 if the report or catalogue files are out of date")
    parser.add_argument("--write-catalog", action="store_true", help="also align the catalogue files' status fields")
    args = parser.parse_args()

    wanted = {REPORT_PATH.name: dump(build_report())}
    if args.write_catalog or args.check:
        wanted.update(catalog_files())
    stale = [name for name, text in wanted.items() if not (CATALOG_DIR / name).exists() or (CATALOG_DIR / name).read_text(encoding="utf-8") != text]
    if args.check:
        for name in stale:
            print(f"out of date: simulation_catalog/{name}")
        return 1 if stale else 0
    for name in stale:
        (CATALOG_DIR / name).write_text(wanted[name], encoding="utf-8")
        print(f"wrote simulation_catalog/{name}")
    totals = json.loads(wanted[REPORT_PATH.name])["summary"]
    print(f"before: {totals['before']}")
    print(f"after:  {totals['after']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
