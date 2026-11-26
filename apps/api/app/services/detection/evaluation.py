"""Precision / recall of the DLP and prompt-injection detectors on a labelled benchmark (JSONL).

    python -m app.services.detection.evaluation tests/fixtures/detection_benchmark

DLP rows: {"id", "text", "labels": [entity type or document category, ...]}. A label is predicted when the scan reports
that entity type at or above the reporting confidence, or that document category at or above the profile's minimum
score. ``api_key`` stands for every secret type (api_key, private_key, credential).

Injection rows: {"id", "text", "label": 0|1, "category", "scope": "direct"|"indirect"}. A row is predicted positive
when the engine's action is anything but ``allow`` under the default thresholds; ``blocked`` counts the rows the default
profile blocks outright.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path
from typing import Any, Iterable

from app.services.detection.dlp_engine import scan
from app.services.detection.injection_engine import assess
from app.services.detection.profile import DEFAULT_PROFILE, DetectionProfile

SECRET_TYPES = {"api_key", "private_key", "credential"}


def load_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def dlp_predictions(text: str, profile: DetectionProfile = DEFAULT_PROFILE) -> set[str]:
    result = scan(text, profile=profile)
    labels = {"api_key" if f.entity_type in SECRET_TYPES else f.entity_type for f in result.reportable()}
    labels |= {name for name in result.detected_categories(profile) if ":" not in name}
    return labels


def _prf(tp: int, fp: int, fn: int) -> dict[str, float | int]:
    precision = tp / (tp + fp) if tp + fp else 1.0
    recall = tp / (tp + fn) if tp + fn else 1.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(precision, 4), "recall": round(recall, 4)}


def evaluate_dlp(rows: Iterable[dict[str, Any]], profile: DetectionProfile = DEFAULT_PROFILE) -> dict[str, Any]:
    rows = list(rows)
    categories = sorted({label for row in rows for label in row["labels"]})
    counts = {c: [0, 0, 0] for c in categories}
    errors: list[dict[str, Any]] = []
    for row in rows:
        predicted = dlp_predictions(row["text"], profile)
        expected = set(row["labels"])
        for category in categories:
            if category in expected and category in predicted:
                counts[category][0] += 1
            elif category in predicted:
                counts[category][1] += 1
                errors.append({"id": row["id"], "category": category, "error": "false_positive"})
            elif category in expected:
                counts[category][2] += 1
                errors.append({"id": row["id"], "category": category, "error": "false_negative"})
    per_category = {c: _prf(*counts[c]) for c in categories}
    total = [sum(v[i] for v in counts.values()) for i in range(3)]
    return {"samples": len(rows), "per_category": per_category, "micro": _prf(*total), "errors": errors}


def evaluate_injection(rows: Iterable[dict[str, Any]], profile: DetectionProfile = DEFAULT_PROFILE) -> dict[str, Any]:
    rows = list(rows)
    per: dict[str, list[int]] = {}
    tp = fp = fn = blocked = 0
    errors: list[dict[str, Any]] = []
    for row in rows:
        verdict = assess(row["text"], scope=row.get("scope", "direct"), profile=profile)
        predicted = verdict.action != "allow"
        bucket = per.setdefault(row["category"], [0, 0])  # [flagged, total]
        bucket[1] += 1
        if predicted:
            bucket[0] += 1
        if row["label"] and predicted:
            tp += 1
            blocked += verdict.action == "block"
        elif predicted:
            fp += 1
            errors.append({"id": row["id"], "error": "false_positive", "risk": verdict.risk_score, "reasons": verdict.reason_codes})
        elif row["label"]:
            fn += 1
            errors.append({"id": row["id"], "error": "false_negative", "risk": verdict.risk_score})
    positives = sum(1 for row in rows if row["label"])
    return {
        "samples": len(rows),
        "overall": _prf(tp, fp, fn),
        "block_rate_on_positives": round(blocked / positives, 4) if positives else 0.0,
        "flag_rate_by_category": {c: round(v[0] / v[1], 4) for c, v in sorted(per.items())},
        "errors": errors,
    }


def latency_ms(texts: list[str], *, repeats: int = 3) -> dict[str, float]:
    samples: list[float] = []
    for _ in range(repeats):
        for text in texts:
            start = time.perf_counter()
            scan(text)
            assess(text)
            samples.append((time.perf_counter() - start) * 1000)
    samples.sort()
    return {"p50": round(samples[len(samples) // 2], 2), "p95": round(samples[int(len(samples) * 0.95) - 1], 2), "max": round(samples[-1], 2)}


def main(argv: list[str]) -> int:
    folder = Path(argv[1] if len(argv) > 1 else "tests/fixtures/detection_benchmark")
    report = {
        "dlp": evaluate_dlp(load_jsonl(folder / "dlp.jsonl")),
        "prompt_injection": evaluate_injection(load_jsonl(folder / "prompt_injection.jsonl")),
    }
    print(json.dumps(report, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv))
