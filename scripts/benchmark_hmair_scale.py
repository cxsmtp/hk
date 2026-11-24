#!/usr/bin/env python3
from __future__ import annotations

from dataclasses import asdict
import json
from pathlib import Path
import sys

API_ROOT = Path(__file__).resolve().parents[1] / "apps" / "api"
sys.path.insert(0, str(API_ROOT))

from app.services.hmair.scale_acceptance import run_hmair_streaming_benchmark


if __name__ == "__main__":
    print(json.dumps(asdict(run_hmair_streaming_benchmark()), sort_keys=True))
