from __future__ import annotations

import json
from pathlib import Path
import shutil
import sys
import argparse

from hawk_endpoint_agent.native_control.codex_acceptance import run_codex_binary_acceptance


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-binary-sha256", required=True)
    parser.add_argument("--identity-helper", required=True)
    parser.add_argument("--key-tag", required=True)
    args = parser.parse_args()
    binary = Path(shutil.which("codex") or "codex")
    repository_root = Path(__file__).resolve().parents[3]
    report = run_codex_binary_acceptance(
        binary,
        repository_root=repository_root,
        python_binary=Path(sys.executable),
        expected_version=args.expected_version,
        expected_binary_sha256=args.expected_binary_sha256,
        identity_helper=Path(args.identity_helper),
        key_tag=args.key_tag,
    )
    print(json.dumps(report.as_evidence_artifact(), indent=2, sort_keys=True))
    if not report.passed:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
