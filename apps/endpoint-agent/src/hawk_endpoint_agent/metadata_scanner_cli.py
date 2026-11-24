"""Default-off, one-shot CLI for read-only endpoint metadata discovery."""

from __future__ import annotations

import argparse
import json
import multiprocessing
import os
from collections.abc import Callable, Mapping, Sequence
from multiprocessing.connection import Connection
from typing import Any

from .metadata_scanner import SCHEMA_VERSION, collect_endpoint_metadata


DISCOVERY_GATE_ENV = "READ_ONLY_ENDPOINT_DISCOVERY_ENABLED"
HARD_SCAN_TIMEOUT_SECONDS = 2.5
_WORKER_STOP_GRACE_SECONDS = 0.25


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hawk-endpoint-metadata-scan",
        description="Run one bounded, local, read-only endpoint metadata scan.",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Indent the JSON output.",
    )
    return parser


def _base_report(status: str) -> dict[str, object]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": status,
        "collection_mode": "one_shot_read_only",
    }


def _error_report(code: str) -> dict[str, object]:
    result = _base_report("error")
    result["errors"] = [{"source": "scanner", "code": code}]
    return result


def _scanner_worker(
    scanner: Callable[[], dict[str, object]],
    sender: Connection,
) -> None:
    try:
        result = scanner()
        if not isinstance(result, dict):
            raise TypeError("scanner result must be a dictionary")
        sender.send(("completed", result))
    except BaseException:
        try:
            sender.send(("error", None))
        except (BrokenPipeError, EOFError, OSError):
            pass
    finally:
        sender.close()


def _stop_worker(process: multiprocessing.Process) -> None:
    if process.is_alive():
        process.terminate()
        process.join(_WORKER_STOP_GRACE_SECONDS)
    if process.is_alive() and hasattr(process, "kill"):
        process.kill()
        process.join(_WORKER_STOP_GRACE_SECONDS)
    if process.is_alive():
        raise RuntimeError("scanner worker could not be stopped")


def _run_with_deadline(
    scanner: Callable[[], dict[str, object]],
    *,
    process_context: Any,
    hard_timeout_seconds: float,
) -> tuple[dict[str, object], int]:
    receiver, sender = process_context.Pipe(duplex=False)
    process = process_context.Process(
        target=_scanner_worker,
        args=(scanner, sender),
        name="hawk-endpoint-metadata-scan",
        daemon=True,
    )
    try:
        process.start()
    except Exception:
        receiver.close()
        sender.close()
        return _error_report("collection_failed"), 1
    sender.close()

    try:
        if not receiver.poll(hard_timeout_seconds):
            _stop_worker(process)
            return _error_report("deadline_exceeded"), 1
        try:
            status, payload = receiver.recv()
        except (EOFError, OSError):
            status, payload = "error", None
        process.join(_WORKER_STOP_GRACE_SECONDS)
        _stop_worker(process)
        if status == "completed" and isinstance(payload, dict):
            return payload, 0
        return _error_report("collection_failed"), 1
    except Exception:
        try:
            _stop_worker(process)
        except RuntimeError:
            pass
        return _error_report("collection_failed"), 1
    finally:
        receiver.close()
        if not process.is_alive():
            process.close()


def main(
    argv: Sequence[str] | None = None,
    *,
    environ: Mapping[str, str] | None = None,
    scanner: Callable[[], dict[str, object]] = collect_endpoint_metadata,
    process_context: Any | None = None,
    hard_timeout_seconds: float = HARD_SCAN_TIMEOUT_SECONDS,
) -> int:
    """Run at most one scan, print one JSON document, and return."""

    args = _parser().parse_args(argv)
    environment = os.environ if environ is None else environ
    enabled = environment.get(DISCOVERY_GATE_ENV, "").strip().lower() == "true"

    if not enabled:
        result = _base_report("disabled")
        result["gate"] = DISCOVERY_GATE_ENV
        return_code = 2
    else:
        context = process_context or multiprocessing.get_context("spawn")
        result, return_code = _run_with_deadline(
            scanner,
            process_context=context,
            hard_timeout_seconds=hard_timeout_seconds,
        )

    print(
        json.dumps(
            result,
            indent=2 if args.pretty else None,
            sort_keys=True,
            separators=None if args.pretty else (",", ":"),
        )
    )
    return return_code


if __name__ == "__main__":
    raise SystemExit(main())
