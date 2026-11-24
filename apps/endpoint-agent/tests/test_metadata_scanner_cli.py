from __future__ import annotations

import json
import multiprocessing
import os
import subprocess
import sys
import time
from pathlib import Path
from queue import Empty

import pytest

from hawk_endpoint_agent.metadata_scanner_cli import (
    DISCOVERY_GATE_ENV,
    main,
)


def test_cli_is_default_off_and_does_not_invoke_scanner(capsys) -> None:
    calls = 0

    def scanner() -> dict:
        nonlocal calls
        calls += 1
        return {"unexpected": True}

    rc = main([], environ={}, scanner=scanner)

    assert rc == 2
    assert calls == 0
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": "hawk.endpoint_metadata.v1",
        "status": "disabled",
        "collection_mode": "one_shot_read_only",
        "gate": DISCOVERY_GATE_ENV,
    }


def test_cli_requires_explicit_true_gate(capsys) -> None:
    calls = 0

    def scanner() -> dict:
        nonlocal calls
        calls += 1
        return {"unexpected": True}

    rc = main([], environ={DISCOVERY_GATE_ENV: "1"}, scanner=scanner)

    assert rc == 2
    assert calls == 0
    assert json.loads(capsys.readouterr().out)["status"] == "disabled"


def test_cli_invokes_scanner_once_prints_json_and_exits(capsys) -> None:
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("shared local scanner probe requires fork")
    context = multiprocessing.get_context("fork")
    calls = context.Value("i", 0)
    expected = {
        "schema_version": "hawk.endpoint_metadata.v1",
        "status": "completed",
        "collection_mode": "one_shot_read_only",
        "products": [],
    }

    def scanner() -> dict:
        with calls.get_lock():
            calls.value += 1
        return expected

    rc = main(
        [],
        environ={DISCOVERY_GATE_ENV: "true"},
        scanner=scanner,
        process_context=context,
    )

    assert rc == 0
    assert calls.value == 1
    assert json.loads(capsys.readouterr().out) == expected


def test_cli_returns_bounded_privacy_safe_error(capsys) -> None:
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("local scanner probe requires fork")
    context = multiprocessing.get_context("fork")

    def scanner() -> dict:
        raise OSError("/private/person@example.test/.codex/config.toml: permission denied")

    rc = main(
        [],
        environ={DISCOVERY_GATE_ENV: "TRUE"},
        scanner=scanner,
        process_context=context,
    )

    assert rc == 1
    output = capsys.readouterr()
    assert output.err == ""
    assert json.loads(output.out) == {
        "schema_version": "hawk.endpoint_metadata.v1",
        "status": "error",
        "collection_mode": "one_shot_read_only",
        "errors": [{"source": "scanner", "code": "collection_failed"}],
    }
    assert "person@example.test" not in output.out


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="FIFO requires POSIX")
def test_enabled_cli_does_not_block_on_fifo_metadata(tmp_path: Path) -> None:
    home = tmp_path / "home"
    (home / ".codex").mkdir(parents=True)
    os.mkfifo(home / ".codex/config.toml")
    environment = os.environ.copy()
    environment.update(
        {
            "HOME": str(home),
            "PATH": "",
            "PYTHONPATH": str(Path(__file__).parents[1] / "src"),
            DISCOVERY_GATE_ENV: "true",
        }
    )

    started = time.monotonic()
    try:
        completed = subprocess.run(
            [sys.executable, "-m", "hawk_endpoint_agent.metadata_scanner_cli"],
            cwd=Path(__file__).parents[1],
            env=environment,
            capture_output=True,
            text=True,
            timeout=3.25,
            check=False,
        )
    except subprocess.TimeoutExpired:
        pytest.fail("enabled scanner exceeded the hard CLI deadline on FIFO metadata")

    assert time.monotonic() - started < 3.25
    assert completed.returncode == 0
    report = json.loads(completed.stdout)
    assert report["status"] == "completed"
    assert "unsupported_file_type" in {
        error["code"] for error in report["errors"]
    }


def test_cli_terminates_blocking_worker_without_orphan(capsys) -> None:
    if "fork" not in multiprocessing.get_all_start_methods():
        pytest.skip("worker PID probe requires fork")
    context = multiprocessing.get_context("fork")
    worker_pids = context.Queue()

    def blocking_scanner() -> dict:
        worker_pids.put(os.getpid())
        time.sleep(30)
        return {"unexpected": True}

    started = time.monotonic()
    rc = main(
        [],
        environ={DISCOVERY_GATE_ENV: "true"},
        scanner=blocking_scanner,
        process_context=context,
        hard_timeout_seconds=0.5,
    )
    elapsed = time.monotonic() - started

    try:
        worker_pid = worker_pids.get(timeout=0.5)
    except Empty:
        pytest.fail("scanner worker did not start")
    finally:
        worker_pids.close()
        worker_pids.join_thread()

    assert rc == 1
    assert elapsed < 2.0
    with pytest.raises(ProcessLookupError):
        os.kill(worker_pid, 0)
    assert json.loads(capsys.readouterr().out) == {
        "schema_version": "hawk.endpoint_metadata.v1",
        "status": "error",
        "collection_mode": "one_shot_read_only",
        "errors": [{"source": "scanner", "code": "deadline_exceeded"}],
    }
