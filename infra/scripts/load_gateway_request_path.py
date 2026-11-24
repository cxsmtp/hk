from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx


METADATA_SCHEMA_VERSION = "hawk.gateway-benchmark-metadata/1.2"
SAMPLE_SCHEMA_VERSION = "hawk.gateway-benchmark-sample/1.2"
BENCHMARK_CONTRACT_VERSION = "hawk.gateway-overhead-benchmark/1.2"
METHODOLOGY_VERSION = "hawk.gateway-overhead-methodology/1.2"
STUB_CONTRACT = "hawk-deterministic-openai-stub/1.0"
MAX_STUB_REQUEST_BYTES = 1_048_576
SAFE_DECISIONS = {
    "allow",
    "warn",
    "redact",
    "hold_for_approval",
    "block",
}
SAFE_CONTROL_MODES = {
    "inline_allowed",
    "inline_prevented",
    "monitor_only",
    "post_execution",
    "shadow",
}
SAFE_FAILURE_CLASSES = {
    "none",
    "http_error",
    "timeout",
    "transport_error",
    "invalid_response",
    "upstream_proof_mismatch",
}
_SAFE_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,255}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _canonical_json_bytes(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    ).encode("utf-8")


def deterministic_client_options(
    *,
    timeout: Any,
    limits: Any,
) -> dict[str, Any]:
    return {
        "timeout": timeout,
        "limits": limits,
        "http2": False,
        "trust_env": False,
    }


def implementation_binding(repo_root: Path) -> dict[str, str]:
    paths = {
        "harness_sha256": Path(__file__).resolve(),
        "reporter_sha256": Path(__file__).resolve().with_name("test_report_summary.py"),
        "methodology_sha256": repo_root / "docs" / "benchmarks" / "methodology.md",
    }
    return {
        "contract_version": BENCHMARK_CONTRACT_VERSION,
        "methodology_version": METHODOLOGY_VERSION,
        **{
            name: _sha256_bytes(path.read_bytes())
            for name, path in paths.items()
        },
    }


def build_source_claim(
    *,
    revision: str,
    dirty: bool,
    dirty_patch_sha256: str | None,
    approved_patch_sha256: str | None,
) -> dict[str, Any]:
    if dirty_patch_sha256 is not None and _SHA256.fullmatch(dirty_patch_sha256) is None:
        raise ValueError("dirty patch hash must be lowercase SHA-256")
    if approved_patch_sha256 is not None and _SHA256.fullmatch(approved_patch_sha256) is None:
        raise ValueError("approved patch hash must be lowercase SHA-256")
    if dirty and dirty_patch_sha256 is None:
        raise ValueError("a dirty source tree requires its calculated patch hash")
    if not dirty and (dirty_patch_sha256 is not None or approved_patch_sha256 is not None):
        raise ValueError("a clean source tree must not declare patch hashes")
    if not dirty:
        eligible = True
        ineligibility_reason = None
    elif approved_patch_sha256 is None:
        eligible = False
        ineligibility_reason = "dirty_tree_without_approved_patch_hash"
    elif approved_patch_sha256 != dirty_patch_sha256:
        eligible = False
        ineligibility_reason = "dirty_tree_patch_hash_mismatch"
    else:
        eligible = True
        ineligibility_reason = None
    return {
        "revision": revision,
        "dirty": dirty,
        "dirty_patch_sha256": dirty_patch_sha256,
        "approved_patch_sha256": approved_patch_sha256,
        "performance_claim_eligible": eligible,
        "ineligibility_reason": ineligibility_reason,
    }


def _hash_framed(hasher: Any, label: bytes, value: bytes) -> None:
    hasher.update(len(label).to_bytes(8, "big"))
    hasher.update(label)
    hasher.update(len(value).to_bytes(8, "big"))
    hasher.update(value)


def source_snapshot(repo_root: Path) -> dict[str, Any]:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    status = subprocess.run(
        [
            "git",
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            ".",
        ],
        cwd=repo_root,
        check=True,
        capture_output=True,
    ).stdout
    if not status:
        return {
            "revision": revision,
            "dirty": False,
            "dirty_patch_sha256": None,
        }

    tracked_patch = subprocess.run(
        ["git", "diff", "--binary", "HEAD", "--", "."],
        cwd=repo_root,
        check=True,
        capture_output=True,
    ).stdout
    untracked_output = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard", "-z", "--", "."],
        cwd=repo_root,
        check=True,
        capture_output=True,
    ).stdout
    hasher = hashlib.sha256()
    _hash_framed(hasher, b"git-status-v1-z", status)
    _hash_framed(hasher, b"git-diff-binary-head", tracked_patch)
    for raw_relative_path in sorted(
        item for item in untracked_output.split(b"\0") if item
    ):
        relative_path = raw_relative_path.decode("utf-8", errors="surrogateescape")
        path = repo_root / relative_path
        if path.is_symlink():
            kind = b"symlink"
            content = os.readlink(path).encode("utf-8", errors="surrogateescape")
        elif path.is_file():
            kind = b"file"
            content = path.read_bytes()
        else:
            kind = b"special"
            content = b""
        _hash_framed(hasher, b"untracked-path", raw_relative_path)
        _hash_framed(hasher, b"untracked-kind", kind)
        _hash_framed(hasher, b"untracked-content", content)
    return {
        "revision": revision,
        "dirty": True,
        "dirty_patch_sha256": hasher.hexdigest(),
    }


def build_run_integrity(
    *,
    source_before: dict[str, Any],
    source_after: dict[str, Any],
    implementation_before: dict[str, str],
    implementation_after: dict[str, str],
) -> dict[str, bool]:
    return {
        "source_snapshot_stable": source_before == source_after,
        "implementation_snapshot_stable": implementation_before == implementation_after,
    }


def expected_upstream_proof(
    *,
    stub_session_nonce: str,
    request_nonce: str,
) -> str:
    if (
        _SHA256.fullmatch(stub_session_nonce) is None
        or _SHA256.fullmatch(request_nonce) is None
    ):
        raise ValueError("stub session and request nonces must be lowercase 256-bit hex")
    return _sha256_bytes(
        f"{STUB_CONTRACT}:{stub_session_nonce}:{request_nonce}".encode("ascii")
    )


def paired_leg_order(pair_index: int) -> tuple[str, str]:
    if isinstance(pair_index, bool) or not isinstance(pair_index, int) or pair_index < 0:
        raise ValueError("pair_index must be a non-negative integer")
    return ("baseline", "hawk") if pair_index % 2 == 0 else ("hawk", "baseline")


def _hawk_envelope(parsed_response: Any) -> dict[str, Any] | None:
    if not isinstance(parsed_response, dict):
        return None
    hawk = parsed_response.get("hawk")
    if isinstance(hawk, dict):
        return hawk
    detail = parsed_response.get("detail")
    if isinstance(detail, dict):
        nested_error = detail.get("error")
        if isinstance(nested_error, dict) and isinstance(nested_error.get("hawk"), dict):
            return nested_error["hawk"]
        if isinstance(detail.get("hawk"), dict):
            return detail["hawk"]
    return None


def _values_for_key(value: Any, key: str) -> list[Any]:
    matches: list[Any] = []
    if isinstance(value, dict):
        if key in value:
            matches.append(value[key])
        for item in value.values():
            matches.extend(_values_for_key(item, key))
    elif isinstance(value, list):
        for item in value:
            matches.extend(_values_for_key(item, key))
    return matches


def _valid_opaque_id(value: Any) -> bool:
    return isinstance(value, str) and _SAFE_IDENTIFIER.fullmatch(value) is not None


def _valid_evidence_node_ids(value: Any) -> bool:
    return (
        isinstance(value, list)
        and 0 < len(value) <= 1_024
        and all(_valid_opaque_id(item) for item in value)
    )


def _valid_evidence_bundle(value: Any) -> bool:
    return isinstance(value, dict) and _valid_opaque_id(
        value.get("evidence_bundle_id")
    )


def _closed_value(value: Any, allowed: set[str]) -> str:
    normalized = str(value or "").strip().lower()
    return normalized if normalized in allowed else "unknown"


def build_sample_record(
    *,
    run_id: str,
    pair_index: int,
    leg: Literal["baseline", "hawk"],
    sequence_index: int,
    excluded_warmup: bool,
    request_started_at: str,
    request_finished_at: str,
    e2e_ms: float,
    request_body: bytes,
    response_body: bytes,
    status_code: int,
    parsed_response: Any,
    upstream_proof: str,
    failure_class: str,
) -> dict[str, Any]:
    if leg not in {"baseline", "hawk"}:
        raise ValueError("leg must be baseline or hawk")
    if failure_class not in SAFE_FAILURE_CLASSES:
        raise ValueError("failure_class is not in the closed contract")
    outcome = "success" if 200 <= status_code < 300 and failure_class == "none" else "failure"
    if leg == "baseline":
        decision = "direct"
        control_mode = "direct"
        evidence_outcome = "not_applicable"
        receipt_outcome = "not_applicable"
    else:
        hawk = _hawk_envelope(parsed_response)
        decision = _closed_value(
            hawk.get("final_decision") if hawk else None,
            SAFE_DECISIONS,
        )
        control_mode = _closed_value(
            hawk.get("control_mode") if hawk else None,
            SAFE_CONTROL_MODES,
        )
        if hawk is None:
            evidence_outcome = "unknown"
            receipt_outcome = "unknown"
        else:
            evidence_node_values = _values_for_key(hawk, "evidence_node_ids")
            evidence_bundle_values = _values_for_key(hawk, "evidence_bundle")
            decision_receipt_values = _values_for_key(hawk, "decision_receipt_id")
            execution_receipt_values = _values_for_key(
                hawk,
                "execution_receipt_id",
            )
            has_evidence_field = bool(
                evidence_node_values or evidence_bundle_values
            )
            has_receipt_field = bool(
                decision_receipt_values or execution_receipt_values
            )
            evidence_outcome = (
                "present"
                if any(_valid_evidence_node_ids(item) for item in evidence_node_values)
                or any(_valid_evidence_bundle(item) for item in evidence_bundle_values)
                else ("missing" if has_evidence_field else "unknown")
            )
            receipt_outcome = (
                "present"
                if any(_valid_opaque_id(item) for item in decision_receipt_values)
                or any(_valid_opaque_id(item) for item in execution_receipt_values)
                else ("missing" if has_receipt_field else "unknown")
            )
    return {
        "schema_version": SAMPLE_SCHEMA_VERSION,
        "run_id": run_id,
        "pair_id": f"pair-{pair_index:06d}",
        "pair_index": pair_index,
        "leg": leg,
        "sequence_index": sequence_index,
        "excluded_warmup": excluded_warmup,
        "request_started_at": request_started_at,
        "request_finished_at": request_finished_at,
        "e2e_ms": round(float(e2e_ms), 6),
        "request_bytes": len(request_body),
        "request_payload_sha256": _sha256_bytes(request_body),
        # Bound after run metadata has its final finish timestamp.
        "metadata_sha256": "0" * 64,
        "response_bytes": len(response_body),
        "response_sha256": _sha256_bytes(response_body),
        "upstream_proof_sha256": _sha256_bytes(upstream_proof.encode("utf-8")),
        "status_code": status_code,
        "outcome": outcome,
        "decision": decision,
        "control_mode": control_mode,
        "evidence_outcome": evidence_outcome,
        "receipt_outcome": receipt_outcome,
        "failure_class": failure_class,
    }


class _DeterministicUpstreamHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "HawkBenchmarkStub/1.0"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def _send_json(
        self,
        *,
        status_code: int,
        payload: dict[str, Any],
        include_proof: bool = True,
    ) -> None:
        body = _canonical_json_bytes(payload)
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if include_proof:
            self.send_header("X-Hawk-Benchmark-Upstream", STUB_CONTRACT)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != "/health":
            self._send_json(status_code=404, payload={"error": "not_found"})
            return
        self._send_json(
            status_code=200,
            payload={
                "contract": STUB_CONTRACT,
                "deterministic": True,
                "session_nonce": self.server.session_nonce,  # type: ignore[attr-defined]
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] not in {"/chat/completions", "/v1/chat/completions"}:
            self._send_json(status_code=404, payload={"error": "not_found"})
            return
        try:
            content_length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            content_length = -1
        if content_length <= 0 or content_length > MAX_STUB_REQUEST_BYTES:
            self._send_json(status_code=413, payload={"error": "invalid_request_size"})
            return
        raw = self.rfile.read(content_length)
        try:
            request = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(status_code=400, payload={"error": "invalid_json"})
            return
        if not isinstance(request, dict):
            self._send_json(status_code=400, payload={"error": "invalid_request"})
            return
        messages = request.get("messages")
        request_nonce = ""
        if isinstance(messages, list):
            for message in messages:
                if not isinstance(message, dict):
                    continue
                content = message.get("content")
                if not isinstance(content, str):
                    continue
                match = re.search(
                    r"(?:^|\s)HAWK_BENCHMARK_REQUEST_NONCE=([0-9a-f]{64})(?:\s|$)",
                    content,
                )
                if match is not None:
                    request_nonce = match.group(1)
                    break
        if not request_nonce:
            self._send_json(
                status_code=400,
                payload={"error": "missing_benchmark_request_nonce"},
            )
            return
        proof = expected_upstream_proof(
            stub_session_nonce=self.server.session_nonce,  # type: ignore[attr-defined]
            request_nonce=request_nonce,
        )
        self._send_json(
            status_code=200,
            payload={
                "id": "hawk-benchmark-stub-response",
                "object": "chat.completion",
                "created": 0,
                "model": "hawk-deterministic-stub",
                "choices": [
                    {
                        "index": 0,
                        "message": {"role": "assistant", "content": proof},
                        "finish_reason": "stop",
                    }
                ],
                "usage": {
                    "prompt_tokens": 0,
                    "completion_tokens": 0,
                    "total_tokens": 0,
                },
            },
        )


def _is_loopback_hostname(hostname: str | None) -> bool:
    return str(hostname or "").lower() in {"127.0.0.1", "::1", "localhost"}


def _validate_url(
    value: str,
    *,
    label: str,
    require_loopback: bool,
) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} must be an absolute HTTP(S) URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError(f"{label} must not contain credentials, query, or fragment")
    if require_loopback and (parsed.scheme != "http" or not _is_loopback_hostname(parsed.hostname)):
        raise ValueError(f"{label} must use HTTP on a loopback host")
    return value.rstrip("/")


def _stub_health_url(upstream_url: str) -> str:
    parsed = urlsplit(upstream_url)
    host = parsed.hostname or ""
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    authority = host if parsed.port is None else f"{host}:{parsed.port}"
    return f"{parsed.scheme}://{authority}/health"


def _extract_upstream_proof(parsed_response: Any) -> str:
    if not isinstance(parsed_response, dict):
        return ""
    choices = parsed_response.get("choices")
    if not isinstance(choices, list) or not choices:
        return ""
    first = choices[0]
    if not isinstance(first, dict):
        return ""
    message = first.get("message")
    if not isinstance(message, dict):
        return ""
    content = message.get("content")
    return content if isinstance(content, str) else ""


def _parse_response(response_body: bytes) -> Any:
    try:
        return json.loads(response_body)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


async def _verify_stub(
    *,
    upstream_url: str,
    timeout: httpx.Timeout,
    limits: httpx.Limits,
) -> str:
    async with httpx.AsyncClient(
        **deterministic_client_options(timeout=timeout, limits=limits)
    ) as client:
        response = await client.get(_stub_health_url(upstream_url))
    if response.status_code != 200:
        raise RuntimeError("deterministic upstream stub health check failed")
    payload = _parse_response(response.content)
    if not isinstance(payload, dict):
        raise RuntimeError("deterministic upstream stub health payload is invalid")
    if (
        payload.get("contract") != STUB_CONTRACT
        or payload.get("deterministic") is not True
        or not isinstance(payload.get("session_nonce"), str)
        or _SHA256.fullmatch(payload["session_nonce"]) is None
    ):
        raise RuntimeError("upstream does not implement the required deterministic stub contract")
    return payload["session_nonce"]


async def _perform_leg(
    *,
    client: httpx.AsyncClient,
    url: str,
    headers: dict[str, str],
    request_body: bytes,
    run_id: str,
    pair_index: int,
    leg: Literal["baseline", "hawk"],
    sequence_index: int,
    excluded_warmup: bool,
    expected_proof: str,
) -> dict[str, Any]:
    wall_started = datetime.now(timezone.utc)
    started_at = _format_utc(wall_started)
    started = time.perf_counter()
    response_body = b""
    parsed_response: Any = None
    status_code = 0
    failure_class = "none"
    upstream_proof = ""
    try:
        response = await client.post(url, headers=headers, content=request_body)
        status_code = response.status_code
        response_body = response.content
        parsed_response = _parse_response(response_body)
        upstream_proof = _extract_upstream_proof(parsed_response)
        if not 200 <= status_code < 300:
            failure_class = "http_error"
        elif parsed_response is None:
            failure_class = "invalid_response"
        elif upstream_proof != expected_proof:
            failure_class = "upstream_proof_mismatch"
    except httpx.TimeoutException:
        failure_class = "timeout"
    except httpx.TransportError:
        failure_class = "transport_error"
    elapsed_ms = (time.perf_counter() - started) * 1000
    finished_at = _format_utc(
        wall_started + timedelta(milliseconds=elapsed_ms)
    )
    return build_sample_record(
        run_id=run_id,
        pair_index=pair_index,
        leg=leg,
        sequence_index=sequence_index,
        excluded_warmup=excluded_warmup,
        request_started_at=started_at,
        request_finished_at=finished_at,
        e2e_ms=elapsed_ms,
        request_body=request_body,
        response_body=response_body,
        status_code=status_code,
        parsed_response=parsed_response,
        upstream_proof=upstream_proof,
        failure_class=failure_class,
    )


async def _run_pair(
    *,
    pair_index: int,
    warmup_pairs: int,
    request_body: bytes,
    run_id: str,
    semaphore: asyncio.Semaphore,
    baseline_client: httpx.AsyncClient,
    hawk_client: httpx.AsyncClient,
    upstream_url: str,
    hawk_url: str,
    baseline_headers: dict[str, str],
    hawk_headers: dict[str, str],
    expected_proof: str,
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    async with semaphore:
        for leg_offset, leg in enumerate(paired_leg_order(pair_index)):
            client = baseline_client if leg == "baseline" else hawk_client
            url = upstream_url if leg == "baseline" else hawk_url
            headers = baseline_headers if leg == "baseline" else hawk_headers
            results.append(
                await _perform_leg(
                    client=client,
                    url=url,
                    headers=headers,
                    request_body=request_body,
                    run_id=run_id,
                    pair_index=pair_index,
                    leg=leg,  # type: ignore[arg-type]
                    sequence_index=(pair_index * 2) + leg_offset,
                    excluded_warmup=pair_index < warmup_pairs,
                    expected_proof=expected_proof,
                )
            )
    return results


async def _collect_stage(
    *,
    pair_indexes: range,
    **kwargs: Any,
) -> list[dict[str, Any]]:
    paired = await asyncio.gather(
        *(_run_pair(pair_index=pair_index, **kwargs) for pair_index in pair_indexes)
    )
    return [sample for pair in paired for sample in pair]


def _safe_identifier(value: str, *, label: str) -> str:
    if _SAFE_IDENTIFIER.fullmatch(value) is None:
        raise ValueError(f"{label} contains unsupported characters")
    return value


def _parse_flag(value: str) -> tuple[str, Any]:
    key, separator, raw_value = value.partition("=")
    if not separator:
        raise ValueError("--flag must use key=value")
    try:
        parsed_value = json.loads(raw_value)
    except json.JSONDecodeError:
        parsed_value = raw_value
    return key, parsed_value


def _memory_bytes() -> int | None:
    try:
        page_size = os.sysconf("SC_PAGE_SIZE")
        page_count = os.sysconf("SC_PHYS_PAGES")
        value = int(page_size) * int(page_count)
        return value if value > 0 else None
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _build_request_body(args: argparse.Namespace, *, request_nonce: str) -> bytes:
    payload = {
        "tenant_id": args.tenant_id,
        "ai_system_id": args.ai_system_id,
        "policy_version_id": args.policy_version_id,
        "provider": "openai",
        "model": "hawk-deterministic-stub",
        "messages": [
            {
                "role": "user",
                "content": (
                    "Return the deterministic benchmark response. "
                    f"HAWK_BENCHMARK_REQUEST_NONCE={request_nonce}"
                ),
            }
        ],
        "stream": False,
        "metadata": {
            "actor_type": "system",
            "actor_id": "hawk-benchmark-runner",
            "context_summary": "deterministic gateway benchmark",
        },
    }
    return _canonical_json_bytes(payload)


def _run_id() -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    suffix = os.urandom(4).hex()
    return f"gateway-{timestamp}-{suffix}"


def _write_artifacts(
    *,
    repo_root: Path,
    run_id: str,
    metadata: dict[str, Any],
    samples: list[dict[str, Any]],
    reporter: Any,
) -> Path:
    reporter.validate_benchmark_artifacts(metadata=metadata, samples=samples)
    run_dir = repo_root / "apps" / "api" / "artifacts" / "benchmarks" / run_id
    run_dir.mkdir(parents=True, exist_ok=False)
    (run_dir / "metadata.json").write_bytes(_canonical_json_bytes(metadata) + b"\n")
    raw_samples = b"".join(_canonical_json_bytes(sample) + b"\n" for sample in samples)
    (run_dir / "samples.ndjson").write_bytes(raw_samples)
    reporter.write_benchmark_summary(run_dir)
    return run_dir


def _load_reporter() -> Any:
    script_dir = Path(__file__).resolve().parent
    if str(script_dir) not in sys.path:
        sys.path.insert(0, str(script_dir))
    import test_report_summary

    return test_report_summary


async def run_benchmark(args: argparse.Namespace) -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    reporter = _load_reporter()
    upstream_url = _validate_url(
        args.upstream_url,
        label="upstream URL",
        require_loopback=True,
    )
    hawk_base_url = _validate_url(
        args.hawk_base_url,
        label="Hawk base URL",
        require_loopback=True,
    )
    bearer_token = os.environ.get("HAWK_BENCHMARK_BEARER_TOKEN", "").strip()
    if not bearer_token:
        raise RuntimeError("HAWK_BENCHMARK_BEARER_TOKEN is required")

    source_before = source_snapshot(repo_root)
    implementation_before = implementation_binding(repo_root)
    run_id = _run_id()
    request_nonce = os.urandom(32).hex()
    request_body = _build_request_body(args, request_nonce=request_nonce)
    timeout = httpx.Timeout(args.timeout_seconds)
    limits = httpx.Limits(
        max_connections=args.concurrency,
        max_keepalive_connections=args.concurrency,
    )
    stub_session_nonce = await _verify_stub(
        upstream_url=upstream_url,
        timeout=timeout,
        limits=limits,
    )
    expected_proof = expected_upstream_proof(
        stub_session_nonce=stub_session_nonce,
        request_nonce=request_nonce,
    )

    started_at = _utc_now()
    flags = dict(_parse_flag(value) for value in args.flag)
    common_kwargs = {
        "warmup_pairs": args.warmup_pairs,
        "request_body": request_body,
        "run_id": run_id,
        "semaphore": asyncio.Semaphore(args.concurrency),
        "upstream_url": upstream_url,
        "hawk_url": f"{hawk_base_url}/openai-compatible/v1/chat/completions",
        "baseline_headers": {
            "Accept": "application/json",
            "Content-Type": "application/json",
        },
        "hawk_headers": {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Authorization": f"Bearer {bearer_token}",
            "X-Tenant-ID": args.tenant_id,
        },
        "expected_proof": expected_proof,
    }
    client_options = deterministic_client_options(timeout=timeout, limits=limits)
    async with (
        httpx.AsyncClient(**client_options) as baseline_client,
        httpx.AsyncClient(**client_options) as hawk_client,
    ):
        client_kwargs = {
            **common_kwargs,
            "baseline_client": baseline_client,
            "hawk_client": hawk_client,
        }
        warmup_samples = await _collect_stage(
            pair_indexes=range(args.warmup_pairs),
            **client_kwargs,
        )
        measured_samples = await _collect_stage(
            pair_indexes=range(
                args.warmup_pairs,
                args.warmup_pairs + args.measured_pairs,
            ),
            **client_kwargs,
        )
    samples = sorted(
        [*warmup_samples, *measured_samples],
        key=lambda sample: sample["sequence_index"],
    )
    source_after = source_snapshot(repo_root)
    implementation_after = implementation_binding(repo_root)
    source = build_source_claim(
        revision=source_before["revision"],
        dirty=source_before["dirty"],
        dirty_patch_sha256=source_before["dirty_patch_sha256"],
        approved_patch_sha256=args.approved_patch_sha256,
    )
    metadata = {
        "schema_version": METADATA_SCHEMA_VERSION,
        "run_id": run_id,
        "environment": {
            "label": args.environment_label,
            "operating_system": f"{platform.system()} {platform.release()}",
            "python_version": platform.python_version(),
        },
        "hardware": {
            "machine": platform.machine() or "unknown",
            "processor": platform.processor() or "unknown",
            "logical_cpu_count": os.cpu_count(),
            "memory_bytes": _memory_bytes(),
        },
        "source": source,
        "target": {
            "topology": "loopback_endpoints",
            "hardware_scope": "runner_only",
            "source_scope": "benchmark_tools_only",
            "hawk_process_provenance": "not_verified_by_harness",
        },
        "implementation": implementation_before,
        "run_integrity": build_run_integrity(
            source_before=source_before,
            source_after=source_after,
            implementation_before=implementation_before,
            implementation_after=implementation_after,
        ),
        "governance_expectations": {
            "decision": "allow",
            "control_mode": "inline_allowed",
            "evidence_outcome": "present",
            "receipt_outcome": "present",
        },
        "policy_profile": args.policy_profile,
        "policy_version_id": args.policy_version_id,
        "flags": flags,
        "payload": {
            "bytes": len(request_body),
            "sha256": _sha256_bytes(request_body),
        },
        "concurrency": args.concurrency,
        "request_settings": {
            "timeout_seconds": float(args.timeout_seconds),
            "http_version": "HTTP/1.1",
            "connection_mode": "persistent-per-leg-pool",
        },
        "warmup_pairs": args.warmup_pairs,
        "measured_pairs": args.measured_pairs,
        "upstream_stub": {
            "contract": STUB_CONTRACT,
            "loopback_only": True,
            "response_proof_sha256": _sha256_bytes(expected_proof.encode("ascii")),
        },
        "started_at": started_at,
        "finished_at": _utc_now(),
    }
    metadata_sha256 = _sha256_bytes(_canonical_json_bytes(metadata))
    for sample in samples:
        sample["metadata_sha256"] = metadata_sha256
    return _write_artifacts(
        repo_root=repo_root,
        run_id=run_id,
        metadata=metadata,
        samples=samples,
        reporter=reporter,
    )


def _positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def _nonnegative_int(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def _sha256_arg(value: str) -> str:
    if _SHA256.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("must be a lowercase SHA-256 digest")
    return value


class _ThreadingHTTPServerV6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


def stub_server_class(host: str) -> type[ThreadingHTTPServer]:
    return _ThreadingHTTPServerV6 if host == "::1" else ThreadingHTTPServer


def _serve_stub(args: argparse.Namespace) -> int:
    if not _is_loopback_hostname(args.host):
        raise ValueError("the deterministic stub may only bind to a loopback host")
    server = stub_server_class(args.host)(
        (args.host, args.port),
        _DeterministicUpstreamHandler,
    )
    server.session_nonce = os.urandom(32).hex()  # type: ignore[attr-defined]
    display_host = f"[{args.host}]" if ":" in args.host else args.host
    print(f"Deterministic upstream stub listening on http://{display_host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Create paired raw direct-versus-Hawk gateway benchmark artifacts."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "source-state",
        help="Print the current revision and calculated dirty-patch SHA-256.",
    )

    stub = subparsers.add_parser("stub", help="Run the deterministic local OpenAI-compatible upstream.")
    stub.add_argument("--host", default="127.0.0.1")
    stub.add_argument("--port", type=_positive_int, default=8765)

    run = subparsers.add_parser("run", help="Run paired warmup and measured samples.")
    run.add_argument("--hawk-base-url", default="http://127.0.0.1:8000")
    run.add_argument(
        "--upstream-url",
        default="http://127.0.0.1:8765/v1/chat/completions",
    )
    run.add_argument("--tenant-id", required=True, type=lambda value: _safe_identifier(value, label="tenant-id"))
    run.add_argument("--ai-system-id", required=True, type=lambda value: _safe_identifier(value, label="ai-system-id"))
    run.add_argument(
        "--policy-version-id",
        required=True,
        type=lambda value: _safe_identifier(value, label="policy-version-id"),
    )
    run.add_argument("--policy-profile", required=True)
    run.add_argument("--environment-label", required=True)
    run.add_argument(
        "--approved-patch-sha256",
        type=_sha256_arg,
        default=None,
        help=(
            "Require an independently approved digest to equal the calculated "
            "dirty-tree patch hash; missing or mismatched values are ineligible."
        ),
    )
    run.add_argument("--warmup-pairs", type=_nonnegative_int, default=10)
    run.add_argument("--measured-pairs", type=_positive_int, default=100)
    run.add_argument("--concurrency", type=_positive_int, default=1)
    run.add_argument("--timeout-seconds", type=float, default=20.0)
    run.add_argument(
        "--flag",
        action="append",
        default=[],
        help="Record a non-sensitive benchmark flag as key=JSON_VALUE.",
    )
    return parser


def main() -> int:
    args = _build_parser().parse_args()
    if args.command == "stub":
        return _serve_stub(args)
    if args.command == "source-state":
        repo_root = Path(__file__).resolve().parents[2]
        print(_canonical_json_bytes(source_snapshot(repo_root)).decode("ascii"))
        return 0
    if args.timeout_seconds <= 0:
        raise ValueError("timeout-seconds must be positive")
    run_dir = asyncio.run(run_benchmark(args))
    print(run_dir)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
