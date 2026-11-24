#!/usr/bin/env python3
"""Register native-demo scan sources and run a bounded Deep Scan preflight.

This script is intentionally operator-facing and conservative:
- it uses the direct native API by default (http://127.0.0.1:8000);
- it registers metadata-only source prerequisites for demo surfaces;
- it runs Deep Scan preflight;
- it launches a scan only when the API reports at least one selected source is ready.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import getpass
import json
import os
import socket
import sys
import urllib.error
import urllib.request
import uuid


API_BASE = os.environ.get("TRINYA_API", "http://127.0.0.1:8000").rstrip("/")


def call(
    method: str,
    path: str,
    *,
    token: str | None = None,
    tenant_id: str | None = None,
    body: dict | None = None,
    idempotency_key: str | None = None,
) -> dict:
    data = None if body is None else json.dumps(body).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if tenant_id:
        headers["X-Tenant-ID"] = tenant_id
    if idempotency_key:
        headers["Idempotency-Key"] = idempotency_key
    request = urllib.request.Request(
        f"{API_BASE}{path}",
        data=data,
        method=method,
        headers=headers,
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:
            raw = response.read().decode("utf-8")
            return json.loads(raw) if raw else {}
    except urllib.error.HTTPError as error:
        detail = error.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {path} failed: HTTP {error.code}: {detail}") from error
    except urllib.error.URLError as error:
        raise RuntimeError(f"{method} {path} failed: {error.reason}") from error


def login() -> tuple[str, str]:
    email = os.environ.get("TRINYA_EMAIL") or input("Trinya owner/admin email: ").strip()
    password = os.environ.get("TRINYA_PASSWORD") or getpass.getpass("Trinya password: ")
    response = call("POST", "/auth/login", body={"email": email, "password": password})
    return response["selected_tenant_id"], response["access_token"]


def register_source(
    *,
    token: str,
    tenant_id: str,
    source_kind: str,
    target_identifier: str,
    expected_count: int,
    authority_reference: str,
    managed_browser_units: list[dict] | None = None,
) -> dict:
    expires_at = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    payload: dict = {
        "source_kind": source_kind,
        "target_identifier": target_identifier,
        "environment": "local_native_demo",
        "expected_count": expected_count,
        "authority_reference": authority_reference,
        "baseline_expires_at": expires_at,
    }
    if managed_browser_units is not None:
        payload["managed_browser_units"] = managed_browser_units
    return call(
        "POST",
        "/discovery/surface-sources",
        token=token,
        tenant_id=tenant_id,
        body=payload,
    )


def main() -> int:
    print(f"Using API: {API_BASE}")
    tenant_id, token = login()
    print(f"Tenant: {tenant_id}")

    safe_stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    hostname = "".join(ch if ch.isalnum() or ch in "._:-" else "-" for ch in socket.gethostname())
    authority_reference = f"local-native-demo-{safe_stamp}"

    registrations = []
    browser_endpoint_id = f"{hostname}-local-native-demo"[:128]
    source_specs = [
        {
            "source_kind": "managed_browser",
            "target_identifier": "local-native-managed-browser",
            "expected_count": 1,
            "managed_browser_units": [
                {
                    "endpoint_id": browser_endpoint_id,
                    "browser": "chrome",
                    "browser_profile": "default",
                }
            ],
        },
        {
            "source_kind": "mcp_environment",
            "target_identifier": "local-native-mcp",
            "expected_count": 1,
        },
        {
            "source_kind": "llm_gateway",
            "target_identifier": "local-native-llm-gateway",
            "expected_count": 1,
        },
        {
            "source_kind": "runtime_environment",
            "target_identifier": "local-native-runtime",
            "expected_count": 1,
        },
    ]

    for spec in source_specs:
        result = register_source(
            token=token,
            tenant_id=tenant_id,
            authority_reference=authority_reference,
            **spec,
        )
        registrations.append(result)
        print(
            "Registered "
            f"{result['target_type']}: target={result['target_id']} "
            f"collector={result['collector_id']} ready={result['ready']}"
        )

    target_ids = [item["target_id"] for item in registrations]
    collector_ids = list(dict.fromkeys(item["collector_id"] for item in registrations))
    preflight_body = {
        "target_ids": target_ids,
        "collector_ids": collector_ids,
        "required_target_ids": [],
        "time_window_minutes": 60,
        "customer_authorization_reference": authority_reference,
        "requested_mode": "partial",
    }
    preflight = call(
        "POST",
        "/discovery/scans/deep-scan/preflight",
        token=token,
        tenant_id=tenant_id,
        body=preflight_body,
    )

    print("")
    print("Deep Scan preflight:")
    print(f"  ready assignments: {preflight.get('ready_assignment_count', 0)}")
    print(f"  exhaustive claim permitted: {preflight.get('exhaustive_claim_permitted', False)}")
    for source in preflight.get("sources", []):
        print(
            "  - "
            f"{source.get('target_type')} "
            f"{source.get('state')} "
            f"mode={source.get('observation_mode')} "
            f"target={source.get('target_id')}"
        )

    if int(preflight.get("ready_assignment_count", 0)) <= 0:
        print("")
        print("No scan launched: no selected source is ready yet.")
        print("Next: create one fresh browser prompt event, endpoint heartbeat, or governed MCP event, then rerun this script.")
        return 0

    launched = call(
        "POST",
        "/discovery/scans/deep-scan",
        token=token,
        tenant_id=tenant_id,
        idempotency_key=f"local-native-demo-{uuid.uuid4()}",
        body={
            "name": "Local native demo Deep Scan",
            "preflight": preflight_body,
            "preflight_digest": preflight["preflight_digest"],
            "dry_run": False,
        },
    )
    scan = launched.get("scan", {})
    print("")
    print("Scan launched:")
    print(f"  scan_id: {scan.get('scan_id')}")
    print(f"  status: {scan.get('status')}")
    print(f"  ready assignments: {launched.get('ready_assignment_count')}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1)
