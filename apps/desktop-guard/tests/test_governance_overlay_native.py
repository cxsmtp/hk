from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "endpoint-agent" / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

from build_macos_app import _compile_governance_overlay
from hawk_endpoint_agent.auth.device_key import EphemeralDeviceKeyProvider
from hawk_endpoint_agent.local_broker_auth import LocalBrokerAuthenticator


SOURCE = Path(__file__).resolve().parents[1] / "native" / "macos" / "HawkGovernanceOverlay.m"


def test_native_overlay_has_visible_spend_and_cost_provenance() -> None:
    source = SOURCE.read_text(encoding="utf-8")
    assert "Spend" in source
    assert "cost_usage" in source
    assert "Cost not reported" in source


def _signed_response() -> tuple[dict, str]:
    provider = EphemeralDeviceKeyProvider()
    identity = provider.ensure_key("endpoint-test")
    authenticator = LocalBrokerAuthenticator(
        endpoint_id="endpoint-test",
        provider=provider,
        identity=identity,
        clock=time.time,
    )
    return authenticator.sign_response(
        {
            "ok": True,
            "request_id": "status-1",
            "schema_version": 1,
            "state": "governed",
            "connected": True,
            "client_app": "Codex",
            "control_mode": "inline_allowed",
            "evidence_ref": "evidence-1",
        }
    ), identity.key_thumbprint


def test_native_overlay_verifies_signed_payload_and_ignores_tampered_outer_state(tmp_path) -> None:
    binary = tmp_path / "HawkGovernanceOverlay"
    _compile_governance_overlay(source=SOURCE, output=binary)
    response, thumbprint = _signed_response()
    response["state"] = "blocked"
    fixture = tmp_path / "signed-response.json"
    fixture.write_text(json.dumps(response), encoding="utf-8")

    verified = subprocess.run(
        [
            str(binary),
            "--verify-response",
            str(fixture),
            "--trusted-thumbprint",
            thumbprint,
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    assert json.loads(verified.stdout)["state"] == "governed"

    rejected = subprocess.run(
        [
            str(binary),
            "--verify-response",
            str(fixture),
            "--trusted-thumbprint",
            "0" * 64,
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert rejected.returncode == 2
