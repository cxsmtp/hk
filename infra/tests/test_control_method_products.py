from __future__ import annotations

import json
import hashlib
import copy
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parents[1] / "scripts"))
import verify_control_method_products as verifier


def test_fixed_manifest_has_exact_four_nonpromoting_methods() -> None:
    manifest = verifier.load_manifest()
    assert tuple(item["id"] for item in manifest["methods"]) == verifier.METHOD_IDS
    assert manifest["release_ready"] is False
    assert all(item["release_ready"] is False for item in manifest["methods"])


def test_new_local_provider_and_client_diagnostics_cannot_promote_target_gates() -> None:
    methods = {item["id"]: item for item in verifier.load_manifest()["methods"]}
    llm = methods["llm_gateway"]
    mcp = methods["mcp_gateway"]
    assert {
        "apps/api/app/core/config.py",
        "apps/api/app/services/brain/providers/openai_provider.py",
        "apps/api/app/services/brain/providers/provider_factory.py",
        "apps/api/app/services/ai_orchestration/providers.py",
        "apps/api/tests/test_openai_provider_reasoning_effort.py",
    }.issubset(set(llm["sources"]))
    for method in (llm, mcp):
        assert method["evidence"]["state"] == "target_required"
        assert method["target_check"]["state"] == "target_required"
        assert method["release_ready"] is False
        assert method["lifecycle_gates"]["upgrade"]["state"] == "target_required"
        assert method["lifecycle_gates"]["rollback"]["state"] == "target_required"


def test_official_sdk_local_sources_cannot_promote_claude_or_remote_target() -> None:
    mcp = next(method for method in verifier.load_manifest()["methods"] if method["id"] == "mcp_gateway")
    assert {
        "packages/hawk-mcp-proxy/package-lock.json",
        "packages/hawk-mcp-proxy/src/hawk-client.mjs",
        "packages/hawk-mcp-proxy/tests/hawk-client.test.mjs",
        "packages/hawk-mcp-proxy/examples/manual-terminal/read-only-mcp-server.mjs",
        "packages/hawk-mcp-proxy/examples/manual-terminal/official-mcp-sdk-client.mjs",
        "packages/hawk-mcp-proxy/tests/official-mcp-sdk-client.test.mjs",
        "apps/api/tests/test_mcp_proxy_authorize_contract.py",
    }.issubset(set(mcp["sources"]))
    assert mcp["evidence"]["state"] == "target_required"
    assert mcp["target_check"]["id"] == "real_claude_code_mcp_acceptance"
    assert mcp["target_check"]["state"] == "target_required"
    assert mcp["release_ready"] is False


def test_install_and_release_rollback_require_target_evidence() -> None:
    methods = {item["id"]: item for item in verifier.load_manifest()["methods"]}
    for method_id in ("browser_extension", "mcp_gateway", "llm_gateway"):
        gate = methods[method_id]["lifecycle_gates"]["clean_install"]
        assert gate["state"] == "target_required"
        assert "install" in gate["basis_reason"].lower()
    rollback = methods["llm_gateway"]["lifecycle_gates"]["rollback"]
    assert rollback["state"] == "target_required"
    assert "release-version rollback" in rollback["basis_reason"]
    assert methods["endpoint_agent"]["lifecycle_gates"]["clean_install"]["state"] == "blocked"


def test_manifest_rejects_path_traversal_and_shell_argv() -> None:
    manifest = verifier.load_manifest()
    manifest["methods"][0]["root"] = "../outside"
    with pytest.raises(verifier.ManifestError):
        verifier.validate_manifest(manifest)
    manifest = verifier.load_manifest()
    manifest["methods"][0]["checks"][0]["cwd"] = "/tmp"
    with pytest.raises(verifier.ManifestError):
        verifier.validate_manifest(manifest)
    manifest = verifier.load_manifest()
    manifest["methods"][0]["checks"][0]["argv"] = ["sh", "-c", "echo unsafe"]
    with pytest.raises(verifier.ManifestError):
        verifier.validate_manifest(manifest)


def test_run_check_reports_pass_fail_timeout_and_missing_executable(monkeypatch) -> None:
    passed = verifier.run_check({"name": "pass", "argv": [sys.executable, "-c", "print('ok')"], "cwd": "infra", "timeout_seconds": 5})
    assert passed["status"] == "passed"
    failed = verifier.run_check({"name": "fail", "argv": [sys.executable, "-c", "raise SystemExit(3)"], "cwd": "infra", "timeout_seconds": 5})
    assert failed["status"] == "failed" and failed["returncode"] == 3
    missing = verifier.run_check({"name": "missing", "argv": ["definitely-not-an-executable"], "cwd": "infra", "timeout_seconds": 5})
    assert missing["status"] == "missing_executable"
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: (_ for _ in ()).throw(subprocess.TimeoutExpired(kwargs.get("timeout"), args[0], output="timeout")))
    timed_out = verifier.run_check({"name": "timeout", "argv": [sys.executable, "-c", "pass"], "cwd": "infra", "timeout_seconds": 1})
    assert timed_out["status"] == "timeout"


def test_run_check_caps_output_and_execute_never_promotes(monkeypatch) -> None:
    class Result:
        returncode = 0
        stdout = "x" * (verifier.MAX_OUTPUT * 2)
        stderr = ""
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: Result())
    result = verifier.run_check({"name": "bounded", "argv": [sys.executable, "-c", "pass"], "cwd": "infra", "timeout_seconds": 1})
    assert len(result["output"]) <= verifier.MAX_OUTPUT
    report = verifier.execute("mcp_gateway")
    assert report["release_ready"] is False
    assert report["methods"][0]["release_ready"] is False


def test_all_passing_endpoint_checks_do_not_promote_blocked_acceptance(monkeypatch) -> None:
    monkeypatch.setattr(verifier, "run_check", lambda check: {"name": check["name"], "status": "passed"})
    method = verifier.execute("endpoint_agent")["methods"][0]
    assert method["repository_checks_passed"] is True
    assert method["acceptance_state"] == "blocked"
    assert method["lifecycle_gates"]["clean_install"]["state"] == "blocked"
    assert method["release_ready"] is False


def test_local_target_checks_cannot_satisfy_promotion_contract(monkeypatch) -> None:
    monkeypatch.setattr(verifier, "run_check", lambda check: {"name": check["name"], "status": "passed"})
    report = verifier.execute("all")
    assert report["release_ready"] is False
    assert report["promotion_requirements"]["minimum_distinct_successful_target_operations"] == 2
    assert report["promotion_requirements"]["distinct_current_and_previous_artifacts_required"] is True
    for method in report["methods"]:
        assert method["repository_checks_passed"] is True
        assert method["release_ready"] is False
        assert method["target_check"]["state"] in {"target_required", "blocked"}
        assert method["lifecycle_gates"]["clean_install"]["state"] != "repository_verified"
        assert method["lifecycle_gates"]["upgrade"]["state"] == "target_required"
        assert method["lifecycle_gates"]["rollback"]["state"] == "target_required"


def test_manifest_rejects_weakened_promotion_contract_and_target_metadata() -> None:
    for mutate in (
        lambda manifest: manifest.pop("promotion_requirements"),
        lambda manifest: manifest["promotion_requirements"].update(minimum_distinct_successful_target_operations=1),
        lambda manifest: manifest["promotion_requirements"].update(distinct_current_and_previous_artifacts_required=False),
        lambda manifest: manifest["methods"][1].pop("target_check"),
        lambda manifest: manifest["methods"][2]["target_check"].update(state="repository_verified"),
    ):
        manifest = copy.deepcopy(verifier.load_manifest())
        mutate(manifest)
        with pytest.raises(verifier.ManifestError):
            verifier.validate_manifest(manifest)


def test_digests_bind_manifest_version_and_sources_once() -> None:
    method = verifier.load_manifest()["methods"][2]
    paths = list(verifier.source_digests(method))
    assert paths == list(dict.fromkeys(["infra/control-method-products.json", method["version_source"], *method["sources"]]))
    for path, digest in verifier.source_digests(method).items():
        assert digest == hashlib.sha256((verifier.ROOT / path).read_bytes()).hexdigest()


@pytest.mark.parametrize("mutation", [
    lambda m: m["methods"][0].update(root="missing-product-root"),
    lambda m: m["methods"][0]["lifecycle_gates"]["allow"].pop("state"),
    lambda m: m["methods"][0]["lifecycle_gates"]["allow"].update(state="unknown"),
    lambda m: m["methods"][0]["lifecycle_gates"]["allow"].update(basis_reason=" "),
    lambda m: m["methods"][0]["checks"][0].update(env={"UNAPPROVED": "x"}),
    lambda m: m["methods"][0]["checks"].extend([dict(m["methods"][0]["checks"][0], name=f"extra_{i}", timeout_seconds=300) for i in range(4)]),
])
def test_manifest_rejects_invalid_root_gate_env_and_combined_timeout(mutation) -> None:
    manifest = copy.deepcopy(verifier.load_manifest())
    mutation(manifest)
    with pytest.raises(verifier.ManifestError):
        verifier.validate_manifest(manifest)


def test_cli_returns_nonzero_when_selected_check_fails(monkeypatch) -> None:
    monkeypatch.setattr(sys, "argv", ["verify_control_method_products.py", "--method", "mcp_gateway"])
    monkeypatch.setattr(verifier, "execute", lambda method_id=None: {"methods": [{"checks": [{"status": "failed"}]}]})
    assert verifier.main() == 1
