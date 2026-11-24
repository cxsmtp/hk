#!/usr/bin/env python3
"""Issue and install a short-lived, repository-bound Hawk demo authority."""

from __future__ import annotations

import getpass
import json
import os
import re
import stat
import subprocess
import tempfile
import tomllib
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path


API = os.environ.get("HAWK_API_BASE", "http://127.0.0.1:8000").rstrip("/")
AGENT_ID = "f97765af-0679-4ed2-97c8-eb928b79b710"
AI_SYSTEM_ID = "e9625bdf-653d-48da-8757-6c9a4ebf34a3"
REPOSITORY = "github.com/hawk-demo/governed-repo"
TOOLS = [
    "list_pull_requests",
    "pull_request_read",
    "create_branch",
    "create_or_update_file",
    "create_pull_request",
]
OWNER_ATTESTATION_MINUTES = 60
AUTHORITY_MINUTES = 55

CODEX_PROFILE = "hawk-github-approved-repo-demo"
CLAUDE_PROFILE = "hawk-github-pr-claude"
KEYCHAIN_SERVICE = "com.hawk.mcp-proxy.capability"
KEYCHAIN_ACCOUNT = "claude-desktop"
CAPABILITY_PATTERN = re.compile(r"^[A-Za-z0-9_-]{32,512}$")
NODE_COMMAND = "/usr/local/bin/node"
CLAUDE_LAUNCHER = str(
    Path(__file__).resolve().parents[3]
    / "packages/hawk-mcp-proxy/bin/hawk-github-pr-endpoint.mjs"
)


class RequestFailure(RuntimeError):
    def __init__(self, status: int, body: object):
        self.status = status
        self.body = body
        super().__init__(f"Hawk request failed with HTTP {status}: {body}")


def request(method: str, path: str, payload: dict | None = None, *, headers: dict | None = None):
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        API + path,
        data=data,
        method=method,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            raw = response.read()
            return response.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read()
        try:
            body = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            body = {"detail": "non-JSON error response"}
        raise RequestFailure(exc.code, body) from None
    except (OSError, TimeoutError) as exc:
        raise RuntimeError(f"Hawk API is unavailable at {API}; no local configuration was changed") from exc


def require_ok(method: str, path: str, payload: dict | None, headers: dict):
    return request(method, path, payload, headers=headers)[1]


def login() -> tuple[dict, dict]:
    email = input("Hawk owner/admin email: ").strip().lower()
    password = getpass.getpass("Hawk owner/admin password: ")
    try:
        body = request("POST", "/auth/login", {"email": email, "password": password})[1]
    finally:
        password = ""
    access_token = str(body.get("access_token") or "")
    tenant_id = str(body.get("selected_tenant_id") or "")
    if not access_token or not tenant_id:
        raise RuntimeError("Owner login did not return an active tenant session")
    return body, {"Authorization": f"Bearer {access_token}", "X-Tenant-ID": tenant_id}


def issue_authority(headers: dict) -> dict:
    require_ok(
        "POST",
        f"/ai-iam/agents/{AGENT_ID}/owner-attestation/refresh",
        {"expires_minutes": OWNER_ATTESTATION_MINUTES},
        headers,
    )
    purpose = require_ok(
        "POST",
        "/ai-iam/purpose-sessions",
        {
            "declared_purpose": "Time-limited governed GitHub repository demonstration",
            "purpose_category": "engineering_security_review",
            "business_function": "engineering",
            "expires_minutes": AUTHORITY_MINUTES,
            "approved_scope": {
                "identity_id": AGENT_ID,
                "identity_type": "agent",
                "purpose": {"name": "github_repository_demo"},
                "scope": {
                    "allowed_actions": ["file_read", "file_write"],
                    "allowed_tools": TOOLS,
                    "allowed_domains": ["github.com"],
                    "allowed_resources": [REPOSITORY],
                    "allowed_environments": ["production"],
                    "allowed_data_scopes": ["internal"],
                },
                "constraints": {"max_risk_level": "high"},
                "context": {"max_chain_depth": 1},
                "mode": "block",
            },
        },
        headers,
    )
    mint_payload = {
        "ai_system_id": AI_SYSTEM_ID,
        "scopes": ["file_read", "file_write"],
        "expires_minutes": AUTHORITY_MINUTES,
        "chain_depth": 1,
    }
    try:
        require_ok("POST", f"/ai-iam/agents/{AGENT_ID}/tokens", mint_payload, headers)
        raise RuntimeError("High-risk token mint unexpectedly bypassed approval")
    except RequestFailure as exc:
        detail = exc.body.get("detail") if isinstance(exc.body, dict) else None
        approval_id = str(detail.get("approval_request_id") or "") if isinstance(detail, dict) else ""
        if exc.status != 409 or not approval_id:
            raise
    require_ok(
        "POST",
        f"/enforcement/approvals/{approval_id}/decision",
        {"decision": "approve"},
        headers,
    )
    minted = require_ok(
        "POST",
        f"/ai-iam/agents/{AGENT_ID}/tokens",
        {**mint_payload, "approval_request_id": approval_id},
        headers,
    )
    capability = str(minted.get("capability_token") or "")
    token_id = str(minted.get("token_id") or "")
    if not capability or not token_id:
        raise RuntimeError("Token mint returned no usable capability")
    try:
        session = require_ok(
            "POST",
            "/gateway/mcp/sessions/open",
            {
                "ai_system_id": AI_SYSTEM_ID,
                "agent_id": AGENT_ID,
                "capability_token": capability,
                "expires_minutes": AUTHORITY_MINUTES,
                "session_context": {
                    "max_chain_depth": 1,
                    "connected_systems": ["github.com"],
                    "allowed_resources": [REPOSITORY],
                    "allowed_data_scope": ["internal"],
                    "allowed_environments": ["production"],
                    "allowed_actions": ["file_read", "file_write"],
                    "allowed_tools": TOOLS,
                    "data_classification": "internal",
                    "environment": "production",
                },
            },
            headers,
        )
        session_id = str(session.get("session_id") or "")
        if not session_id:
            raise RuntimeError("MCP session did not return an identifier")
    except Exception:
        revoke_token(headers, token_id)
        raise
    return {
        "approval_request_id": approval_id,
        "capability": capability,
        "mcp_session_id": session_id,
        "purpose_session_id": purpose.get("id"),
        "session_expires_at": session.get("expires_at"),
        "token_expires_at": minted.get("expires_at"),
        "token_id": token_id,
    }


def revoke_token(headers: dict, token_id: str) -> None:
    try:
        request("POST", f"/ai-iam/tokens/{token_id}/revoke", {}, headers=headers)
    except Exception:
        pass


def _atomic_write(path: Path, content: str, mode: int) -> None:
    fd, temp_name = tempfile.mkstemp(prefix=f".{path.name}.hawk-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temp_name, mode)
        os.replace(temp_name, path)
    finally:
        if os.path.exists(temp_name):
            os.unlink(temp_name)


def _replace_toml_arg(section: str, flag: str, value: str) -> str:
    pattern = rf'("{re.escape(flag)}"\s*,\s*\n\s*)"[^"]*"'
    updated, count = re.subn(pattern, lambda match: match.group(1) + json.dumps(value), section, count=1)
    if count != 1:
        raise RuntimeError(f"Could not safely update {flag} in {CODEX_PROFILE}")
    return updated


def update_codex_config(session_id: str, capability: str, token_id: str) -> Path:
    path = Path.home() / ".codex/config.toml"
    original = path.read_text(encoding="utf-8")
    header = f"[mcp_servers.{CODEX_PROFILE}]"
    start = original.find(header)
    if start < 0:
        raise RuntimeError(f"Missing Codex MCP profile {CODEX_PROFILE}")
    next_header = original.find("\n[", start + len(header))
    end = len(original) if next_header < 0 else next_header + 1
    section = original[start:end]
    section = _replace_toml_arg(section, "--session-id", session_id)
    section = _replace_toml_arg(section, "--capability-token", capability)
    section = _replace_toml_arg(section, "--chain-id", f"github-repo-demo-{token_id[:8]}")
    updated = original[:start] + section + original[end:]
    tomllib.loads(updated)
    redacted = re.sub(
        r'("--capability-token"\s*,\s*\n\s*)"[^"]*"',
        r'\1"<redacted>"',
        original,
    )
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(path.name + f".hawk-github-demo-{stamp}.redacted")
    backup.write_text(redacted, encoding="utf-8")
    os.chmod(backup, stat.S_IRUSR | stat.S_IWUSR)
    _atomic_write(path, updated, stat.S_IMODE(path.stat().st_mode))
    return backup


def _arg_value(args: list, flag: str) -> str:
    try:
        return str(args[args.index(flag) + 1])
    except (ValueError, IndexError):
        raise RuntimeError(f"Claude profile is missing {flag}") from None


def update_claude_config(path: Path, session_id: str) -> Path:
    original_text = path.read_text(encoding="utf-8")
    data = json.loads(original_text)
    profile = (data.get("mcpServers") or {}).get(CLAUDE_PROFILE)
    if not isinstance(profile, dict):
        raise RuntimeError(f"Missing Claude MCP profile {CLAUDE_PROFILE}")
    if profile.get("command") != NODE_COMMAND:
        raise RuntimeError("Claude profile has an unexpected Node executable")
    args = profile.get("args")
    if not isinstance(args, list) or not args or args[0] != CLAUDE_LAUNCHER:
        raise RuntimeError("Claude profile has an unexpected launcher path")
    if _arg_value(args, "--repository-scope") != REPOSITORY:
        raise RuntimeError("Claude profile repository scope does not match the approved repository")
    if _arg_value(args, "--keychain-service") != KEYCHAIN_SERVICE:
        raise RuntimeError("Claude profile has an unexpected Keychain service")
    if _arg_value(args, "--keychain-account") != KEYCHAIN_ACCOUNT:
        raise RuntimeError("Claude profile has an unexpected Keychain account")
    args[args.index("--session-id") + 1] = session_id
    updated = json.dumps(data, indent=2) + "\n"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(path.name + f".hawk-demo-{stamp}.backup")
    backup.write_text(original_text, encoding="utf-8")
    os.chmod(backup, stat.S_IRUSR | stat.S_IWUSR)
    _atomic_write(path, updated, stat.S_IMODE(path.stat().st_mode))
    return backup


def _security(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/usr/bin/security", *args],
        check=check,
        capture_output=True,
        text=True,
    )


def read_keychain() -> str | None:
    result = _security(
        "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, "-w", check=False
    )
    return result.stdout.rstrip("\n") if result.returncode == 0 else None


def write_keychain(capability: str) -> None:
    if CAPABILITY_PATTERN.fullmatch(capability) is None:
        raise RuntimeError("Refusing to store a malformed Hawk capability")
    subprocess.run(
        [
            "/usr/bin/security",
            "add-generic-password",
            "-U",
            "-s",
            KEYCHAIN_SERVICE,
            "-a",
            KEYCHAIN_ACCOUNT,
            "-w",
        ],
        input=capability + "\n",
        check=True,
        capture_output=True,
        text=True,
        shell=False,
    )


def restore_keychain(previous: str | None) -> None:
    if previous is None:
        _security("delete-generic-password", "-s", KEYCHAIN_SERVICE, "-a", KEYCHAIN_ACCOUNT, check=False)
    else:
        write_keychain(previous)


def require_claude_stopped() -> None:
    result = subprocess.run(["/usr/bin/pgrep", "-x", "Claude"], capture_output=True)
    if result.returncode == 0:
        raise RuntimeError("Fully quit Claude Desktop before refreshing its authority")


def rotate_claude_authority(config_path: Path, session_id: str, capability: str) -> Path:
    original_text = config_path.read_text(encoding="utf-8")
    original_mode = stat.S_IMODE(config_path.stat().st_mode)
    previous_keychain = read_keychain()
    try:
        write_keychain(capability)
        backup = update_claude_config(config_path, session_id)
        if read_keychain() != capability:
            raise RuntimeError("Claude Keychain authority verification failed")
        return backup
    except Exception as exc:
        rollback_errors = []
        try:
            restore_keychain(previous_keychain)
        except Exception as rollback_exc:
            rollback_errors.append(f"Keychain rollback failed: {rollback_exc}")
        try:
            _atomic_write(config_path, original_text, original_mode)
        except Exception as rollback_exc:
            rollback_errors.append(f"configuration rollback failed: {rollback_exc}")
        if rollback_errors:
            raise RuntimeError("; ".join(rollback_errors)) from exc
        raise


def install(client: str) -> dict:
    if client == "claude":
        require_claude_stopped()
    login_body, headers = login()
    authority = issue_authority(headers)
    try:
        if client == "codex":
            backup = update_codex_config(
                authority["mcp_session_id"], authority["capability"], authority["token_id"]
            )
        elif client == "claude":
            config_path = Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
            backup = rotate_claude_authority(
                config_path,
                authority["mcp_session_id"],
                authority["capability"],
            )
        else:
            raise RuntimeError(f"Unsupported client {client}")
    except Exception:
        revoke_token(headers, authority["token_id"])
        raise
    finally:
        authority["capability"] = ""
        login_body["access_token"] = ""
    return {
        "status": "created",
        "client": client,
        "repository": REPOSITORY,
        "approval_request_id": authority["approval_request_id"],
        "purpose_session_id": authority["purpose_session_id"],
        "token_id": authority["token_id"],
        "mcp_session_id": authority["mcp_session_id"],
        "expires_at": authority["session_expires_at"],
        "backup": str(backup),
    }
