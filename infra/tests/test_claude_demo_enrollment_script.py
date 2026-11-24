from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "infra" / "scripts" / "enroll_claude_demo.sh"


def test_claude_demo_enrollment_is_resume_safe_and_secretless() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "set -euo pipefail" in script
    assert "umask 077" in script
    assert '"$HAWK_STACK" prepare' in script
    assert script.count('"$HAWK_STACK" up') == 2
    assert "validate-claude" in script
    assert '"$HAWK_API/auth/login"' in script
    assert "macos_secure_enclave" in script
    assert "--security-profile development" in script
    assert "claude-demo-enrollment.json" in script
    assert "credential_registered" in script
    assert "NATIVE_CONTROL_ROUTE_BINDINGS_JSON" in script
    assert "runtime_control" in script
    assert "--provider claude_code" in script
    assert "--scope user" in script
    assert "--hawk-managed-hook" in script
    state_start = script.index('HAWK_STATE_PAYLOAD="$(')
    state_end = script.index('printf \'%s\\n\' "$HAWK_STATE_PAYLOAD"', state_start)
    state_payload = script[state_start:state_end]
    assert "access_token" not in state_payload
    assert "HAWK_TOKEN" not in state_payload
    assert "Password123!" not in script
    assert '$($HAWK_PY' not in script
    assert '$($HAWK_IDENTITY' not in script
    assert 'HAWK_VALIDATION="$("$HAWK_PY"' in script
    assert 'HAWK_IDENTITY_JSON="$("$HAWK_IDENTITY"' in script
    assert 'HAWK_INSTALL_RESULT="$("$HAWK_PY"' in script
    assert "curl -fsS --fail-with-body" not in script
    assert script.count("curl -sS --fail-with-body") == 5
    assert 'HAWK_CLAUDE_VERIFIED_BINARY="$HOME/.local/share/claude/versions/2.1.183"' in script
    assert '/bin/ln -sfn "$HAWK_CLAUDE_VERIFIED_BINARY" "$HAWK_CLAUDE_BINARY"' in script
    assert 'validate-claude --binary "$HAWK_CLAUDE_VERIFIED_BINARY"' in script
    assert '"DISABLE_AUTOUPDATER":"1"' in script
    assert '"DISABLE_UPDATES":"1"' in script
    assert 'Claude Code launcher is not a symlink; refusing to replace it.' in script


def test_claude_demo_enrollment_preserves_existing_claude_settings() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "$HAWK_CLAUDE_SETTINGS.hawk-backup-" in script
    assert '/bin/cp -p "$HAWK_CLAUDE_SETTINGS" "$HAWK_CLAUDE_BACKUP"' in script
    assert "uninstall" not in script
    assert "rm -rf" not in script
