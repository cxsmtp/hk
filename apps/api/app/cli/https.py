"""The way back in when HTTPS settings made Settings → HTTPS unreachable (a certificate no browser accepts, HSTS…).
Changes Hawk AI's HTTPS mode; the front proxy picks it up within 5 seconds, without a restart. Recorded in the audit
log. Ported from CxMissionZero's scripts/https.mjs.

    python -m app.cli.https            what is set now
    python -m app.cli.https both       http and https side by side (the safe choice)
    python -m app.cli.https http       plain http only
    python -m app.cli.https https      https only

    docker compose -f deploy/compose.yaml exec api python -m app.cli.https both
"""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path

from app.core.config import settings
from app.services.https_manager import MODES, HttpsManager, set_mode_offline
from app.services.state_file import read_state


def main(argv: list[str] | None = None, *, data_dir: str | None = None, audit: Callable[..., None] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    directory = Path(data_dir or settings.hawk_data_dir)
    wanted = args[0].strip().lower() if args else ""
    current = read_state(directory / "https.json", fallback={}) or {}
    if not wanted:
        print(f"HTTPS mode: {current.get('mode') or '(not chosen on the Settings page; HTTPS=… decides)'}; HSTS {'on' if (current.get('hsts') or {}).get('enabled') else 'off'}.")
        print(f"Change it: python -m app.cli.https {'|'.join(MODES)}")
        return 0
    if wanted not in MODES:
        print(f"Use one of: {', '.join(MODES)}.", file=sys.stderr)
        return 1
    before, state = set_mode_offline(directory, wanted)
    # Handed to the front proxy now (it reloads within a second); the API picks the saved choice up within 5 seconds.
    try:
        HttpsManager(data_dir=directory).check()
    except Exception as error:  # noqa: BLE001 - the saved choice stands; the API says why at its next look
        print(f"! The proxy could not be given the new setting yet: {error}", file=sys.stderr)
    hsts_off = bool((before.get("hsts") or {}).get("enabled")) and not (state.get("hsts") or {}).get("enabled")
    reason = f"HTTPS mode set to {wanted} from the command line (python -m app.cli.https){'; HSTS turned off' if hsts_off else ''}."
    if audit is None:
        from app.services.https_runtime import audit_system

        audit = audit_system
    audit(action="https.mode.changed", outcome="changed", reason=reason, actor="app.cli.https", details={"from": before.get("mode") or "", "to": wanted, "commandLine": True})
    print(f"HTTPS mode is now: {wanted}. A running server switches within 5 seconds.")
    if wanted != "https":
        print("Open Settings → HTTPS (http works again) and fix the certificate there.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
