from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from .api import HawkApiClient, UnavailableApiClient
from .collectors import default_collector
from .config import DesktopGuardConfig
from .diagnostics import build_diagnostics
from .one_shot import evaluate_text_once
from .presenter import ConsolePresenter, MacDialogPresenter
from .runner import DesktopGuardRunner


#: The most of a prompt read from standard input (characters).
MAX_STDIN_PROMPT_CHARS = 1_000_000


def read_prompt_from_stdin(stream=None) -> str:
    """The prompt from standard input: never a command-line argument, which other local processes can read."""

    source = stream if stream is not None else sys.stdin
    return source.read(MAX_STDIN_PROMPT_CHARS)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Hawk Desktop Guard for Claude Desktop.")
    parser.add_argument("--config", default=None)
    parser.add_argument("--api-url", default=None)
    parser.add_argument("--access-token", default=None)
    parser.add_argument("--email", default=None)
    parser.add_argument("--password", default=None)
    parser.add_argument("--tenant-id", default=None)
    parser.add_argument("--application", default=None)
    parser.add_argument("--desktop-app", default=None)
    parser.add_argument("--machine-id", default=None)
    parser.add_argument("--poll-seconds", type=float, default=None)
    parser.add_argument("--dialog", action="store_true")
    parser.add_argument("--diagnose", action="store_true")
    parser.add_argument("--evaluate-text", default=None, help="For manual tests only: the text is visible to other local processes.")
    parser.add_argument(
        "--evaluate-stdin",
        action="store_true",
        help="Evaluate the prompt read from standard input (how the macOS Return guard passes it).",
    )
    parser.add_argument("--capture-method", default="desktop_guard_manual")
    args = parser.parse_args()
    # Read at once, so the process handing over the prompt is never left waiting on a full pipe.
    stdin_prompt = read_prompt_from_stdin() if args.evaluate_stdin else None

    config = DesktopGuardConfig.from_file_and_env(
        config_path=Path(args.config).expanduser() if args.config else None
    )
    config = DesktopGuardConfig(
        api_url=(args.api_url or config.api_url),
        access_token=args.access_token or config.access_token,
        email=args.email or config.email,
        password=args.password or config.password,
        tenant_id=args.tenant_id or config.tenant_id,
        application=args.application or config.application,
        desktop_app=args.desktop_app or config.desktop_app,
        machine_id=args.machine_id or config.machine_id,
        poll_seconds=args.poll_seconds if args.poll_seconds is not None else config.poll_seconds,
        dialog=bool(args.dialog or config.dialog),
        full_prompt_capture=config.full_prompt_capture,
    )

    if not config.has_auth:
        raise SystemExit("Provide --access-token/HAWK_ACCESS_TOKEN or --email/HAWK_EMAIL plus --password/HAWK_PASSWORD")

    collector = default_collector(
        application=config.application,
        desktop_app=config.desktop_app,
        machine_id=config.machine_id,
    )
    if args.diagnose:
        print(json.dumps(build_diagnostics(collector), indent=2, sort_keys=True))
        return
    try:
        api = (
            HawkApiClient(
                api_url=config.api_url,
                access_token=config.access_token or "",
                tenant_id=config.tenant_id,
                full_prompt_capture=config.full_prompt_capture,
            )
            if config.access_token
            else HawkApiClient.login(
                api_url=config.api_url,
                email=config.email or "",
                password=config.password or "",
                tenant_id=config.tenant_id,
                full_prompt_capture=config.full_prompt_capture,
            )
        )
    except Exception as exc:
        print(f"Hawk Desktop Guard: API unavailable at startup; continuing local-only ({exc})", file=sys.stderr)
        api = UnavailableApiClient(reason=str(exc))
    presenter = MacDialogPresenter() if config.dialog else ConsolePresenter()
    if args.evaluate_stdin or args.evaluate_text is not None:
        evaluate_text_once(
            text=stdin_prompt if args.evaluate_stdin else args.evaluate_text,
            application=config.application,
            desktop_app=config.desktop_app,
            machine_id=config.machine_id,
            capture_method=args.capture_method,
            api=api,
            presenter=presenter if config.dialog else None,
        )
        return
    runner = DesktopGuardRunner(
        collector=collector,
        api=api,
        presenter=presenter,
        poll_seconds=config.poll_seconds,
    )
    runner.run_forever()


if __name__ == "__main__":
    main()
