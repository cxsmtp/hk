#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from typing import Any


DEFAULT_API_URL = "http://localhost:8000"


def _safe_str(value: Any) -> str:
    return str(value or "").strip()


def _is_loopback_host(host: str) -> bool:
    token = _safe_str(host).lower()
    return token in {"localhost", "127.0.0.1", "::1"}


def _validate_api_url(api_url: str, *, allow_http: bool) -> str:
    token = _safe_str(api_url)
    parsed = urllib.parse.urlparse(token)
    if not _safe_str(parsed.scheme) or not _safe_str(parsed.hostname):
        raise ValueError("Invalid API URL.")
    scheme = _safe_str(parsed.scheme).lower()
    if scheme == "https":
        return token.rstrip("/")
    if scheme == "http" and allow_http and _is_loopback_host(_safe_str(parsed.hostname)):
        return token.rstrip("/")
    raise ValueError("API URL must be HTTPS (HTTP only allowed for localhost when --allow-local-http-api is set).")


def _request_json(
    *,
    method: str,
    url: str,
    token: str,
    tenant_id: str,
    payload: dict[str, Any] | None = None,
    timeout: int = 20,
) -> dict[str, Any]:
    data = json.dumps(payload).encode("utf-8") if payload is not None else None
    req = urllib.request.Request(
        url=url,
        data=data,
        method=method,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "X-Tenant-ID": tenant_id,
        },
    )
    with urllib.request.urlopen(req, timeout=timeout) as response:
        body = response.read().decode("utf-8")
    return json.loads(body) if body else {}


def _print_json(title: str, payload: dict[str, Any]) -> None:
    print(f"\n{title}:")
    print(json.dumps(payload, indent=2))


def _bootstrap_slack(args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {
        "name": _safe_str(args.name) or "Slack Connector",
        "client_id": _safe_str(args.client_id),
        "client_secret": _safe_str(args.client_secret),
        "redirect_uri": _safe_str(args.redirect_uri),
        "create_connector": bool(args.create_connector),
        "enabled": bool(args.enabled),
        "polling_interval_minutes": max(1, int(args.polling_interval_minutes)),
    }
    if _safe_str(args.workspace_domain):
        payload["workspace_domain"] = _safe_str(args.workspace_domain)
    if _safe_str(args.signing_secret):
        payload["signing_secret"] = _safe_str(args.signing_secret)
    if _safe_str(args.state):
        payload["state"] = _safe_str(args.state)

    if _safe_str(args.scopes):
        payload["scopes"] = [token.strip() for token in _safe_str(args.scopes).split(",") if token.strip()]

    out = _request_json(
        method="POST",
        url=f"{args.api_url}/monitoring/connectors/bootstrap/slack",
        token=args.token,
        tenant_id=args.tenant_id,
        payload=payload,
    )
    _print_json("Slack bootstrap result", out)
    install_url = _safe_str(out.get("install_url"))
    if install_url:
        print(f"\nSlack install URL:\n{install_url}\n")

    connector_id = _safe_str(out.get("connector_id"))
    if args.run_pull and connector_id:
        pull = _request_json(
            method="POST",
            url=f"{args.api_url}/monitoring/connectors/{connector_id}/pull",
            token=args.token,
            tenant_id=args.tenant_id,
            payload={},
        )
        _print_json("Connector pull result", pull)
    return 0


def _bootstrap_microsoft(args: argparse.Namespace) -> int:
    payload: dict[str, Any] = {
        "name": _safe_str(args.name) or "Microsoft 365 Connector",
        "provider_key": _safe_str(args.provider_key) or "microsoft_365",
        "tenant_id": _safe_str(args.ms_tenant_id),
        "client_id": _safe_str(args.client_id),
        "redirect_uri": _safe_str(args.redirect_uri),
        "permission_mode": _safe_str(args.permission_mode) or "poc_safe",
        "include_optional_scopes": bool(args.include_optional_scopes),
        "create_connector": bool(args.create_connector),
        "enabled": bool(args.enabled),
        "polling_interval_minutes": max(1, int(args.polling_interval_minutes)),
        "credential_mode": _safe_str(args.credential_mode) or "client_secret",
    }
    if _safe_str(args.state):
        payload["state"] = _safe_str(args.state)

    credential_mode = _safe_str(args.credential_mode).lower() or "client_secret"
    if credential_mode == "client_assertion":
        payload["client_assertion"] = _safe_str(args.client_assertion)
        if _safe_str(args.client_assertion_type):
            payload["client_assertion_type"] = _safe_str(args.client_assertion_type)
    else:
        payload["client_secret"] = _safe_str(args.client_secret)

    out = _request_json(
        method="POST",
        url=f"{args.api_url}/monitoring/connectors/bootstrap/microsoft",
        token=args.token,
        tenant_id=args.tenant_id,
        payload=payload,
    )
    _print_json("Microsoft bootstrap result", out)
    consent_url = _safe_str(out.get("consent_url"))
    if consent_url:
        print(f"\nMicrosoft admin consent URL:\n{consent_url}\n")

    connector_id = _safe_str(out.get("connector_id"))
    if args.run_pull and connector_id:
        pull = _request_json(
            method="POST",
            url=f"{args.api_url}/monitoring/connectors/{connector_id}/pull",
            token=args.token,
            tenant_id=args.tenant_id,
            payload={},
        )
        _print_json("Connector pull result", pull)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Hawk connector bootstrap automation for Slack/Microsoft (POC-friendly)",
    )
    parser.add_argument("--api-url", default=os.getenv("HAWK_API_URL", DEFAULT_API_URL))
    parser.add_argument("--tenant-id", default=os.getenv("TENANT_ID", ""))
    parser.add_argument("--token", default=os.getenv("ACCESS_TOKEN", ""))
    parser.add_argument("--allow-local-http-api", action="store_true")

    sub = parser.add_subparsers(dest="command", required=True)

    slack = sub.add_parser("slack", help="Bootstrap Slack connector + install URL")
    slack.add_argument("--name", default="Slack Connector")
    slack.add_argument("--client-id", required=True)
    slack.add_argument("--client-secret", required=True)
    slack.add_argument("--redirect-uri", required=True)
    slack.add_argument("--signing-secret", default="")
    slack.add_argument("--workspace-domain", default="")
    slack.add_argument("--state", default="")
    slack.add_argument("--scopes", default="")
    slack.add_argument("--create-connector", action="store_true", default=True)
    slack.add_argument("--no-create-connector", action="store_false", dest="create_connector")
    slack.add_argument("--enabled", action="store_true", default=True)
    slack.add_argument("--disabled", action="store_false", dest="enabled")
    slack.add_argument("--polling-interval-minutes", type=int, default=15)
    slack.add_argument("--run-pull", action="store_true")

    microsoft = sub.add_parser("microsoft", help="Bootstrap Microsoft connector + admin consent URL")
    microsoft.add_argument("--name", default="Microsoft 365 Connector")
    microsoft.add_argument("--provider-key", default="microsoft_365")
    microsoft.add_argument("--ms-tenant-id", required=True)
    microsoft.add_argument("--client-id", required=True)
    microsoft.add_argument("--client-secret", default="")
    microsoft.add_argument("--credential-mode", default="client_secret")
    microsoft.add_argument("--client-assertion", default="")
    microsoft.add_argument("--client-assertion-type", default="")
    microsoft.add_argument("--redirect-uri", required=True)
    microsoft.add_argument("--permission-mode", default="poc_safe")
    microsoft.add_argument("--include-optional-scopes", action="store_true", default=True)
    microsoft.add_argument("--no-include-optional-scopes", action="store_false", dest="include_optional_scopes")
    microsoft.add_argument("--create-connector", action="store_true", default=True)
    microsoft.add_argument("--no-create-connector", action="store_false", dest="create_connector")
    microsoft.add_argument("--enabled", action="store_true", default=True)
    microsoft.add_argument("--disabled", action="store_false", dest="enabled")
    microsoft.add_argument("--polling-interval-minutes", type=int, default=15)
    microsoft.add_argument("--state", default="")
    microsoft.add_argument("--run-pull", action="store_true")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not _safe_str(args.tenant_id) or not _safe_str(args.token):
        print("Missing TENANT_ID/ACCESS_TOKEN (or --tenant-id/--token).", file=sys.stderr)
        return 2

    try:
        args.api_url = _validate_api_url(_safe_str(args.api_url), allow_http=bool(args.allow_local_http_api))
    except ValueError as exc:
        print(f"Invalid API URL: {exc}", file=sys.stderr)
        return 2

    try:
        if args.command == "slack":
            return _bootstrap_slack(args)
        if args.command == "microsoft":
            return _bootstrap_microsoft(args)
        parser.print_help()
        return 2
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read().decode("utf-8")
        except Exception:
            body = ""
        print(f"Bootstrap failed: HTTP {exc.code} {exc.reason}. {body}", file=sys.stderr)
        return 1
    except urllib.error.URLError as exc:
        print(f"Bootstrap failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

