from __future__ import annotations

import hashlib
import os
import ssl
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse


SENSITIVE_QUERY_KEYS = {
    "token",
    "access_token",
    "api_key",
    "apikey",
    "secret",
    "password",
    "auth",
    "authorization",
    "tenant",
    "tenant_id",
}


@dataclass(frozen=True)
class SecurityDecision:
    allowed: bool
    reason: str
    details: dict[str, Any]


def _normalize_tls_version(value: str | None) -> str:
    token = str(value or "TLSv1.3").strip().upper().replace(" ", "")
    token = token.replace("TLS", "TLSV")
    if token in {"TLSV1.3", "1.3"}:
        return "TLSv1.3"
    if token in {"TLSV1.2", "1.2"}:
        return "TLSv1.2"
    return "TLSv1.3"


def sanitize_url_for_logs(url: str) -> str:
    parsed = urlparse(str(url or "").strip())
    host = parsed.hostname or ""
    scheme = parsed.scheme or ""
    path = parsed.path or ""
    return f"{scheme}://{host}{path}" if scheme or host else path


def reject_sensitive_query_string(url: str) -> SecurityDecision:
    parsed = urlparse(str(url or "").strip())
    if not parsed.query:
        return SecurityDecision(True, "ok", {"url": sanitize_url_for_logs(url)})

    query_pairs = parse_qsl(parsed.query, keep_blank_values=True)
    for key, value in query_pairs:
        key_norm = str(key or "").strip().lower()
        if key_norm in SENSITIVE_QUERY_KEYS:
            return SecurityDecision(
                False,
                "query_contains_sensitive_key",
                {
                    "query_key": key_norm,
                    "url": sanitize_url_for_logs(url),
                },
            )
        if any(marker in key_norm for marker in ("secret", "token", "auth", "password")):
            return SecurityDecision(
                False,
                "query_contains_sensitive_marker",
                {
                    "query_key": key_norm,
                    "url": sanitize_url_for_logs(url),
                },
            )
        value_norm = str(value or "").strip().lower()
        if len(value_norm) > 20 and ("eyj" in value_norm[:8] or "sk-" in value_norm):
            return SecurityDecision(
                False,
                "query_value_looks_secret",
                {
                    "query_key": key_norm,
                    "url": sanitize_url_for_logs(url),
                },
            )

    return SecurityDecision(True, "ok", {"url": sanitize_url_for_logs(url)})


def validate_transport_security(
    *,
    endpoint_url: str,
    transport_policy: dict[str, Any] | None,
    egress_policy: dict[str, Any] | None,
) -> SecurityDecision:
    url = str(endpoint_url or "").strip()
    parsed = urlparse(url)
    policy = dict(transport_policy or {})
    egress = dict(egress_policy or {})

    if not parsed.scheme or not parsed.hostname:
        return SecurityDecision(False, "invalid_endpoint_url", {"url": sanitize_url_for_logs(url)})

    if str(parsed.scheme).lower() != "https":
        return SecurityDecision(False, "https_required", {"url": sanitize_url_for_logs(url)})

    query_check = reject_sensitive_query_string(url)
    if not query_check.allowed:
        return query_check

    minimum_tls = _normalize_tls_version(str(policy.get("minimum_tls_version") or "TLSv1.3"))
    allow_tls12_fallback = bool(policy.get("allow_tls12_fallback", True))
    if minimum_tls == "TLSv1.2" and not allow_tls12_fallback:
        return SecurityDecision(
            False,
            "tls_policy_inconsistent",
            {"minimum_tls_version": minimum_tls},
        )

    allowed_hosts = [str(item).strip().lower() for item in (egress.get("allowed_hosts") or []) if str(item).strip()]
    if allowed_hosts:
        host = str(parsed.hostname or "").lower()
        if host not in allowed_hosts:
            return SecurityDecision(
                False,
                "host_not_in_egress_allowlist",
                {"host": host, "allowed_hosts": allowed_hosts},
            )

    return SecurityDecision(
        True,
        "ok",
        {
            "url": sanitize_url_for_logs(url),
            "minimum_tls_version": minimum_tls,
            "allow_tls12_fallback": allow_tls12_fallback,
            "mtls_required": bool(policy.get("require_mtls", False)),
            "certificate_pinning": bool(policy.get("pinned_certificate_sha256")),
        },
    )


def build_ssl_context(
    *,
    transport_policy: dict[str, Any] | None,
    auth_config: dict[str, Any] | None,
    use_system_trust_store: bool = False,
) -> ssl.SSLContext:
    policy = dict(transport_policy or {})
    auth = dict(auth_config or {})

    if use_system_trust_store:
        try:
            import truststore  # type: ignore

            ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        except Exception:
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)
    else:
        explicit_ca_bundle = str(policy.get("ca_bundle_path") or auth.get("ca_bundle_path") or "").strip()
        env_ca_bundle = str(os.getenv("SSL_CERT_FILE") or os.getenv("REQUESTS_CA_BUNDLE") or "").strip()
        ca_bundle_path = explicit_ca_bundle or env_ca_bundle
        if ca_bundle_path and not Path(ca_bundle_path).is_file():
            raise ValueError("invalid_ca_bundle_path")

        if not ca_bundle_path:
            try:
                import certifi  # type: ignore

                certifi_path = str(certifi.where() or "").strip()
                if certifi_path and Path(certifi_path).is_file():
                    ca_bundle_path = certifi_path
            except Exception:
                ca_bundle_path = ""

        if ca_bundle_path:
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH, cafile=ca_bundle_path)
        else:
            ctx = ssl.create_default_context(purpose=ssl.Purpose.SERVER_AUTH)

    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.options |= ssl.OP_NO_COMPRESSION

    minimum_tls = _normalize_tls_version(str(policy.get("minimum_tls_version") or "TLSv1.3"))
    allow_tls12_fallback = bool(policy.get("allow_tls12_fallback", True))
    if minimum_tls == "TLSv1.3":
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    else:
        if allow_tls12_fallback:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        else:
            ctx.minimum_version = ssl.TLSVersion.TLSv1_3

    cert_file = str(auth.get("mtls_client_cert_path") or "").strip()
    key_file = str(auth.get("mtls_client_key_path") or "").strip()
    if cert_file and key_file:
        ctx.load_cert_chain(certfile=cert_file, keyfile=key_file)
    elif bool(policy.get("require_mtls", False)):
        raise ValueError("mtls_required_but_no_client_cert")

    return ctx


def minimal_headers(base: dict[str, str] | None = None) -> dict[str, str]:
    safe: dict[str, str] = {}
    for key, value in (base or {}).items():
        k = str(key or "").strip()
        if not k:
            continue
        k_norm = k.lower()
        if k_norm.startswith("x-debug") or k_norm.startswith("x-internal"):
            continue
        safe[k] = str(value or "")
    if "User-Agent" not in safe and "user-agent" not in {k.lower() for k in safe}:
        safe["User-Agent"] = "hawk-ai-risk-intel/1.0"
    return safe


def assert_payload_minimization(*, payload: dict[str, Any], allowed_keys: set[str]) -> SecurityDecision:
    keys = {str(key) for key in payload.keys()}
    extra = sorted(keys.difference(allowed_keys))
    if extra:
        return SecurityDecision(
            False,
            "payload_contains_disallowed_fields",
            {"disallowed_fields": extra},
        )
    return SecurityDecision(True, "ok", {"field_count": len(keys)})


def verify_pinned_certificate_hash(*, certificate_bytes: bytes, pinned_sha256: list[str] | None) -> SecurityDecision:
    pins = [str(item).strip().lower() for item in (pinned_sha256 or []) if str(item).strip()]
    if not pins:
        return SecurityDecision(True, "pinning_not_configured", {})

    digest = hashlib.sha256(certificate_bytes).hexdigest().lower()
    if digest in pins:
        return SecurityDecision(True, "certificate_pin_match", {"fingerprint_sha256": digest})
    return SecurityDecision(
        False,
        "certificate_pin_mismatch",
        {
            "fingerprint_sha256": digest,
        },
    )
