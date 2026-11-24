from __future__ import annotations

import json
import socket
import shutil
import ssl
import subprocess
from dataclasses import dataclass
from typing import Any, Callable
from urllib import request as urllib_request
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from app.db.models.external_risk import ExternalRiskSource
from app.services.outbound_destination_policy import (
    OutboundDestinationPolicy,
    PinnedHTTPSHandler,
    ValidatingHTTPRedirectHandler,
    build_outbound_destination_policy,
    canonical_origin,
)
from app.services.external_risk_intel.transport_security import (
    SecurityDecision,
    build_ssl_context,
    minimal_headers,
    validate_transport_security,
    verify_pinned_certificate_hash,
)


DEFAULT_SOURCE_ENDPOINTS: dict[str, str] = {
    "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
    "mitre": "https://cveawg.mitre.org/api/cve",
    "cisa_kev": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "github": "https://api.github.com/advisories",
    "osv": "https://api.osv.dev/v1/querybatch",
}


def _external_risk_destination_policy() -> OutboundDestinationPolicy:
    return build_outbound_destination_policy(
        {
            f"external-risk:{source}": (canonical_origin(endpoint),)
            for source, endpoint in DEFAULT_SOURCE_ENDPOINTS.items()
        }
    )


class ExternalFeedFetchError(RuntimeError):
    pass


@dataclass(frozen=True)
class ExternalFeedResult:
    source: str
    endpoint_url: str
    records: list[dict[str, Any]]
    metadata: dict[str, Any]


def _allow_curl_tls_fallback(source: ExternalRiskSource) -> bool:
    policy = dict(source.transport_policy or {})
    # Keep fallback explicit for public feed pulls; authenticated feeds stay on stdlib TLS path only.
    return bool(policy.get("allow_curl_tls_fallback", True)) and str(source.auth_mode or "none").strip().lower() == "none"


def _ssl_chain_error(exc: BaseException | None) -> bool:
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, ssl.SSLCertVerificationError):
            return True
        reason = getattr(current, "reason", None)
        if isinstance(reason, BaseException) and id(reason) not in visited:
            current = reason
            continue
        message = str(current).lower()
        if "certificate_verify_failed" in message or "unable to get local issuer certificate" in message:
            return True
        current = current.__cause__ if isinstance(current.__cause__, BaseException) else None
    return False


def _dns_resolution_error(exc: BaseException | None) -> bool:
    current: BaseException | None = exc
    visited: set[int] = set()
    while current is not None and id(current) not in visited:
        visited.add(id(current))
        if isinstance(current, socket.gaierror):
            return True
        reason = getattr(current, "reason", None)
        if isinstance(reason, BaseException) and id(reason) not in visited:
            current = reason
            continue
        errno = getattr(current, "errno", None)
        if errno in {8, -2}:
            return True
        message = str(current).lower()
        if any(
            marker in message
            for marker in (
                "nodename nor servname provided",
                "name or service not known",
                "temporary failure in name resolution",
                "could not resolve host",
            )
        ):
            return True
        current = current.__cause__ if isinstance(current.__cause__, BaseException) else None
    return False


def _auth_headers(source: ExternalRiskSource) -> dict[str, str]:
    mode = str(source.auth_mode or "none").strip().lower()
    config = dict(source.auth_config or {})
    headers: dict[str, str] = {}

    if mode == "bearer":
        token = str(config.get("bearer_token") or "").strip()
        if not token:
            raise ExternalFeedFetchError("bearer_token_missing")
        headers["Authorization"] = f"Bearer {token}"
    elif mode == "api_key":
        key = str(config.get("api_key") or "").strip()
        if not key:
            raise ExternalFeedFetchError("api_key_missing")
        header_name = str(config.get("api_key_header") or "X-API-Key").strip() or "X-API-Key"
        headers[header_name] = key
    elif mode == "none":
        pass
    else:
        raise ExternalFeedFetchError(f"unsupported_auth_mode:{mode}")

    return headers


def _decode_json_payload(raw: bytes) -> dict[str, Any]:
    text = raw.decode("utf-8") if raw else "{}"
    parsed = json.loads(text or "{}")
    if not isinstance(parsed, dict):
        return {"records": parsed if isinstance(parsed, list) else []}
    return parsed


def _extract_payload_rows(source_name: str, payload: dict[str, Any]) -> list[dict[str, Any]]:
    source = str(source_name or "").strip().lower()
    if source == "nvd":
        rows = payload.get("vulnerabilities")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    if source == "mitre":
        rows = payload.get("vulnerabilities") or payload.get("items") or payload.get("records")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    if source == "cisa_kev":
        rows = payload.get("vulnerabilities")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    if source in {"github", "github_advisory"}:
        rows = payload.get("records") or payload.get("advisories")
        if isinstance(rows, list):
            return [row for row in rows if isinstance(row, dict)]
    if source == "osv":
        direct_rows = payload.get("vulns")
        if isinstance(direct_rows, list):
            return [row for row in direct_rows if isinstance(row, dict)]
        batch_rows = payload.get("results")
        if isinstance(batch_rows, list):
            normalized_rows: list[dict[str, Any]] = []
            for batch_row in batch_rows:
                if not isinstance(batch_row, dict):
                    continue
                vulns = batch_row.get("vulns")
                if isinstance(vulns, list):
                    for vuln in vulns:
                        if isinstance(vuln, dict):
                            normalized_rows.append(vuln)
            return normalized_rows

    generic_rows = payload.get("records") if isinstance(payload.get("records"), list) else None
    if generic_rows is not None:
        return [row for row in generic_rows if isinstance(row, dict)]

    return []


def _verify_trust_policy(payload: dict[str, Any], source: ExternalRiskSource) -> SecurityDecision:
    trust = dict(source.source_trust_policy or {})
    require_integrity_hint = bool(trust.get("require_integrity_signature", False))
    if not require_integrity_hint:
        return SecurityDecision(True, "ok", {"integrity": "not_required"})

    if "signature" in payload or "integrity" in payload:
        return SecurityDecision(True, "ok", {"integrity": "hint_present"})

    return SecurityDecision(False, "integrity_signature_missing", {"source": source.source})


def _append_query_defaults(endpoint_url: str, defaults: dict[str, str]) -> str:
    parsed = urlparse(endpoint_url)
    query_pairs = dict(parse_qsl(parsed.query, keep_blank_values=True))
    changed = False
    for key, value in defaults.items():
        if key not in query_pairs:
            query_pairs[key] = value
            changed = True
    if not changed:
        return endpoint_url
    updated = parsed._replace(query=urlencode(query_pairs))
    return urlunparse(updated)


def _default_osv_queries(source: ExternalRiskSource) -> list[dict[str, Any]]:
    configured = (source.routing_policy or {}).get("osv_querybatch")
    if isinstance(configured, list):
        queries = [item for item in configured if isinstance(item, dict)]
        if queries:
            return queries
    return [
        {"package": {"name": "openai", "ecosystem": "PyPI"}},
        {"package": {"name": "anthropic", "ecosystem": "PyPI"}},
        {"package": {"name": "langchain", "ecosystem": "PyPI"}},
        {"package": {"name": "openai", "ecosystem": "npm"}},
    ]


def _prepare_request(source: ExternalRiskSource, endpoint_url: str, headers: dict[str, str]) -> urllib_request.Request:
    source_name = str(source.source or "").strip().lower()
    if source_name == "nvd":
        per_page = int((source.routing_policy or {}).get("nvd_results_per_page") or 200)
        safe_per_page = str(max(1, min(per_page, 2000)))
        endpoint_url = _append_query_defaults(
            endpoint_url,
            {"resultsPerPage": safe_per_page, "startIndex": "0"},
        )

    if source_name == "osv":
        body = json.dumps({"queries": _default_osv_queries(source)}).encode("utf-8")
        request_headers = dict(headers)
        request_headers.setdefault("Content-Type", "application/json")
        return urllib_request.Request(url=endpoint_url, headers=request_headers, data=body, method="POST")

    return urllib_request.Request(url=endpoint_url, headers=headers, method="GET")


def _open_source_request(
    source: ExternalRiskSource,
    request: urllib_request.Request,
    *,
    timeout_seconds: float,
    context: ssl.SSLContext,
    destination_policy: OutboundDestinationPolicy | None,
):
    policy = destination_policy or _external_risk_destination_policy()
    source_key = f"external-risk:{str(source.source or '').strip().lower()}"
    opener = _build_source_opener(
        policy=policy,
        source_key=source_key,
        context=context,
    )
    return opener.open(request, timeout=timeout_seconds)


def _build_source_opener(
    *,
    policy: OutboundDestinationPolicy,
    source_key: str,
    context: ssl.SSLContext,
):
    return urllib_request.build_opener(
        urllib_request.ProxyHandler({}),
        PinnedHTTPSHandler(policy=policy, source=source_key, context=context),
        ValidatingHTTPRedirectHandler(policy=policy, source=source_key),
    )


def _fetch_json_via_curl(
    *,
    source: ExternalRiskSource,
    request: urllib_request.Request,
    timeout_seconds: float,
    destination_policy: OutboundDestinationPolicy,
) -> dict[str, Any]:
    curl_path = shutil.which("curl")
    if not curl_path:
        raise ExternalFeedFetchError("curl_not_available")

    method = str(request.get_method() or "GET").upper()
    url = str(getattr(request, "full_url", "") or "").strip()
    if not url:
        raise ExternalFeedFetchError("curl_missing_request_url")
    source_key = f"external-risk:{str(source.source or '').strip().lower()}"
    destination = destination_policy.validate(url, source=source_key)
    address = destination.approved_address
    curl_address = f"[{address}]" if ":" in address else address

    cmd: list[str] = [
        curl_path,
        "--fail",
        "--silent",
        "--show-error",
        "--noproxy",
        "*",
        "--proto",
        "=https",
        "--resolve",
        f"{destination.hostname}:{destination.port}:{curl_address}",
        "--connect-timeout",
        str(max(2, int(timeout_seconds // 2) or 2)),
        "--max-time",
        str(max(4, int(timeout_seconds))),
        "-X",
        method,
    ]

    for key, value in request.header_items():
        key_norm = str(key or "").strip().lower()
        # Never pass auth-bearing headers via subprocess args.
        if key_norm in {"authorization", "proxy-authorization", "x-api-key"}:
            raise ExternalFeedFetchError("curl_fallback_not_allowed_for_auth_headers")
        cmd.extend(["-H", f"{key}: {value}"])

    payload = request.data
    if payload:
        body_text = payload.decode("utf-8", errors="ignore")
        cmd.extend(["--data-binary", body_text])

    cmd.append(url)

    run = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if run.returncode != 0:
        stderr = str(run.stderr or "").strip()
        raise ExternalFeedFetchError(
            f"curl_tls_fallback_failed:{source.source}:{stderr or f'code_{run.returncode}'}"
        )
    return _decode_json_payload(str(run.stdout or "{}").encode("utf-8"))


def fetch_source_records(
    source: ExternalRiskSource,
    *,
    timeout_seconds: float = 20.0,
    fetcher: Callable[[ExternalRiskSource], dict[str, Any]] | None = None,
    destination_policy: OutboundDestinationPolicy | None = None,
) -> ExternalFeedResult:
    if fetcher is not None:
        payload = fetcher(source)
        if not isinstance(payload, dict):
            raise ExternalFeedFetchError("fetcher_payload_must_be_dict")
        rows = _extract_payload_rows(source.source, payload)
        return ExternalFeedResult(
            source=str(source.source),
            endpoint_url=str(source.endpoint_url),
            records=rows,
            metadata={
                "transport": "custom_fetcher",
                "record_count": len(rows),
            },
        )

    endpoint_url = str(source.endpoint_url or "").strip()
    policy = destination_policy or _external_risk_destination_policy()
    policy.validate(
        endpoint_url,
        source=f"external-risk:{str(source.source or '').strip().lower()}",
    )
    policy_check = validate_transport_security(
        endpoint_url=endpoint_url,
        transport_policy=dict(source.transport_policy or {}),
        egress_policy=dict(source.egress_policy or {}),
    )
    if not policy_check.allowed:
        raise ExternalFeedFetchError(f"transport_policy_failed:{policy_check.reason}")

    headers = minimal_headers(_auth_headers(source))
    headers.setdefault("Accept", "application/json")

    request = _prepare_request(source, endpoint_url, headers)
    allow_system_trust_fallback = bool((source.transport_policy or {}).get("allow_system_trust_store_fallback", True))
    attempts: list[tuple[str, bool]] = [("configured_bundle", False)]
    if allow_system_trust_fallback:
        attempts.append(("system_trust_store", True))

    last_exc: Exception | None = None
    for index, (trust_mode, use_system_trust_store) in enumerate(attempts):
        context = build_ssl_context(
            transport_policy=dict(source.transport_policy or {}),
            auth_config=dict(source.auth_config or {}),
            use_system_trust_store=use_system_trust_store,
        )
        try:
            with _open_source_request(
                source,
                request,
                timeout_seconds=timeout_seconds,
                context=context,
                destination_policy=destination_policy,
            ) as response:
                source_name = str(source.source or "").strip().lower()
                default_max_response_bytes = 6_000_000 if source_name == "nvd" else 2_000_000
                max_response_bytes = int((source.source_trust_policy or {}).get("max_response_bytes") or default_max_response_bytes)
                content_length_header = response.headers.get("Content-Length")
                if content_length_header:
                    try:
                        content_length = int(content_length_header)
                    except ValueError:
                        content_length = None
                    if content_length is not None and content_length > max_response_bytes:
                        raise ExternalFeedFetchError(
                            f"response_too_large:{source.source}:content_length={content_length}:max={max_response_bytes}"
                        )

                raw = response.read(max_response_bytes + 1)
                if len(raw) > max_response_bytes:
                    raise ExternalFeedFetchError(
                        f"response_too_large:{source.source}:bytes={len(raw)}:max={max_response_bytes}"
                    )

                payload = _decode_json_payload(raw)

                pins = list((source.transport_policy or {}).get("pinned_certificate_sha256") or [])
                certificate_bytes: bytes | None = None
                try:
                    certificate_bytes = response.fp.raw._sock.getpeercert(binary_form=True)  # type: ignore[attr-defined]
                except Exception:
                    certificate_bytes = None

                if pins and certificate_bytes:
                    pin_check = verify_pinned_certificate_hash(
                        certificate_bytes=certificate_bytes,
                        pinned_sha256=pins,
                    )
                    if not pin_check.allowed:
                        raise ExternalFeedFetchError("certificate_pin_mismatch")

                trust_check = _verify_trust_policy(payload, source)
                if not trust_check.allowed:
                    raise ExternalFeedFetchError(f"trust_policy_failed:{trust_check.reason}")

                rows = _extract_payload_rows(source.source, payload)
                return ExternalFeedResult(
                    source=str(source.source),
                    endpoint_url=endpoint_url,
                    records=rows,
                    metadata={
                        "transport": "https",
                        "record_count": len(rows),
                        "tls_policy": policy_check.details,
                        "response_bytes": len(raw),
                        "trust_store_mode": trust_mode,
                    },
                )
        except ExternalFeedFetchError:
            raise
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
            is_dns_error = _dns_resolution_error(exc)
            should_retry_with_system_store = (
                not use_system_trust_store
                and index < len(attempts) - 1
                and _ssl_chain_error(exc)
            )
            if should_retry_with_system_store:
                continue
            if _ssl_chain_error(exc):
                if _allow_curl_tls_fallback(source):
                    try:
                        payload = _fetch_json_via_curl(
                            source=source,
                            request=request,
                            timeout_seconds=timeout_seconds,
                            destination_policy=policy,
                        )
                        rows = _extract_payload_rows(source.source, payload)
                        return ExternalFeedResult(
                            source=str(source.source),
                            endpoint_url=endpoint_url,
                            records=rows,
                            metadata={
                                "transport": "https",
                                "record_count": len(rows),
                                "tls_policy": policy_check.details,
                                "trust_store_mode": "curl_tls_fallback",
                            },
                        )
                    except ExternalFeedFetchError:
                        pass
                raise ExternalFeedFetchError(
                    f"source_fetch_failed:{source.source}:{exc}. "
                    "Hint: provide transport_policy.ca_bundle_path or SSL_CERT_FILE/REQUESTS_CA_BUNDLE for your local issuer."
                ) from exc
            if is_dns_error:
                if _allow_curl_tls_fallback(source):
                    try:
                        payload = _fetch_json_via_curl(
                            source=source,
                            request=request,
                            timeout_seconds=timeout_seconds,
                            destination_policy=policy,
                        )
                        rows = _extract_payload_rows(source.source, payload)
                        return ExternalFeedResult(
                            source=str(source.source),
                            endpoint_url=endpoint_url,
                            records=rows,
                            metadata={
                                "transport": "https",
                                "record_count": len(rows),
                                "tls_policy": policy_check.details,
                                "trust_store_mode": "curl_network_fallback",
                            },
                        )
                    except ExternalFeedFetchError:
                        pass
                raise ExternalFeedFetchError(
                    f"source_fetch_failed:{source.source}:{exc}. "
                    "Hint: current API runtime cannot resolve or reach external hosts. Check DNS, outbound internet egress, or run the sync from a runtime with external network access."
                ) from exc
            raise ExternalFeedFetchError(f"source_fetch_failed:{source.source}:{exc}") from exc

    if last_exc is not None:
        raise ExternalFeedFetchError(f"source_fetch_failed:{source.source}:{last_exc}") from last_exc
    raise ExternalFeedFetchError(f"source_fetch_failed:{source.source}:unknown_error")
