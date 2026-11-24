"""Metadata-only Microsoft 365 Copilot and optional Entra source connector."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any, Protocol

from app.services.hmair.contracts import ObservationType, SourceSurface
from app.services.hmair.source_connectors.contracts import (
    HMAIRNormalizedRecord,
    HMAIRSourceCapability,
    HMAIRSourceCollectionResult,
    HMAIRSourceConnectionInput,
    HMAIRSourceProvider,
)
from app.services.hmair.source_connectors.http import SafeSourceHTTPError


GRAPH_ORIGIN = "https://graph.microsoft.com"
COPILOT_REPORT_PATH = (
    "/v1.0/copilot/reports/getMicrosoft365CopilotUsageUserDetail("
    "period='D7',version='v2')"
)
ENTRA_SIGN_INS_PATH = "/v1.0/auditLogs/signIns"
_M365_LIMITATION = "unlicensed_copilot_chat_not_reported_by_graph"


class M365HTTP(Protocol):
    def get_json(self, url: str, **kwargs: Any) -> Any: ...


def _hash_identifier(value: object, *, salt: str) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    return sha256(f"{salt}\x00{value.strip()}".encode("utf-8")).hexdigest()


def _utc(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(UTC)


def _report_rows(payload: object) -> tuple[Mapping[str, object], ...]:
    if not isinstance(payload, Mapping):
        return ()
    rows = payload.get("value")
    if not isinstance(rows, list):
        return ()
    return tuple(row for row in rows if isinstance(row, Mapping))[:10_000]


def _denominator(payload: object) -> int | None:
    if not isinstance(payload, Mapping):
        return None
    value = payload.get("licensed_user_count")
    return value if isinstance(value, int) and value >= 0 else None


def _copilot_report(http: M365HTTP) -> object:
    """Request the documented JSON representation; retain no report body."""

    return http.get_json(
        f"{GRAPH_ORIGIN}{COPILOT_REPORT_PATH}",
        headers={"Accept": "application/json"},
        params={"$format": "application/json"},
    )


def _capability_from_report(
    payload: object, *, fresh_at: datetime
) -> HMAIRSourceCapability:
    source_denominator = _denominator(payload)
    limitations = [_M365_LIMITATION]
    if source_denominator is None:
        limitations.append("source_denominator_unavailable")
    return HMAIRSourceCapability(
        provider_key=HMAIRSourceProvider.MICROSOFT365,
        state=(
            "partial"
            if source_denominator is None
            else "empty"
            if not _report_rows(payload)
            else "ready"
        ),
        allowed_capabilities=("copilot_usage",),
        denominator=source_denominator,
        fresh_at=fresh_at.astimezone(UTC),
        limitations=tuple(limitations),
    )


class Microsoft365SourceConnector:
    provider_key = HMAIRSourceProvider.MICROSOFT365

    def validate(
        self,
        connection: HMAIRSourceConnectionInput,
        http: M365HTTP,
        *,
        now: datetime,
    ) -> HMAIRSourceCapability:
        if connection.provider_key is not self.provider_key:
            raise ValueError("Microsoft 365 collector received the wrong source provider")
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("Microsoft 365 validation requires a timezone-aware time")
        try:
            payload = _copilot_report(http)
        except SafeSourceHTTPError as error:
            if error.reason in {"source_http_401", "source_http_403"}:
                return HMAIRSourceCapability(
                    provider_key=self.provider_key,
                    state="permission_denied",
                    allowed_capabilities=(),
                    limitations=("copilot_report_permission_missing",),
                )
            return HMAIRSourceCapability(
                provider_key=self.provider_key,
                state="failed",
                allowed_capabilities=(),
                limitations=("copilot_report_validation_unavailable",),
            )
        return _capability_from_report(payload, fresh_at=now)

    def collect(
        self,
        connection: HMAIRSourceConnectionInput,
        window: tuple[datetime, datetime],
        http: M365HTTP,
        *,
        identifier_salt: str,
    ) -> HMAIRSourceCollectionResult:
        if connection.provider_key is not self.provider_key:
            raise ValueError("Microsoft 365 collector received the wrong source provider")
        start, end = window
        if start.tzinfo is None or end.tzinfo is None or start >= end:
            raise ValueError("Microsoft 365 collection requires an ordered UTC window")
        payload = _copilot_report(http)
        records: list[HMAIRNormalizedRecord] = []
        for row in _report_rows(payload):
            user_hash = _hash_identifier(
                row.get("userPrincipalName") or row.get("user_principal_name"),
                salt=identifier_salt,
            )
            observed_at = _utc(
                row.get("lastActivityDate") or row.get("last_activity_date")
            )
            if user_hash is None or observed_at is None:
                continue
            records.append(
                HMAIRNormalizedRecord(
                    record_id=f"m365-{user_hash[:48]}",
                    record_kind="copilot_usage",
                    observed_at=observed_at,
                    candidate_asset_type="ai_application",
                    observation_type=ObservationType.WEB_AI_USAGE,
                    source_surface=SourceSurface.SAAS,
                    identifiers={"user_hash": user_hash, "provider": "microsoft365"},
                    metadata={"report_period_days": 7, "licensed_source": True},
                )
            )
        capability = _capability_from_report(payload, fresh_at=end)
        entra_records: tuple[HMAIRNormalizedRecord, ...] = ()
        if connection.include_entra_account_evidence:
            entra_records = self._collect_entra(
                start=start,
                end=end,
                http=http,
                identifier_salt=identifier_salt,
            )
        return HMAIRSourceCollectionResult(
            capability=capability,
            records=tuple(records),
            entra_records=entra_records,
        )

    @staticmethod
    def _collect_entra(
        *,
        start: datetime,
        end: datetime,
        http: M365HTTP,
        identifier_salt: str,
    ) -> tuple[HMAIRNormalizedRecord, ...]:
        payload = http.get_json(
            f"{GRAPH_ORIGIN}{ENTRA_SIGN_INS_PATH}",
            headers={"Accept": "application/json"},
            params={
                "$filter": (
                    "createdDateTime ge "
                    f"{start.astimezone(UTC).isoformat()} and createdDateTime le "
                    f"{end.astimezone(UTC).isoformat()}"
                ),
            },
        )
        records: list[HMAIRNormalizedRecord] = []
        for row in _report_rows(payload):
            user_hash = _hash_identifier(row.get("userPrincipalName"), salt=identifier_salt)
            event_hash = _hash_identifier(row.get("id"), salt=identifier_salt)
            observed_at = _utc(row.get("createdDateTime"))
            if user_hash is None or event_hash is None or observed_at is None:
                continue
            records.append(
                HMAIRNormalizedRecord(
                    record_id=f"entra-{event_hash[:48]}",
                    record_kind="entra_account_evidence",
                    observed_at=observed_at,
                    candidate_asset_type="ai_provider_account",
                    observation_type=ObservationType.ACTIVE_USER,
                    source_surface=SourceSurface.IDENTITY,
                    identifiers={"user_hash": user_hash, "provider": "entra"},
                    metadata={"evidence_class": "account_activity"},
                )
            )
        return tuple(records)


microsoft365 = Microsoft365SourceConnector()

__all__ = ["Microsoft365SourceConnector", "microsoft365"]
