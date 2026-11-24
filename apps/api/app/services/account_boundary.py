from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import secrets
from typing import Any
from uuid import uuid4

from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.db.models.account_boundary import (
    ACCOUNT_CLASSES,
    AccountAccessReceipt,
    AccountBoundaryIntegration,
    AccountBoundaryValidation,
    AIAccountIdentity,
    AIAccountSession,
    AIAccountSessionPermit,
    AIAuthTransaction,
)
from app.db.models.endpoint_identity import EndpointDeviceIdentity
from app.db.models.control_coverage import DeploymentSurface
from app.services.account_boundary_adapters import AccountBoundaryAdapterRegistry
from app.services.account_boundary_signing import (
    ACCOUNT_ACCESS_RECEIPT_DOMAIN,
    ACCOUNT_ACCESS_RECEIPT_PURPOSE,
    ACCOUNT_SESSION_PERMIT_DOMAIN,
    ACCOUNT_SESSION_PERMIT_PURPOSE,
    VALIDATION_DOMAIN,
    VALIDATION_PURPOSE,
    SigningKeyProvider,
    active_key_id,
    pseudonymize,
    sign_object,
    verify_signed_object,
)


ASSURANCE_RANK = {"AB0": 0, "AB1": 1, "AB2": 2, "AB3": 3, "AB4": 4, "AB5": 5}
PROVIDERS = {"openai": ("ChatGPT", "tier_1"), "anthropic": ("Claude", "tier_1"), "google": ("Gemini", "tier_1"), "microsoft": ("Copilot", "tier_1"), "github": ("GitHub Copilot", "tier_2"), "cursor": ("Cursor", "tier_3"), "windsurf": ("Windsurf", "tier_3"), "perplexity": ("Perplexity", "tier_3"), "replit": ("Replit", "tier_3"), "notion": ("Notion AI", "tier_3"), "slack": ("Slack AI", "tier_3"), "atlassian": ("Atlassian Intelligence", "tier_3"), "salesforce": ("Einstein", "tier_3"), "zoom": ("Zoom AI Companion", "tier_3"), "servicenow": ("Now Assist", "tier_3"), "grok": ("Grok", "tier_3"), "poe": ("Poe", "tier_3"), "deepseek": ("DeepSeek", "tier_3"), "kimi": ("Kimi", "tier_3"), "qwen": ("Qwen", "tier_3"), "mistral": ("Mistral", "tier_3"), "unknown_public_ai": ("Unknown public AI", "unknown")}
CAPABILITY_NAMES = ("PROVIDER_SERVER_RESTRICTION", "AUTHENTICATION_PLANE_BINDING", "WORKSPACE_SESSION_BINDING", "SUBSCRIPTION_ROUTE_BINDING", "APPLICATION_PROCESS_BINDING", "BROWSER_PROFILE_BINDING", "DOMAIN_OBSERVATION")
_LIFECYCLE_ORDER = ("DISCOVER", "SIMULATE", "VALIDATE", "MONITOR", "ENFORCE")
_LIFECYCLE_MODES = {"MONITOR": "monitor", "ENFORCE": "enforce", "DISABLED": "disabled"}
_DOWNLOAD_CONTROL_FRESHNESS = timedelta(minutes=5)
_DOWNLOAD_CAPABILITY_STATES = {"inline", "inline_bound", "supported", "verified", "yes"}


class AccountBoundaryAuthorityUnavailable(RuntimeError):
    pass


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


def _canonical_json(value: dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _normalise_domain(email: str | None) -> str | None:
    return email.rsplit("@", 1)[1].strip().lower() if email and "@" in email else None


def _subscription_to_class(subscription_class: str | None) -> str:
    value = (subscription_class or "").lower()
    if value in {"free", "personal_free"}:
        return "PERSONAL_FREE"
    if value in {"paid", "plus", "pro", "personal_paid"}:
        return "PERSONAL_PAID"
    if value in {"developer", "team_personal"}:
        return "PERSONAL_DEVELOPER"
    return "UNKNOWN"


def _session_state_for_account_class(account_class: str) -> str:
    if account_class.startswith("ENTERPRISE"):
        return "ENTERPRISE_VERIFIED"
    if account_class.startswith("PARTNER"):
        return "PARTNER_VERIFIED"
    if account_class.startswith("EXTERNAL"):
        return "EXTERNAL_UNAPPROVED"
    if account_class.startswith("PERSONAL"):
        return "PERSONAL_DETECTED"
    if account_class == "ANONYMOUS":
        return "ANONYMOUS_DETECTED"
    return "UNKNOWN"


def _integration_provenance(integration_id: str) -> str:
    return f"account-boundary:integration:{integration_id}"


class AccountBoundaryService:
    """Fail-closed, tenant-bound account/session authority primitives."""

    def __init__(self, *, pseudonymization_key: str | None = None, signing_provider: SigningKeyProvider | None = None,
                 adapter_registry: AccountBoundaryAdapterRegistry | None = None) -> None:
        if not isinstance(pseudonymization_key, str) or len(pseudonymization_key.strip()) < 32:
            raise ValueError("account-boundary pseudonymization key is required")
        if signing_provider is None:
            raise ValueError("account-boundary signing provider is required")
        self.pseudonymization_key = pseudonymization_key
        self.signing_provider = signing_provider
        self.adapters = adapter_registry or AccountBoundaryAdapterRegistry()

    def _hash(self, tenant_id: str, purpose: str, value: str | None) -> str | None:
        return pseudonymize(self.pseudonymization_key, tenant_id=tenant_id, purpose=purpose, value=value)

    def _key_id(self, purpose: str, tenant_id: str) -> str:
        try:
            return active_key_id(self.signing_provider, purpose=purpose, tenant_id=tenant_id)
        except Exception as exc:
            raise AccountBoundaryAuthorityUnavailable("account-boundary signing authority unavailable") from exc

    def provider_capability_manifests(self) -> dict[str, dict[str, Any]]:
        return {
            provider: {"provider": provider, "product": product, "provider_tier": tier,
                       "capabilities": {name: {"level": "UNKNOWN", "verification": "UNVERIFIED", "evidence_refs": []} for name in CAPABILITY_NAMES},
                       "limitations": ["No provider-native account control is claimed until server-owned validation passes.", "Shared IdP domains are corroborating evidence only."],
                       "verification_status": "UNVERIFIED"}
            for provider, (product, tier) in PROVIDERS.items()
        }

    def start_auth_transaction(self, db: Session, *, tenant_id: str, user_identity_ref: str, device_id: str,
                               application_asset_id: str | None, application_family: str, provider: str, product: str,
                               surface: str, auth_protocol: str, expected_issuer: str | None = None,
                               expected_client_id: str | None = None, expected_redirect_uri: str | None = None,
                               state: str | None = None, nonce: str | None = None, pkce_challenge: str | None = None,
                               relay_state: str | None = None, device_code: str | None = None,
                               initiating_browser_profile: str | None = None, initiating_tab_or_navigation_id: str | None = None,
                               initiating_process_instance: str | None = None, intended_enterprise_org_ids: list[str] | None = None,
                               intended_workspace_ids: list[str] | None = None, intended_tenant_ids: list[str] | None = None,
                               policy_id: str | None = None, policy_version: str | None = None,
                               started_at: datetime | None = None, ttl_seconds: int = 600) -> AIAuthTransaction:
        started = started_at or _now()
        protocol = auth_protocol.lower()
        if protocol in {"oauth", "oidc"} and not state:
            raise ValueError("state is required for OAuth/OIDC")
        if protocol == "oidc" and not nonce:
            raise ValueError("nonce is required for OIDC")
        if not 1 <= ttl_seconds <= 3600:
            raise ValueError("auth transaction TTL must be positive and bounded")
        row = AIAuthTransaction(auth_transaction_id=f"auth-{uuid4()}", tenant_id=tenant_id, user_identity_ref=user_identity_ref,
            device_id=device_id, application_asset_id=application_asset_id, application_family=application_family, provider=provider,
            product=product, surface=surface, initiating_process_instance=initiating_process_instance,
            initiating_browser_profile=initiating_browser_profile, initiating_tab_or_navigation_id=initiating_tab_or_navigation_id,
            auth_protocol=auth_protocol, expected_issuer=expected_issuer, expected_client_id=expected_client_id,
            expected_redirect_uri=expected_redirect_uri, state_hash=self._hash(tenant_id, "state", state),
            nonce_hash=self._hash(tenant_id, "nonce", nonce), pkce_challenge_hash=self._hash(tenant_id, "pkce", pkce_challenge),
            relay_state_hash=self._hash(tenant_id, "relay-state", relay_state), device_code_hash=self._hash(tenant_id, "device-code", device_code),
            intended_enterprise_org_ids=intended_enterprise_org_ids or [], intended_workspace_ids=intended_workspace_ids or [],
            intended_tenant_ids=intended_tenant_ids or [], policy_id=policy_id, policy_version=policy_version, started_at=started,
            expires_at=started + timedelta(seconds=ttl_seconds), current_state="STARTED", safe_event_log=[], evidence_refs=[])
        db.add(row); db.flush(); return row

    def correlate_auth_event(self, db: Session, *, tenant_id: str, auth_transaction_id: str, issuer: str | None,
                             client_id: str | None, redirect_uri: str | None, state: str | None = None,
                             nonce: str | None = None, referrer: str | None = None, callback_process_instance: str | None = None,
                             callback_browser_profile: str | None = None, callback_tab_or_navigation_id: str | None = None,
                             occurred_at: datetime | None = None) -> dict[str, Any]:
        occurred = occurred_at or _now()
        tx = db.scalar(select(AIAuthTransaction).where(AIAuthTransaction.tenant_id == tenant_id, AIAuthTransaction.auth_transaction_id == auth_transaction_id))
        if tx is None: raise LookupError("auth_transaction_not_found")
        if tx.current_state != "STARTED": raise PermissionError("auth transaction replayed")
        if tx.expires_at < occurred: tx.current_state = "EXPIRED"; raise PermissionError("Auth transaction expired")
        if tx.expected_issuer and tx.expected_issuer != issuer: raise PermissionError("Issuer mismatch")
        if tx.expected_client_id and tx.expected_client_id != client_id: raise PermissionError("Referrer is not an account boundary; client_id mismatch")
        if tx.expected_redirect_uri and tx.expected_redirect_uri != redirect_uri: raise PermissionError("Redirect URI mismatch")
        if tx.state_hash and tx.state_hash != self._hash(tenant_id, "state", state): raise PermissionError("State mismatch")
        if tx.nonce_hash and tx.nonce_hash != self._hash(tenant_id, "nonce", nonce): raise PermissionError("Nonce mismatch")
        if tx.initiating_process_instance and tx.initiating_process_instance != callback_process_instance: raise PermissionError("Process context mismatch")
        if tx.initiating_browser_profile and tx.initiating_browser_profile != callback_browser_profile: raise PermissionError("Browser profile mismatch")
        if tx.initiating_tab_or_navigation_id and tx.initiating_tab_or_navigation_id != callback_tab_or_navigation_id: raise PermissionError("Navigation context mismatch")
        tx.current_state = "AUTH_BOUND"; tx.correlation_confidence = .92 if referrer else .88
        tx.safe_event_log = [*list(tx.safe_event_log or []), {"event": "auth_event_correlated", "occurred_at": occurred.isoformat(), "client_id_hash": self._hash(tenant_id, "client-id", client_id), "referrer_domain_observed": bool(referrer), "shared_idp_domain_blocked": False}]
        db.flush(); return {"state": tx.current_state, "shared_idp_domain_blocked": False, "correlation_confidence": tx.correlation_confidence}

    def create_integration(self, db: Session, *, tenant_id: str, provider: str, product: str, surfaces: list[str]) -> AccountBoundaryIntegration:
        row = AccountBoundaryIntegration(tenant_id=tenant_id, provider=provider, product=product, surfaces=sorted(set(surfaces)), mode="monitor", health="UNKNOWN", lifecycle_state="DISCOVER", route_health="UNKNOWN", evidence_refs=[])
        db.add(row); db.flush(); return row

    def get_integration(self, db: Session, *, tenant_id: str, integration_id: str) -> AccountBoundaryIntegration:
        row = db.get(AccountBoundaryIntegration, integration_id)
        if row is None or row.tenant_id != tenant_id: raise LookupError("integration_not_found")
        return row

    def list_integrations(self, db: Session, *, tenant_id: str) -> list[AccountBoundaryIntegration]:
        return list(db.scalars(select(AccountBoundaryIntegration).where(AccountBoundaryIntegration.tenant_id == tenant_id).order_by(AccountBoundaryIntegration.created_at)))

    def validate_integration(self, db: Session, *, tenant_id: str, integration_id: str, surface: str, checked_at: datetime | None = None) -> AccountBoundaryValidation:
        integration = self.get_integration(db, tenant_id=tenant_id, integration_id=integration_id)
        checked = checked_at or _now()
        result = self.adapters.adapter_for(integration.provider).validate_integration(tenant_id=tenant_id, provider=integration.provider, product=integration.product, surface=surface)
        envelope = {"tenant_id": tenant_id, "integration_id": integration.id, "provider": integration.provider, "product": integration.product, "surface": surface, "status": result.status, "route_health": result.route_health, "provider_version": result.provider_version, "capabilities": list(result.capabilities), "limitations": list(result.limitations), "measured_at": checked.isoformat(), "valid_until": result.valid_until(checked).isoformat()}
        signed = sign_object(self.signing_provider, purpose=VALIDATION_PURPOSE, domain=VALIDATION_DOMAIN, tenant_id=tenant_id, key_id=self._key_id(VALIDATION_PURPOSE, tenant_id), value=envelope)
        row = AccountBoundaryValidation(tenant_id=tenant_id, integration_id=integration.id, provider=integration.provider, product=integration.product, surface=surface, validation_type="server_owned", status=result.status, evidence_refs=[], limitations=list(result.limitations), measured_at=checked, valid_until=result.valid_until(checked), route_health=result.route_health, provider_version=result.provider_version, result={"capabilities": list(result.capabilities)}, signed_envelope=signed, signing_key_id=signed["signing_key_id"], signing_algorithm=signed["algorithm"])
        integration.health = result.route_health; integration.route_health = result.route_health; integration.provider_version = result.provider_version
        db.add(row); db.flush(); return row

    def _current_validation(self, db: Session, *, tenant_id: str, integration_id: str, provider: str, product: str, surface: str, checked_at: datetime) -> AccountBoundaryValidation | None:
        row = db.scalar(select(AccountBoundaryValidation).where(AccountBoundaryValidation.tenant_id == tenant_id, AccountBoundaryValidation.integration_id == integration_id, AccountBoundaryValidation.provider == provider, AccountBoundaryValidation.product == product, AccountBoundaryValidation.surface == surface).order_by(AccountBoundaryValidation.measured_at.desc()))
        if row is None or row.status != "PASS" or row.route_health != "HEALTHY" or row.valid_until is None or _utc(row.valid_until) < _utc(checked_at):
            return None
        expected = {"tenant_id": row.tenant_id, "integration_id": row.integration_id, "provider": row.provider, "product": row.product, "surface": row.surface, "status": row.status, "route_health": row.route_health, "provider_version": row.provider_version, "capabilities": list((row.result or {}).get("capabilities", [])), "limitations": list(row.limitations or []), "measured_at": _utc(row.measured_at).isoformat(), "valid_until": _utc(row.valid_until).isoformat(), "algorithm": row.signing_algorithm, "signing_key_id": row.signing_key_id}
        envelope = dict(row.signed_envelope or {})
        if not envelope or _canonical_json({key: value for key, value in envelope.items() if key != "signature"}) != _canonical_json(expected) or not verify_signed_object(self.signing_provider, purpose=VALIDATION_PURPOSE, domain=VALIDATION_DOMAIN, tenant_id=tenant_id, value=envelope, current_authority=True):
            return None
        return row

    def advance_lifecycle(self, db: Session, *, tenant_id: str, integration_id: str, target_state: str, enforcement_enabled: bool = False, checked_at: datetime | None = None) -> AccountBoundaryIntegration:
        integration = self.get_integration(db, tenant_id=tenant_id, integration_id=integration_id)
        if target_state == "DISABLED": integration.lifecycle_state = "DISABLED"; integration.mode = _LIFECYCLE_MODES[target_state]; integration.health = "DISABLED"; self._revoke_integration_permits(db, integration); db.flush(); return integration
        if target_state not in _LIFECYCLE_ORDER or integration.lifecycle_state == "DISABLED": raise PermissionError("invalid_lifecycle_transition")
        current_index = _LIFECYCLE_ORDER.index(integration.lifecycle_state)
        if _LIFECYCLE_ORDER.index(target_state) != current_index + 1: raise PermissionError("invalid_lifecycle_transition")
        if target_state == "ENFORCE" and not enforcement_enabled: raise PermissionError("enforcement_enabled_required")
        if target_state in {"MONITOR", "ENFORCE"} and not all(self._current_validation(db, tenant_id=tenant_id, integration_id=integration.id, provider=integration.provider, product=integration.product, surface=surface, checked_at=checked_at or _now()) for surface in integration.surfaces):
            raise PermissionError("current_passing_validation_required")
        integration.lifecycle_state = target_state; integration.mode = _LIFECYCLE_MODES.get(target_state, "monitor"); db.flush(); return integration

    def _upsert_identity(self, db: Session, *, tenant_id: str, provider: str, provider_subject_ref: str, email: str | None, organisation_ids: list[str], workspace_ids: list[str], tenant_ids: list[str], subscription_class: str | None, enterprise_membership: bool, verification_method: str, verification_status: str, verified_at: datetime, account_class: str | None = None, evidence_refs: list[str] | None = None) -> AIAccountIdentity:
        row = db.scalar(select(AIAccountIdentity).where(AIAccountIdentity.tenant_id == tenant_id, AIAccountIdentity.provider == provider, AIAccountIdentity.provider_subject_ref == provider_subject_ref))
        if row is None: row = AIAccountIdentity(tenant_id=tenant_id, provider=provider, provider_subject_ref=provider_subject_ref); db.add(row)
        row.email_hash = self._hash(tenant_id, "email", email.lower() if email else None); row.email_domain = _normalise_domain(email); row.account_class = account_class or ("ENTERPRISE_MANAGED_USER" if enterprise_membership else _subscription_to_class(subscription_class))
        row.organisation_ids = organisation_ids; row.workspace_ids = workspace_ids; row.tenant_ids = tenant_ids; row.subscription_class = subscription_class; row.enterprise_membership = enterprise_membership; row.verification_method = verification_method; row.verification_status = verification_status; row.verified_at = verified_at; row.evidence_refs = list(evidence_refs or [])
        db.flush(); return row

    def verify_account_identity(self, db: Session, *, tenant_id: str, provider: str, provider_subject_ref: str, email: str | None, organisation_ids: list[str], workspace_ids: list[str], tenant_ids: list[str], subscription_class: str | None, enterprise_membership: bool, verification_method: str, evidence_refs: list[str], verified_at: datetime) -> AIAccountIdentity:
        """Record a restrictive observation; client claims never establish enterprise authority.

        A provider-observed consumer subscription may safely select a personal class because
        that classification can only reduce access. Enterprise, partner, and external
        membership still require the server-owned adapter path below.
        """
        observed_personal_class = _subscription_to_class(subscription_class)
        account_class = observed_personal_class if not enterprise_membership else "UNKNOWN"
        return self._upsert_identity(
            db,
            tenant_id=tenant_id,
            provider=provider,
            provider_subject_ref=provider_subject_ref,
            email=email,
            organisation_ids=[],
            workspace_ids=[],
            tenant_ids=[],
            subscription_class=subscription_class if account_class.startswith("PERSONAL") else None,
            enterprise_membership=False,
            verification_method="client_observation",
            verification_status="OBSERVED" if account_class.startswith("PERSONAL") else "UNKNOWN",
            verified_at=verified_at,
            account_class=account_class,
            evidence_refs=list(evidence_refs),
        )

    def record_server_verified_identity(self, db: Session, *, tenant_id: str, integration_id: str, provider_subject_ref: str, email: str | None, organisation_ids: list[str] | None = None, workspace_ids: list[str] | None = None, verified_at: datetime) -> AIAccountIdentity:
        integration = self.get_integration(db, tenant_id=tenant_id, integration_id=integration_id)
        validation = self._current_validation(db, tenant_id=tenant_id, integration_id=integration.id, provider=integration.provider, product=integration.product, surface=(integration.surfaces or [""])[0], checked_at=verified_at)
        if validation is None: raise PermissionError("current_server_validation_required")
        identity = self.adapters.adapter_for(integration.provider).verify_identity(tenant_id=tenant_id, provider=integration.provider, product=integration.product, subject_ref=provider_subject_ref, email=email)
        account_class = identity.account_class if identity.account_class in ACCOUNT_CLASSES else "UNKNOWN"
        enterprise = account_class.startswith(("ENTERPRISE", "PARTNER", "EXTERNAL"))
        return self._upsert_identity(db, tenant_id=tenant_id, provider=integration.provider, provider_subject_ref=provider_subject_ref, email=email, organisation_ids=list(identity.organisation_ids), workspace_ids=list(identity.workspace_ids), tenant_ids=[], subscription_class="enterprise" if enterprise else None, enterprise_membership=enterprise, verification_method="server_owned_adapter", verification_status="VERIFIED" if enterprise else "UNKNOWN", verified_at=verified_at, account_class=account_class, evidence_refs=[_integration_provenance(integration.id)])

    def create_account_session(self, db: Session, *, tenant_id: str, provider: str, product: str, surface: str, user_identity_ref: str, account_identity_id: str, device_id: str, process_instance: str | None, browser_profile: str | None, tab_or_app_session: str | None, organisation_id: str | None, workspace_id: str | None, policy_version: str | None, issued_at: datetime, integration_id: str | None = None, ttl_seconds: int = 3600) -> AIAccountSession:
        identity = db.get(AIAccountIdentity, account_identity_id)
        if identity is None or identity.tenant_id != tenant_id or identity.provider != provider: raise LookupError("account_identity_not_found")
        integration = self.get_integration(db, tenant_id=tenant_id, integration_id=integration_id) if integration_id else None
        if identity.account_class.startswith(("ENTERPRISE", "PARTNER", "EXTERNAL")):
            provenance = _integration_provenance(integration.id) if integration else None
            if integration is None or provenance not in (identity.evidence_refs or []) or (integration.provider, integration.product) != (provider, product) or surface not in (integration.surfaces or []) or self._current_validation(db, tenant_id=tenant_id, integration_id=integration.id, provider=provider, product=product, surface=surface, checked_at=issued_at) is None:
                raise PermissionError("current_integration_validation_required")
            if organisation_id and organisation_id not in (identity.organisation_ids or []): raise PermissionError("organisation_not_server_verified")
            if workspace_id and workspace_id not in (identity.workspace_ids or []): raise PermissionError("workspace_not_server_verified")
        state = _session_state_for_account_class(identity.account_class)
        assurance = "AB4" if state in {"PARTNER_VERIFIED", "EXTERNAL_UNAPPROVED"} else ("AB4" if state == "ENTERPRISE_VERIFIED" and (organisation_id or workspace_id) else "AB3" if state == "ENTERPRISE_VERIFIED" else "AB1" if state == "PERSONAL_DETECTED" else "AB0")
        evidence_refs = [_integration_provenance(integration.id)] if integration and identity.account_class.startswith(("ENTERPRISE", "PARTNER", "EXTERNAL")) else []
        row = AIAccountSession(account_session_id=f"session-{uuid4()}", tenant_id=tenant_id, provider=provider, product=product, surface=surface, user_identity_ref=user_identity_ref, account_identity_ref=identity.id, account_boundary_integration_id=integration.id if integration else None, device_id=device_id, process_instance=process_instance, browser_profile=browser_profile, tab_or_app_session=tab_or_app_session, organisation_id=organisation_id, workspace_id=workspace_id, subscription_class=identity.subscription_class, assurance_level=assurance, verification_method=identity.verification_method, issued_at=issued_at, last_verified_at=issued_at, expires_at=issued_at + timedelta(seconds=ttl_seconds), policy_version=policy_version, session_state=state, evidence_refs=evidence_refs)
        db.add(row); db.flush(); return row

    def select_boundary_plan(self, db: Session, *, tenant_id: str, integration_id: str | None = None, provider: str, product: str, surface: str, required_assurance: str, device_managed: bool, provider_capabilities: list[str] | None = None, route_healthy: bool | None = None, checked_at: datetime | None = None) -> dict[str, Any]:
        integration = self.get_integration(db, tenant_id=tenant_id, integration_id=integration_id) if integration_id else None
        validation = self._current_validation(db, tenant_id=tenant_id, integration_id=integration.id, provider=provider, product=product, surface=surface, checked_at=checked_at or _now()) if integration else None
        capabilities = set((validation.result or {}).get("capabilities", [])) if validation else set()
        if validation and device_managed and "WORKSPACE_SESSION_BOUND" in capabilities: achieved, primary = "AB4", "WORKSPACE_SESSION_BOUND"
        elif validation and "SUBSCRIPTION_ROUTE_BOUND" in capabilities: achieved, primary = "AB3", "SUBSCRIPTION_ROUTE_BOUND"
        elif validation and "BROWSER_PROFILE_BOUND" in capabilities: achieved, primary = "AB2", "BROWSER_PROFILE_BOUND"
        else: achieved, primary = "AB0", "UNKNOWN"
        return {"provider": provider, "product": product, "surface": surface, "required_assurance": required_assurance, "achieved_assurance": achieved, "primary_account_control": primary, "satisfied": ASSURANCE_RANK[achieved] >= ASSURANCE_RANK.get(required_assurance, 0), "truth": "persisted_current_server_validation" if validation else "no_current_server_validation"}

    def _permit_payload(self, permit: AIAccountSessionPermit) -> dict[str, Any]:
        return {"tenant_id": permit.tenant_id, "permit_id": permit.permit_id, "account_session_ref": permit.account_session_ref, "user_identity_ref": permit.user_identity_ref, "account_identity_ref": permit.account_identity_ref, "device_id": permit.device_id, "process_instance": permit.process_instance, "browser_profile": permit.browser_profile, "workspace_or_org_binding": permit.workspace_or_org_binding or {}, "provider": permit.provider, "product": permit.product, "surface": permit.surface, "allowed_destination_scope": sorted(permit.allowed_destination_scope or []), "allowed_data_classes": sorted(permit.allowed_data_classes or []), "allowed_business_purposes": sorted(permit.allowed_business_purposes or []), "policy_epoch": permit.policy_epoch, "issued_at": _utc(permit.issued_at).isoformat(), "expires_at": _utc(permit.expires_at).isoformat(), "nonce": permit.nonce, "max_uses": permit.max_uses}

    def _bound_session_integration(self, db: Session, *, tenant_id: str, session: AIAccountSession) -> AccountBoundaryIntegration | None:
        if session.tenant_id != tenant_id or not session.account_boundary_integration_id:
            return None
        integration = db.get(AccountBoundaryIntegration, session.account_boundary_integration_id)
        if integration is None or integration.tenant_id != tenant_id or (integration.provider, integration.product) != (session.provider, session.product) or session.surface not in (integration.surfaces or []):
            return None
        return integration

    def _session_identity_provenance_matches(self, db: Session, *, tenant_id: str, session: AIAccountSession) -> bool:
        integration = self._bound_session_integration(db, tenant_id=tenant_id, session=session)
        identity = db.get(AIAccountIdentity, session.account_identity_ref)
        if integration is None or identity is None:
            return False
        if session.session_state not in {"ENTERPRISE_VERIFIED", "PARTNER_VERIFIED", "EXTERNAL_UNAPPROVED"}:
            return True
        provenance = _integration_provenance(integration.id)
        return provenance in (identity.evidence_refs or []) and provenance in (session.evidence_refs or []) and _session_state_for_account_class(identity.account_class) == session.session_state and (session.organisation_id is None or session.organisation_id in (identity.organisation_ids or [])) and (session.workspace_id is None or session.workspace_id in (identity.workspace_ids or []))

    def issue_session_permit(self, db: Session, *, tenant_id: str, session_id: str, device_id: str, process_instance: str | None, allowed_destination_scope: list[str], allowed_data_classes: list[str], allowed_business_purposes: list[str], policy_epoch: int, issued_at: datetime, ttl_seconds: int) -> AIAccountSessionPermit:
        session = db.get(AIAccountSession, session_id)
        if session is None or session.tenant_id != tenant_id: raise LookupError("account_session_not_found")
        if session.device_id != device_id or (session.process_instance and session.process_instance != process_instance): raise PermissionError("session_binding_mismatch")
        if not session.session_state.startswith(("ENTERPRISE", "PARTNER")) or _utc(session.expires_at) < _utc(issued_at): raise PermissionError("session_not_enterprise_bound")
        integration = self._bound_session_integration(db, tenant_id=tenant_id, session=session)
        validation = self._current_validation(db, tenant_id=tenant_id, integration_id=integration.id, provider=session.provider, product=session.product, surface=session.surface, checked_at=issued_at) if integration else None
        if validation is None: raise PermissionError("current_server_validation_required")
        row = AIAccountSessionPermit(permit_id=f"permit-{uuid4()}", tenant_id=tenant_id, account_session_ref=session.id, device_id=device_id, provider=session.provider, product=session.product, surface=session.surface, user_identity_ref=session.user_identity_ref, account_identity_ref=session.account_identity_ref, process_instance=process_instance, browser_profile=session.browser_profile, workspace_or_org_binding={"organisation_id": session.organisation_id, "workspace_id": session.workspace_id}, allowed_destination_scope=sorted(set(allowed_destination_scope)), allowed_data_classes=sorted(set(allowed_data_classes)), allowed_business_purposes=sorted(set(allowed_business_purposes)), issued_at=issued_at, expires_at=issued_at + timedelta(seconds=ttl_seconds), policy_epoch=policy_epoch, nonce=secrets.token_hex(16), signature="", signing_key_id="", signing_algorithm="", signed_envelope={}, max_uses=1, consumed_state="UNCONSUMED")
        db.add(row); db.flush()
        signed = sign_object(self.signing_provider, purpose=ACCOUNT_SESSION_PERMIT_PURPOSE, domain=ACCOUNT_SESSION_PERMIT_DOMAIN, tenant_id=tenant_id, key_id=self._key_id(ACCOUNT_SESSION_PERMIT_PURPOSE, tenant_id), value=self._permit_payload(row))
        row.signature = signed["signature"]; row.signing_key_id = signed["signing_key_id"]; row.signing_algorithm = signed["algorithm"]; row.signed_envelope = signed
        db.flush(); return row

    def verify_session_permit(self, db: Session, *, tenant_id: str, permit_id: str, device_id: str, process_instance: str | None, provider: str, product: str, surface: str, destination: str, data_class: str | None = None, business_purpose: str | None = None, policy_epoch: int, checked_at: datetime) -> dict[str, Any]:
        permit = db.scalar(select(AIAccountSessionPermit).where(AIAccountSessionPermit.tenant_id == tenant_id, AIAccountSessionPermit.id == permit_id).with_for_update())
        if permit is None: return {"valid": False, "reason": "permit_not_found"}
        expected = self._permit_payload(permit) | {"algorithm": permit.signing_algorithm, "signing_key_id": permit.signing_key_id, "signature": permit.signature}
        if _canonical_json(dict(permit.signed_envelope or {})) != _canonical_json(expected): return {"valid": False, "reason": "envelope_mismatch"}
        if not verify_signed_object(self.signing_provider, purpose=ACCOUNT_SESSION_PERMIT_PURPOSE, domain=ACCOUNT_SESSION_PERMIT_DOMAIN, tenant_id=tenant_id, value=dict(permit.signed_envelope), current_authority=True): return {"valid": False, "reason": "invalid_signature"}
        session = db.get(AIAccountSession, permit.account_session_ref)
        if session is None or session.tenant_id != tenant_id or (session.provider, session.product, session.surface, session.device_id, session.account_identity_ref, session.user_identity_ref) != (permit.provider, permit.product, permit.surface, permit.device_id, permit.account_identity_ref, permit.user_identity_ref):
            return {"valid": False, "reason": "session_binding_mismatch"}
        if not self._session_identity_provenance_matches(db, tenant_id=tenant_id, session=session):
            session.session_state = "DRIFTED"; session.drift_state = "IDENTITY_PROVENANCE_DRIFT"; self._revoke_session_permits(db, session.id); db.flush()
            return {"valid": False, "reason": "session_identity_mismatch"}
        if permit.revoked: return {"valid": False, "reason": "permit_revoked"}
        if _utc(permit.expires_at) < _utc(checked_at): return {"valid": False, "reason": "permit_expired"}
        if permit.consumed_count >= permit.max_uses: return {"valid": False, "reason": "permit_consumed"}
        if permit.device_id != device_id: return {"valid": False, "reason": "device_mismatch"}
        if permit.process_instance and permit.process_instance != process_instance: return {"valid": False, "reason": "process_mismatch"}
        if (permit.provider, permit.product, permit.surface) != (provider, product, surface): return {"valid": False, "reason": "surface_mismatch"}
        if permit.policy_epoch != policy_epoch: return {"valid": False, "reason": "policy_epoch_mismatch"}
        if destination not in (permit.allowed_destination_scope or []): return {"valid": False, "reason": "destination_mismatch"}
        if not data_class or data_class not in (permit.allowed_data_classes or []): return {"valid": False, "reason": "data_class_mismatch"}
        if not business_purpose or business_purpose not in (permit.allowed_business_purposes or []): return {"valid": False, "reason": "business_purpose_mismatch"}
        permit.consumed_count += 1; permit.consumed_state = "CONSUMED"; permit.consumed_at = checked_at; db.flush(); return {"valid": True, "reason": "matched", "consumed_count": permit.consumed_count}

    def _revoke_session_permits(self, db: Session, session_id: str) -> None:
        db.execute(update(AIAccountSessionPermit).where(AIAccountSessionPermit.account_session_ref == session_id).values(revoked=True, consumed_state="REVOKED"))

    def _revoke_integration_permits(self, db: Session, integration: AccountBoundaryIntegration) -> None:
        session_ids = select(AIAccountSession.id).where(AIAccountSession.tenant_id == integration.tenant_id, AIAccountSession.account_boundary_integration_id == integration.id)
        db.execute(update(AIAccountSessionPermit).where(AIAccountSessionPermit.account_session_ref.in_(session_ids)).values(revoked=True, consumed_state="REVOKED"))

    def revalidate_session(self, db: Session, *, tenant_id: str, session_id: str, policy_version: str | None, checked_at: datetime) -> AIAccountSession:
        session = db.get(AIAccountSession, session_id)
        if session is None or session.tenant_id != tenant_id: raise LookupError("account_session_not_found")
        identity = db.get(AIAccountIdentity, session.account_identity_ref)
        if identity is None or identity.tenant_id != tenant_id:
            session.session_state = "DRIFTED"
            session.drift_state = "IDENTITY_PROVENANCE_DRIFT"
            self._revoke_session_permits(db, session.id)
            db.flush()
            return session
        expected_untrusted_state = _session_state_for_account_class(identity.account_class)
        if expected_untrusted_state in {"PERSONAL_DETECTED", "ANONYMOUS_DETECTED", "UNKNOWN"}:
            if _utc(session.expires_at) < _utc(checked_at):
                session.session_state = "EXPIRED"
                session.drift_state = "SESSION_EXPIRED"
            elif session.policy_version != policy_version or session.session_state != expected_untrusted_state:
                session.session_state = "DRIFTED"
                session.drift_state = "POLICY_OR_IDENTITY_DRIFT"
            else:
                session.last_verified_at = checked_at
            if session.session_state in {"EXPIRED", "DRIFTED"}:
                self._revoke_session_permits(db, session.id)
            db.flush()
            return session
        integration = self._bound_session_integration(db, tenant_id=tenant_id, session=session)
        validation = self._current_validation(db, tenant_id=tenant_id, integration_id=integration.id, provider=session.provider, product=session.product, surface=session.surface, checked_at=checked_at) if integration else None
        if _utc(session.expires_at) < _utc(checked_at) or validation is None or session.policy_version != policy_version or not self._session_identity_provenance_matches(db, tenant_id=tenant_id, session=session):
            session.session_state = "DRIFTED" if _utc(session.expires_at) >= _utc(checked_at) else "EXPIRED"; session.drift_state = "POLICY_OR_ROUTE_DRIFT"; self._revoke_session_permits(db, session.id)
        else: session.last_verified_at = checked_at
        db.flush(); return session

    def revoke_session(self, db: Session, *, tenant_id: str, session_id: str) -> AIAccountSession:
        session = db.get(AIAccountSession, session_id)
        if session is None or session.tenant_id != tenant_id: raise LookupError("account_session_not_found")
        session.session_state = "REVOKED"; self._revoke_session_permits(db, session.id); db.flush(); return session

    def revoke_permit(self, db: Session, *, tenant_id: str, permit_id: str) -> AIAccountSessionPermit:
        row = db.scalar(select(AIAccountSessionPermit).where(AIAccountSessionPermit.tenant_id == tenant_id, AIAccountSessionPermit.id == permit_id))
        if row is None: raise LookupError("permit_not_found")
        row.revoked = True; row.consumed_state = "REVOKED"; db.flush(); return row

    def decide_account_access(self, db: Session, *, tenant_id: str, session_id: str, required_assurance: str, control_point: str, policy_id: str | None, policy_version: str | None, decided_at: datetime) -> dict[str, Any]:
        session = self.revalidate_session(db, tenant_id=tenant_id, session_id=session_id, policy_version=policy_version, checked_at=decided_at)
        identity = db.get(AIAccountIdentity, session.account_identity_ref)
        if identity is None: raise LookupError("account_identity_not_found")
        integration = self._bound_session_integration(db, tenant_id=tenant_id, session=session)
        if session.session_state == "PERSONAL_DETECTED": decision = "BLOCK_PERSONAL"
        elif session.session_state == "ANONYMOUS_DETECTED": decision = "BLOCK_ANONYMOUS"
        elif session.session_state == "EXTERNAL_UNAPPROVED": decision = "BLOCK_EXTERNAL_TENANT"
        elif integration and integration.lifecycle_state == "MONITOR" and integration.mode == "monitor": decision = "MONITOR_ONLY"
        elif integration and integration.lifecycle_state == "ENFORCE" and integration.mode == "enforce" and session.session_state == "ENTERPRISE_VERIFIED" and ASSURANCE_RANK[session.assurance_level] >= ASSURANCE_RANK.get(required_assurance, 0): decision = "ALLOW_ENTERPRISE"
        elif integration and integration.lifecycle_state == "ENFORCE" and integration.mode == "enforce" and session.session_state == "PARTNER_VERIFIED" and ASSURANCE_RANK[session.assurance_level] >= ASSURANCE_RANK.get(required_assurance, 0): decision = "ALLOW_PARTNER"
        else: decision = "BLOCK_UNKNOWN"
        payload = {"tenant_id": tenant_id, "session_id": session.id, "account_class": identity.account_class, "assurance_level": session.assurance_level, "required_assurance": required_assurance, "decision": decision, "policy_version": policy_version}
        signed = sign_object(self.signing_provider, purpose=ACCOUNT_ACCESS_RECEIPT_PURPOSE, domain=ACCOUNT_ACCESS_RECEIPT_DOMAIN, tenant_id=tenant_id, key_id=self._key_id(ACCOUNT_ACCESS_RECEIPT_PURPOSE, tenant_id), value=payload)
        receipt = AccountAccessReceipt(receipt_id=f"account-access-{uuid4()}", tenant_id=tenant_id, actor=session.user_identity_ref, device=session.device_id, application=session.process_instance or session.browser_profile or session.surface, provider=session.provider, product=session.product, surface=session.surface, account_class=identity.account_class, organisation_or_workspace=session.organisation_id or session.workspace_id, verification_method=identity.verification_method, assurance_level=session.assurance_level, decision=decision, control_point=control_point, policy_id=policy_id, policy_version=policy_version, managed_route_state=(integration.route_health if integration else "UNKNOWN"), issued_at=decided_at, expires_at=session.expires_at, evidence_refs=[], blind_spots=[] if decision.startswith("ALLOW") else ["enterprise_account_not_verified"], signature=signed["signature"], signing_key_id=signed["signing_key_id"], signing_algorithm=signed["algorithm"], signed_envelope=signed, safe_payload=payload)
        db.add(receipt); db.flush(); return {"decision": decision, "receipt_id": receipt.id, "receipt_ref": receipt.receipt_id}

    def decide_device_download(
        self,
        db: Session,
        *,
        tenant_id: str,
        session_id: str,
        data_classification: str,
        policy_id: str | None,
        policy_version: str | None,
        decided_at: datetime,
    ) -> dict[str, Any]:
        """Make a fail-secure download decision from persisted account/device facts.

        Callers cannot assert that an account is corporate, that a device is
        managed, or that inline download control exists. An enrolled endpoint
        is only REGISTERED_BYOD until an authoritative device-management
        integration supplies a stronger assurance record.
        """

        session = db.scalar(
            select(AIAccountSession).where(
                AIAccountSession.tenant_id == tenant_id,
                AIAccountSession.id == session_id,
            )
        )
        if session is None:
            raise LookupError("account_session_not_found")
        identity = db.scalar(
            select(AIAccountIdentity).where(
                AIAccountIdentity.tenant_id == tenant_id,
                AIAccountIdentity.id == session.account_identity_ref,
            )
        )
        if identity is None:
            raise LookupError("account_identity_not_found")
        endpoint = db.scalar(
            select(EndpointDeviceIdentity).where(
                EndpointDeviceIdentity.tenant_id == tenant_id,
                EndpointDeviceIdentity.endpoint_id == session.device_id,
                EndpointDeviceIdentity.status == "active",
            )
        )
        endpoint_bound = bool(
            endpoint is not None
            and endpoint.assigned_user_id
            and endpoint.assigned_user_id == session.user_identity_ref
        )
        device_assurance = "REGISTERED_BYOD" if endpoint_bound else "UNMANAGED"
        normalized_surface = str(session.surface or "").strip().lower()
        if normalized_surface in {"browser", "web"}:
            deployment_family = "browser"
        elif normalized_surface in {"desktop", "cli", "ide", "endpoint"}:
            deployment_family = "endpoint"
        elif normalized_surface in {"runtime", "agent", "mcp"}:
            deployment_family = "runtime"
        elif normalized_surface in {"saas", "api", "saas_api", "provider"}:
            deployment_family = "saas_api"
        else:
            deployment_family = "unknown"
        surface_rows = tuple(
            db.scalars(
                select(DeploymentSurface)
                .where(
                    DeploymentSurface.tenant_id == tenant_id,
                    DeploymentSurface.deployment_family == deployment_family,
                    DeploymentSurface.status == "active",
                    DeploymentSurface.health_status == "healthy",
                    DeploymentSurface.control_capability == "inline",
                    DeploymentSurface.containment_capability.in_(("direct", "surface_limited")),
                )
                .order_by(DeploymentSurface.last_heartbeat_at.desc())
                .limit(100)
            ).all()
        )

        def supports_current_download_control(row: DeploymentSurface) -> bool:
            heartbeat = _utc(row.last_heartbeat_at) if row.last_heartbeat_at else None
            if heartbeat is None or _utc(decided_at) - heartbeat > _DOWNLOAD_CONTROL_FRESHNESS:
                return False
            profile = row.capability_profile if isinstance(row.capability_profile, dict) else {}
            raw = profile.get("download_control")
            if isinstance(raw, dict):
                raw = raw.get("state") or raw.get("level") or raw.get("capability")
            return str(raw or "").strip().lower() in _DOWNLOAD_CAPABILITY_STATES

        enforcement_surface = next(
            (row for row in surface_rows if supports_current_download_control(row)),
            None,
        )
        enforcement_available = enforcement_surface is not None
        selected_control_point = (
            str(enforcement_surface.source_id)[:64]
            if enforcement_surface is not None
            else "unavailable"
        )
        account_class = str(identity.account_class or "UNKNOWN").upper()
        classification = str(data_classification or "UNKNOWN").strip().upper()
        restricted = classification not in {"PUBLIC", "UNCLASSIFIED"}
        session_current = bool(
            _utc(session.expires_at) >= _utc(decided_at)
            and session.session_state
            not in {"EXPIRED", "REVOKED", "DRIFTED", "BYPASS_SUSPECTED"}
        )
        corporate = account_class.startswith("ENTERPRISE")
        personal = account_class.startswith("PERSONAL") or account_class in {
            "ANONYMOUS",
            "UNKNOWN",
        }
        if restricted and not enforcement_available and corporate:
            decision, reason = "BLOCK_UNKNOWN", "corporate_session_denied_download_control_gap"
            session.session_state = "BYPASS_SUSPECTED"
            session.drift_state = "DOWNLOAD_CONTROL_UNAVAILABLE"
            self._revoke_session_permits(db, session.id)
        elif not session_current:
            decision, reason = "BLOCK_UNKNOWN", "account_session_not_current"
        elif restricted and personal:
            decision, reason = "BLOCK_PERSONAL", "restricted_download_to_unapproved_account"
        elif restricted and corporate and device_assurance != "MANAGED_COMPLIANT":
            decision, reason = "BLOCK_UNKNOWN", "managed_device_assurance_required"
        elif session.session_state != "ENTERPRISE_VERIFIED":
            decision, reason = "BLOCK_UNKNOWN", "enterprise_session_not_verified"
        else:
            decision, reason = "ALLOW_ENTERPRISE", "verified_enterprise_download"

        safe_payload = {
            "tenant_id": tenant_id,
            "session_id": session.id,
            "operation": "download",
            "data_classification": classification,
            "account_class": account_class,
            "device_assurance": device_assurance,
            "decision": decision,
            "reason": reason,
            "enforcement_status": "CURRENT" if enforcement_available else "GAP",
            "control_point": selected_control_point,
            "policy_version": policy_version,
        }
        signed = sign_object(
            self.signing_provider,
            purpose=ACCOUNT_ACCESS_RECEIPT_PURPOSE,
            domain=ACCOUNT_ACCESS_RECEIPT_DOMAIN,
            tenant_id=tenant_id,
            key_id=self._key_id(ACCOUNT_ACCESS_RECEIPT_PURPOSE, tenant_id),
            value=safe_payload,
        )
        receipt = AccountAccessReceipt(
            receipt_id=f"account-access-{uuid4()}",
            tenant_id=tenant_id,
            actor=session.user_identity_ref,
            device=session.device_id,
            application=session.process_instance or session.browser_profile or session.surface,
            provider=session.provider,
            product=session.product,
            surface=session.surface,
            account_class=account_class,
            organisation_or_workspace=session.organisation_id or session.workspace_id,
            verification_method=identity.verification_method,
            assurance_level=session.assurance_level,
            decision=decision,
            control_point=selected_control_point,
            policy_id=policy_id,
            policy_version=policy_version,
            managed_route_state=("CURRENT" if enforcement_available else "GAP"),
            issued_at=decided_at,
            expires_at=session.expires_at,
            evidence_refs=list(identity.evidence_refs or ()),
            blind_spots=[
                *(
                    []
                    if device_assurance == "MANAGED_COMPLIANT"
                    else ["authoritative_managed_device_assurance_unavailable"]
                ),
                *([] if enforcement_available else ["inline_download_control_unavailable"]),
            ],
            signature=signed["signature"],
            signing_key_id=signed["signing_key_id"],
            signing_algorithm=signed["algorithm"],
            signed_envelope=signed,
            safe_payload=safe_payload,
        )
        db.add(receipt)
        db.flush()
        return {
            "decision": decision,
            "reason": reason,
            "device_assurance": device_assurance,
            "enforcement_available": enforcement_available,
            "enforcement_status": "CURRENT" if enforcement_available else "GAP",
            "control_point": selected_control_point,
            "receipt_id": receipt.id,
            "receipt_ref": receipt.receipt_id,
        }
