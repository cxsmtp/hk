"""Requests from data subjects (Settings → Compliance → Data requests; app/services/data_subject_requests.py, migration
0107): recording and listing requests, who may read and change them, tenant isolation, the due date and what counts as
overdue, the access export's contents, erasure by pseudonymisation (the audit log kept, never the last Owner), the
trail, the audit entries, and the controls and packs that read them."""

from __future__ import annotations

import datetime as dt
import io
import json
import zipfile

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, func, select
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.permissions import ADMIN_ONLY, PERMISSION_BY_ID, default_permissions
from app.core.security import get_password_hash
from app.db.models.access import ImmutableRecordError
from app.db.models.activity_audit import AIAction, AISession, DeploymentEndpoint, PromptPayload, UserRegistry
from app.db.models.audit import AuditLog
from app.db.models.data_subject import DataSubjectRequest, DataSubjectRequestEvent
from app.db.models.finding import Finding
from app.db.models.platform_records import UserActivity
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import compliance_service, data_subject_requests as dsr
from app.services.audit_service import write_audit_log
from app.services.compliance_packs import controls as registry

PASSWORD = "correct-Horse-2026"
RAW_PROMPT = "My card is 4111 1111 1111 1111 and my name is Priya Raman"
MASKED_PROMPT = "My card is [credit_card] and my name is [person]"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'dsr.sqlite3'}", connect_args={"check_same_thread": False})
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    monkeypatch.setattr(settings, "hawk_data_dir", str(tmp_path / "data"))
    monkeypatch.delenv("TIME_SYNC_NTP_SERVER", raising=False)
    monkeypatch.setattr(compliance_service, "kernel_clock", lambda: {"synchronized": True, "source": "kernel"})
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "db": factory}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def member(env, email: str, role: str = "owner", slug: str = "acme", *, sign_in: bool = True) -> dict:
    with env["db"]() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == slug))
        if tenant is None:
            tenant = Tenant(name=slug.title(), slug=slug, is_active=True)
            db.add(tenant)
            db.flush()
        user = User(email=email, full_name=email.split("@")[0].title(), hashed_password=get_password_hash(PASSWORD), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
        db.commit()
        out = {"id": user.id, "tenant": tenant.id, "email": email}
    if sign_in:
        response = env["client"].post("/auth/login", json={"email": email, "password": PASSWORD})
        assert response.status_code == 200, response.text
        tokens = response.json()
        out["h"] = {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tokens["selected_tenant_id"]}
    return out


def create(env, headers, **body):
    payload = {"kind": "access", "subjectEmail": "person@example.test", "law": "dpdp", **body}
    response = env["client"].post("/compliance/data-requests", headers=headers, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def audit(env, tenant_id: str, prefix: str = "privacy.") -> list[AuditLog]:
    with env["db"]() as db:
        return list(db.scalars(select(AuditLog).where(AuditLog.tenant_id == tenant_id, AuditLog.action.startswith(prefix)).order_by(AuditLog.seq)).all())


def seed_activity(env, user: dict) -> None:
    """Records a member leaves behind: an audit entry, console activity, an AI session and action with its prompt, a
    finding, a directory entry and an endpoint."""

    with env["db"]() as db:
        tenant_id = user["tenant"]
        write_audit_log(db, tenant_id=tenant_id, actor_user_id=user["id"], actor_type="human", action="policies.changed", resource_type="policy", resource_id="p1", payload={"outcome": "changed", "reason": "Changed the policy."})
        db.add(UserActivity(tenant_id=tenant_id, user_id=user["id"], user=user["email"], name="Priya", ip="10.0.0.7", action="Opened the dashboard", method="GET", route="/dashboard", status=200))
        db.add(AISession(session_id="s-1", tenant_id=tenant_id, user_id=user["id"], ai_app="ChatGPT"))
        db.add(AIAction(action_id="a-1", tenant_id=tenant_id, session_id="s-1", user_id=user["id"], action_type="prompt", ai_app="ChatGPT", enforcement_action="redacted"))
        db.flush()
        db.add(PromptPayload(action_id="a-1", raw_prompt=RAW_PROMPT, redacted_prompt=MASKED_PROMPT, pii_detected=True))
        db.add(Finding(tenant_id=tenant_id, source_surface="browser", ai_tool="ChatGPT", user_id=user["id"], user_email=user["email"], severity="high", finding_type="dlp", risk_category="data", dedupe_key="d-1"))
        db.add(UserRegistry(tenant_id=tenant_id, user_id=user["id"], display_name="Priya Raman", email=user["email"], department="Finance"))
        db.add(DeploymentEndpoint(endpoint_id="e-1", tenant_id=tenant_id, user_id=user["id"], hostname="priya-laptop", ip_address="10.0.0.7", location="Pune"))
        db.commit()


# --- The permission ---------------------------------------------------------------------------------------------------


def test_the_permission_is_in_the_catalogue_for_owners_and_admins():
    permission = PERMISSION_BY_ID["compliance.dsr.manage"]
    assert permission.level == "manage" and permission.group == "Administration"
    # Not Admin-only: a role made here (a compliance officer's) can be given it.
    assert "compliance.dsr.manage" not in ADMIN_ONLY
    assert "compliance.dsr.manage" in default_permissions("owner") and "compliance.dsr.manage" in default_permissions("admin")
    for role in ("auditor", "operator", "viewer"):
        assert "compliance.dsr.manage" not in default_permissions(role)


def test_who_may_read_and_change_requests(env):
    owner = member(env, "owner@acme.test", "owner")
    auditor = member(env, "auditor@acme.test", "auditor")
    viewer = member(env, "viewer@acme.test", "viewer")
    operator = member(env, "operator@acme.test", "operator")
    c = env["client"]
    made = create(env, owner["h"])
    rid = made["request"]["id"]
    # The auditor reads (with the audit log) but changes nothing.
    assert c.get("/compliance/data-requests", headers=auditor["h"]).status_code == 200
    assert c.get(f"/compliance/data-requests/{rid}", headers=auditor["h"]).json()["mayManage"] is False
    assert c.post("/compliance/data-requests", headers=auditor["h"], json={"kind": "access", "subjectEmail": "x@example.test"}).status_code == 403
    assert c.patch(f"/compliance/data-requests/{rid}", headers=auditor["h"], json={"status": "verifying"}).status_code == 403
    assert c.post(f"/compliance/data-requests/{rid}/export", headers=auditor["h"]).status_code == 403
    assert c.put("/compliance/data-requests/settings", headers=auditor["h"], json={"dueDays": 10}).status_code == 403
    for person in (viewer, operator):
        assert c.get("/compliance/data-requests", headers=person["h"]).status_code == 403
        assert c.get(f"/compliance/data-requests/{rid}", headers=person["h"]).status_code == 403
        assert c.post("/compliance/data-requests", headers=person["h"], json={"kind": "access", "subjectEmail": "x@example.test"}).status_code == 403
    assert c.get("/compliance/data-requests").status_code in (401, 403)


# --- Recording, listing and the trail -----------------------------------------------------------------------------------


def test_create_list_get_with_a_due_date_a_trail_and_an_audit_entry(env):
    owner = member(env, "owner@acme.test", "owner")
    member(env, "priya@acme.test", "operator", sign_in=False)
    c = env["client"]
    made = create(env, owner["h"], subjectEmail="Priya@Acme.test", receivedAt="2026-11-20", channel="email", notes="Asked by email.")
    request = made["request"]
    assert request["kind"] == "access" and request["status"] == "received" and request["law"] == "dpdp"
    assert request["subjectEmail"] == "priya@acme.test" and request["subjectMatched"] is True
    assert request["receivedAt"].startswith("2026-11-20") and request["dueAt"].startswith("2026-12-20")
    assert request["handledBy"] == "owner@acme.test"
    assert [e["kind"] for e in made["events"]] == ["created"] and made["mayManage"] is True
    listed = c.get("/compliance/data-requests", headers=owner["h"]).json()
    assert [r["id"] for r in listed["items"]] == [request["id"]]
    assert listed["settings"]["dueDays"] == 30 and listed["summary"]["open"] == 1
    assert {k["id"] for k in listed["kinds"]} == {"access", "correction", "erasure", "grievance", "nomination"}
    got = c.get(f"/compliance/data-requests/{request['id']}", headers=owner["h"]).json()
    assert got["request"]["id"] == request["id"]
    entries = audit(env, owner["tenant"])
    assert [e.action for e in entries] == ["privacy.request.created"]
    assert entries[0].resource_id == request["id"] and "priya" not in json.dumps(entries[0].payload).lower()
    # Bad input is refused with a sentence.
    for body in ({"kind": "delete"}, {"kind": "access"}, {"kind": "access", "subjectEmail": "not-an-email"}, {"kind": "access", "subjectEmail": "a@b.test", "receivedAt": "2099-01-01"}, {"kind": "access", "subjectEmail": "a@b.test", "law": "gdpr"}):
        answer = c.post("/compliance/data-requests", headers=owner["h"], json=body)
        assert answer.status_code == 400 and answer.json()["error"], body
    assert c.get("/compliance/data-requests?status=nonsense", headers=owner["h"]).status_code == 400


def test_status_changes_notes_and_the_append_only_trail(env):
    owner = member(env, "owner@acme.test", "owner")
    admin = member(env, "admin@acme.test", "admin")
    c = env["client"]
    rid = create(env, owner["h"], kind="correction")["request"]["id"]
    path = f"/compliance/data-requests/{rid}"
    assert c.patch(path, headers=owner["h"], json={"status": "verifying", "note": "Identity checked by phone."}).status_code == 200
    assert c.patch(path, headers=owner["h"], json={"handledBy": "admin@acme.test"}).json()["request"]["handledBy"] == "admin@acme.test"
    assert c.patch(path, headers=owner["h"], json={"handledBy": "nobody@elsewhere.test"}).status_code == 400
    # Completing a correction needs a note of what was done; refusing needs a reason.
    assert c.patch(path, headers=admin["h"], json={"status": "completed"}).status_code == 400
    assert c.patch(path, headers=admin["h"], json={"status": "refused"}).status_code == 400
    done = c.patch(path, headers=admin["h"], json={"status": "completed", "note": "Name corrected on Settings → People."}).json()
    assert done["request"]["status"] == "completed" and done["request"]["completedAt"]
    # Final: it does not move again.
    assert c.patch(path, headers=admin["h"], json={"status": "in_progress"}).status_code == 409
    assert c.patch(path, headers=admin["h"], json={}).status_code == 400
    kinds = [(e["kind"], e["from"], e["to"]) for e in done["events"]]
    assert kinds == [("created", "", "received"), ("status", "received", "verifying"), ("assigned", "", ""), ("status", "verifying", "completed")]
    assert done["events"][1]["note"] == "Identity checked by phone." and done["events"][-1]["by"] == "admin@acme.test"
    assert [e.action for e in audit(env, owner["tenant"])] == ["privacy.request.created"] + ["privacy.request.updated"] * 3
    # The trail is append-only.
    with env["db"]() as db:
        event = db.scalars(select(DataSubjectRequestEvent).where(DataSubjectRequestEvent.request_id == rid)).first()
        event.note = "rewritten"
        with pytest.raises(ImmutableRecordError):
            db.flush()
        db.rollback()
        event = db.scalars(select(DataSubjectRequestEvent).where(DataSubjectRequestEvent.request_id == rid)).first()
        db.delete(event)
        with pytest.raises(ImmutableRecordError):
            db.flush()


def test_a_refusal_keeps_its_reason(env):
    owner = member(env, "owner@acme.test", "owner")
    rid = create(env, owner["h"], kind="grievance")["request"]["id"]
    refused = env["client"].patch(f"/compliance/data-requests/{rid}", headers=owner["h"], json={"status": "refused", "refusalReason": "Not about personal data we process."}).json()
    assert refused["request"]["status"] == "refused" and refused["request"]["refusalReason"] == "Not about personal data we process."
    assert refused["events"][-1]["note"] == "Not about personal data we process."


# --- Tenant isolation ---------------------------------------------------------------------------------------------------


def test_another_workspace_sees_nothing_and_its_people_are_never_matched(env):
    acme = member(env, "owner@acme.test", "owner", "acme")
    beta = member(env, "owner@beta.test", "owner", "beta")
    member(env, "staff@beta.test", "operator", "beta", sign_in=False)
    c = env["client"]
    made = create(env, acme["h"], subjectEmail="staff@beta.test", kind="erasure")
    assert made["request"]["subjectMatched"] is False  # beta's member is not acme's
    rid = made["request"]["id"]
    assert c.get("/compliance/data-requests", headers=beta["h"]).json()["items"] == []
    assert c.get(f"/compliance/data-requests/{rid}", headers=beta["h"]).status_code == 404
    assert c.patch(f"/compliance/data-requests/{rid}", headers=beta["h"], json={"status": "verifying"}).status_code == 404
    assert c.post(f"/compliance/data-requests/{rid}/erase", headers=beta["h"], json={"confirm": True}).status_code == 404
    assert c.get("/compliance/data-requests", headers=beta["h"]).json()["summary"]["total"] == 0
    # Erasing from acme leaves beta's account alone.
    assert c.post(f"/compliance/data-requests/{rid}/erase", headers=acme["h"], json={"confirm": True}).status_code == 200
    with env["db"]() as db:
        staff = db.scalar(select(User).where(User.email == "staff@beta.test"))
        assert staff is not None and staff.is_active


# --- Due dates and overdue ------------------------------------------------------------------------------------------------


def test_overdue_and_due_soon_are_counted_listed_and_surfaced(env):
    owner = member(env, "owner@acme.test", "owner")
    c = env["client"]
    now = dt.datetime.now(dt.timezone.utc)
    late = create(env, owner["h"], receivedAt=(now - dt.timedelta(days=40)).date().isoformat())["request"]
    soon = create(env, owner["h"], kind="correction", receivedAt=(now - dt.timedelta(days=26)).date().isoformat())["request"]
    fresh = create(env, owner["h"], kind="grievance")["request"]
    assert late["overdue"] is True and late["daysLeft"] < 0
    assert soon["overdue"] is False and soon["dueSoon"] is True
    assert fresh["overdue"] is False and fresh["dueSoon"] is False
    listed = c.get("/compliance/data-requests?overdue=true", headers=owner["h"]).json()
    assert [r["id"] for r in listed["items"]] == [late["id"]]
    assert listed["summary"]["overdue"] == 1 and listed["summary"]["dueSoon"] == 1 and listed["summary"]["open"] == 3
    assert [r["id"] for r in c.get("/compliance/data-requests?status=open", headers=owner["h"]).json()["items"]] == [late["id"], soon["id"], fresh["id"]]
    # The Compliance overview and the packs overview show them.
    assert c.get("/compliance", headers=owner["h"]).json()["dataRequests"]["overdue"] == 1
    assert c.get("/compliance/packs", headers=owner["h"]).json()["dataRequests"]["dueSoon"] == 1
    controls = {x["id"]: x for x in c.get("/compliance/controls", headers=owner["h"]).json()["controls"]}
    assert controls["privacy.data_subject_requests"]["status"] == registry.GAP and "1 past their due date" in controls["privacy.data_subject_requests"]["reason"]
    dpdp = {r["id"]: r for r in c.get("/compliance/packs/dpdp-india", headers=owner["h"]).json()["requirements"]}
    assert dpdp["s.11 / R.14"]["status"] == "gap"
    pdpl = {r["id"]: r for r in c.get("/compliance/packs/uae-pdpl", headers=owner["h"]).json()["requirements"]}
    assert pdpl["Art. 15"]["controls"][0]["id"] == "privacy.data_subject_requests"
    # Answered: only the one due soon is left, so the control is partly met.
    c.patch(f"/compliance/data-requests/{late['id']}", headers=owner["h"], json={"status": "refused", "refusalReason": "Duplicate."})
    controls = {x["id"]: x for x in c.get("/compliance/controls", headers=owner["h"]).json()["controls"]}
    assert controls["privacy.data_subject_requests"]["status"] == registry.PARTLY
    c.patch(f"/compliance/data-requests/{soon['id']}", headers=owner["h"], json={"status": "completed", "note": "Corrected."})
    controls = {x["id"]: x for x in c.get("/compliance/controls", headers=owner["h"]).json()["controls"]}
    assert controls["privacy.data_subject_requests"]["status"] == registry.MET


def test_the_due_days_and_grievance_contact_are_set_per_workspace(env):
    owner = member(env, "owner@acme.test", "owner")
    beta = member(env, "owner@beta.test", "owner", "beta")
    c = env["client"]
    controls = {x["id"]: x for x in c.get("/compliance/controls", headers=owner["h"]).json()["controls"]}
    assert controls["privacy.grievance_contact"]["status"] == registry.GAP
    for days in (0, 91, "x", True):
        assert c.put("/compliance/data-requests/settings", headers=owner["h"], json={"dueDays": days}).status_code == 400
    saved = c.put("/compliance/data-requests/settings", headers=owner["h"], json={"dueDays": 15, "grievanceContact": "Data Protection Officer, dpo@acme.test, +971 4 000 0000"}).json()
    assert saved["settings"]["dueDays"] == 15 and saved["settings"]["grievanceContact"].startswith("Data Protection Officer")
    assert c.get("/compliance/data-requests/settings", headers=owner["h"]).json()["settings"]["dueDays"] == 15
    made = create(env, owner["h"], receivedAt="2026-11-01")["request"]
    assert made["dueAt"].startswith("2026-11-16")
    assert [e.action for e in audit(env, owner["tenant"], "privacy.settings")] == ["privacy.settings.changed"] * 2
    controls = {x["id"]: x for x in c.get("/compliance/controls", headers=owner["h"]).json()["controls"]}
    assert controls["privacy.grievance_contact"]["status"] == registry.MET
    dpdp = {r["id"]: r for r in c.get("/compliance/packs/dpdp-india", headers=owner["h"]).json()["requirements"]}
    assert dpdp["s.8(9) / R.9"]["status"] == "met"
    # Another workspace keeps its own.
    assert c.get("/compliance/data-requests/settings", headers=beta["h"]).json()["settings"] == {**c.get("/compliance/data-requests/settings", headers=beta["h"]).json()["settings"], "dueDays": 30, "grievanceContact": ""}


# --- Access: the export ---------------------------------------------------------------------------------------------------


def test_the_access_export_holds_what_hawk_ai_keeps_and_never_secrets_or_raw_prompts(env):
    owner = member(env, "owner@acme.test", "owner")
    priya = member(env, "priya@acme.test", "operator", sign_in=False)
    seed_activity(env, priya)
    c = env["client"]
    rid = create(env, owner["h"], subjectEmail="priya@acme.test")["request"]["id"]
    answer = c.post(f"/compliance/data-requests/{rid}/export", headers=owner["h"])
    assert answer.status_code == 200, answer.text
    assert answer.headers["cache-control"] == "no-store" and "attachment" in answer.headers["content-disposition"]
    assert answer.headers.get("X-Hawk-Evidence-Signature-Status") in ("signed", "unavailable")
    text = answer.text
    body = answer.json()
    assert body["kind"] == "hawk-ai-data-subject-access-export" and body["subject"]["accountFound"] is True
    holds = body["holds"]
    assert holds["account"]["email"] == "priya@acme.test" and holds["membership"]["role"] == "operator"
    assert [a["action"] for a in holds["auditEntries"]] == ["policies.changed"]
    assert holds["consoleActivity"][0]["route"] == "/dashboard"
    assert holds["aiSessions"][0]["aiApp"] == "ChatGPT"
    assert holds["aiActivity"][0]["decision"] == "redacted" and "[credit_card]" in holds["aiActivity"][0]["maskedPrompt"]
    assert holds["findings"][0]["type"] == "dlp" and holds["directory"][0]["department"] == "Finance"
    assert holds["endpoints"][0]["hostname"] == "priya-laptop"
    assert body["counts"]["auditEntries"] == 1 and body["counts"]["aiActivity"] == 1
    # Never the raw prompt, a password hash or anyone else's account.
    assert "4111" not in text and "Priya Raman" not in json.dumps(holds["aiActivity"])
    assert "$2b$" not in text and "hashed_password" not in text and "owner@acme.test" not in json.dumps(holds)
    detail = c.get(f"/compliance/data-requests/{rid}", headers=owner["h"]).json()
    assert detail["events"][-1]["kind"] == "exported" and detail["events"][-1]["details"]["counts"]["aiActivity"] == 1
    exported = audit(env, owner["tenant"], "privacy.request.exported")
    assert len(exported) == 1 and exported[0].resource_id == rid
    # Only an access request has an export.
    other = create(env, owner["h"], kind="erasure")["request"]["id"]
    assert c.post(f"/compliance/data-requests/{other}/export", headers=owner["h"]).status_code == 409


def test_an_export_for_someone_without_an_account_finds_their_records_by_email(env):
    owner = member(env, "owner@acme.test", "owner")
    with env["db"]() as db:
        db.add(Finding(tenant_id=owner["tenant"], source_surface="browser", ai_tool="Gemini", user_email="visitor@example.test", severity="low", finding_type="shadow_ai", risk_category="usage", dedupe_key="v-1"))
        db.commit()
    rid = create(env, owner["h"], subjectEmail="visitor@example.test")["request"]["id"]
    body = env["client"].post(f"/compliance/data-requests/{rid}/export", headers=owner["h"]).json()
    assert body["holds"]["account"] is None and body["subject"]["accountFound"] is False
    assert [f["aiTool"] for f in body["holds"]["findings"]] == ["Gemini"]


# --- Erasure ------------------------------------------------------------------------------------------------------------


def test_erasure_pseudonymises_personal_fields_and_keeps_the_audit_log(env):
    owner = member(env, "owner@acme.test", "owner")
    priya = member(env, "priya@acme.test", "operator")
    seed_activity(env, priya)
    c = env["client"]
    with env["db"]() as db:
        audit_before = db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.actor_user_id == priya["id"]))
    rid = create(env, owner["h"], kind="erasure", subjectEmail="priya@acme.test")["request"]["id"]
    assert c.post(f"/compliance/data-requests/{rid}/erase", headers=owner["h"], json={}).status_code == 400
    answer = c.post(f"/compliance/data-requests/{rid}/erase", headers=owner["h"], json={"confirm": True})
    assert answer.status_code == 200, answer.text
    result = answer.json()
    alias = dsr.pseudonym(priya["id"])
    assert result["erasure"]["pseudonym"] == alias and result["erasure"]["auditEntriesKept"] == audit_before
    assert result["request"]["status"] == "completed" and result["request"]["subjectEmail"] == f"{alias}@erased.invalid"
    assert result["events"][-1]["kind"] == "erased"
    with env["db"]() as db:
        user = db.get(User, priya["id"])
        assert user.email == f"{alias}@erased.invalid" and user.full_name == "Erased person" and not user.is_active
        assert user.hashed_password == "!erased" and user.mfa_secret is None
        assert db.scalar(select(UserRegistry.email).where(UserRegistry.user_id == priya["id"])) == f"{alias}@erased.invalid"
        assert db.scalar(select(UserRegistry.department).where(UserRegistry.user_id == priya["id"])) is None
        assert db.scalar(select(Finding.user_email).where(Finding.dedupe_key == "d-1")) == f"{alias}@erased.invalid"
        activity = db.scalars(select(UserActivity).where(UserActivity.user_id == priya["id"])).one()
        assert (activity.user, activity.name, activity.ip) == (f"{alias}@erased.invalid", "Erased person", "")
        payload = db.get(PromptPayload, "a-1")
        assert payload.raw_prompt is None and payload.redacted_prompt == MASKED_PROMPT
        endpoint = db.get(DeploymentEndpoint, "e-1")
        assert endpoint.hostname is None and endpoint.ip_address is None
        # The audit log: every entry the person made is still there, unchanged, pointing at the pseudonymised account.
        assert db.scalar(select(func.count()).select_from(AuditLog).where(AuditLog.actor_user_id == priya["id"])) == audit_before
        assert db.scalar(select(func.count()).select_from(DataSubjectRequest).where(DataSubjectRequest.subject_email == "priya@acme.test")) == 0
    erased = audit(env, owner["tenant"], "privacy.request.erased")
    assert len(erased) == 1 and alias in erased[0].payload["reason"] and "priya" not in erased[0].payload["reason"]
    # The person can no longer sign in, and the pseudonym is stable.
    assert c.post("/auth/login", json={"email": "priya@acme.test", "password": PASSWORD}).status_code != 200
    assert dsr.pseudonym(priya["id"]) == alias
    # Done: it cannot be erased twice.
    assert c.post(f"/compliance/data-requests/{rid}/erase", headers=owner["h"], json={"confirm": True}).status_code == 409


def test_erasure_refuses_the_last_owner_and_ones_own_account(env):
    owner = member(env, "owner@acme.test", "owner")
    admin = member(env, "admin@acme.test", "admin")
    c = env["client"]
    rid = create(env, admin["h"], kind="erasure", subjectEmail="owner@acme.test")["request"]["id"]
    refused = c.post(f"/compliance/data-requests/{rid}/erase", headers=admin["h"], json={"confirm": True})
    assert refused.status_code == 409 and "last active Owner" in refused.json()["error"]
    with env["db"]() as db:
        assert db.get(User, owner["id"]).email == "owner@acme.test"
    assert [e.action for e in audit(env, owner["tenant"], "privacy.request.erase_refused")] == ["privacy.request.erase_refused"]
    assert c.get(f"/compliance/data-requests/{rid}", headers=admin["h"]).json()["request"]["status"] == "received"
    mine = create(env, admin["h"], kind="erasure", subjectEmail="admin@acme.test")["request"]["id"]
    assert c.post(f"/compliance/data-requests/{mine}/erase", headers=admin["h"], json={"confirm": True}).status_code == 409
    # With a second Owner, the first can be erased.
    member(env, "second@acme.test", "owner", sign_in=False)
    assert c.post(f"/compliance/data-requests/{rid}/erase", headers=admin["h"], json={"confirm": True}).status_code == 200
    # Only an erasure request erases.
    access = create(env, admin["h"], kind="access", subjectEmail="second@acme.test")["request"]["id"]
    assert c.post(f"/compliance/data-requests/{access}/erase", headers=admin["h"], json={"confirm": True}).status_code == 409


# --- Evidence ---------------------------------------------------------------------------------------------------------


def test_the_dpdp_evidence_bundle_carries_the_requests_without_whom_they_are_about(env):
    owner = member(env, "owner@acme.test", "owner")
    c = env["client"]
    rid = create(env, owner["h"], subjectEmail="priya@example.test")["request"]["id"]
    answer = c.get("/compliance/packs/dpdp-india/evidence", headers=owner["h"])
    assert answer.status_code == 200, answer.text
    with zipfile.ZipFile(io.BytesIO(answer.content)) as archive:
        records = json.loads(archive.read("records.json"))
        entries = archive.read("audit-entries.jsonl").decode()
    requests = records["dataSubjectRequests"]["requests"]
    assert [r["id"] for r in requests] == [rid] and requests[0]["events"][0]["kind"] == "created"
    assert "priya" not in json.dumps(records["dataSubjectRequests"])
    assert "privacy.request.created" in entries
    # A pack that does not cite them leaves them out.
    desc = c.get("/compliance/packs/desc-isr/evidence", headers=owner["h"])
    with zipfile.ZipFile(io.BytesIO(desc.content)) as archive:
        assert "dataSubjectRequests" not in json.loads(archive.read("records.json"))
