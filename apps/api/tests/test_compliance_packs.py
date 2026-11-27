"""Framework packs on Settings → Compliance (app/services/compliance_packs; migration 0105): every pack file is sound,
every control it maps exists in the control registry, statuses follow the settings in force, records (attestations),
the signed evidence bundle checked with tools/verify_evidence.py, and who may do what."""

from __future__ import annotations

import importlib.util
import io
import json
import re
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import settings
from app.core.security import get_password_hash
from app.db.models.audit import AuditLog
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import compliance_packs, compliance_service, evidence_signing
from app.services.compliance_packs import controls as registry
from app.services.compliance_packs import evidence as pack_evidence

PASSWORD = "correct-Horse-2026"
REPO = Path(__file__).resolve().parents[3]
EXPECTED_PACKS = {
    "dpdp-india", "uae-pdpl", "desc-isr", "iso-27001", "iso-42001", "pci-dss", "cis-controls", "nist-ai-rmf", "nist-ai-600-1",
    "nist-csf", "nca-ecc", "sama-csf", "asd-essential-eight", "apra-cps-234", "au-ai-safety-standard", "owasp-llm-top10",
    "mitre-atlas", "eu-ai-act",
}


@pytest.fixture()
def env(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'packs.sqlite3'}", connect_args={"check_same_thread": False})
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
        yield {"client": client, "db": factory, "tmp": tmp_path}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def signed_in(env, email: str = "owner@example.test", role: str = "owner") -> dict[str, str]:
    with env["db"]() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == "acme"))
        if tenant is None:
            tenant = Tenant(name="Acme", slug="acme", is_active=True)
            db.add(tenant)
            db.flush()
        user = User(email=email, full_name=email.split("@")[0], hashed_password=get_password_hash(PASSWORD), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
        db.commit()
    response = env["client"].post("/auth/login", json={"email": email, "password": PASSWORD})
    assert response.status_code == 200, response.text
    tokens = response.json()
    return {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tokens["selected_tenant_id"]}


def requirement(view: dict, rid: str) -> dict:
    return next(r for r in view["requirements"] if r["id"] == rid)


def verifier():
    spec = importlib.util.spec_from_file_location("verify_evidence_tool", REPO / "tools" / "verify_evidence.py")
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# --- The pack files ----------------------------------------------------------------------------------------------------


def test_every_pack_file_is_valid_and_named_after_its_id():
    files = sorted(compliance_packs.PACKS_DIR.glob("*.json"))
    assert {f.stem for f in files} == EXPECTED_PACKS
    assert not list(compliance_packs.PACKS_DIR.glob("*.md"))
    for path in files:
        data = json.loads(path.read_text(encoding="utf-8"))
        assert compliance_packs.validate(data, name=path.name) == [], path.name
        assert data["id"] == path.stem
    assert [p["id"] for p in compliance_packs.packs()][0] == "dpdp-india"
    assert [p["id"] for p in compliance_packs.packs() if p["optional"]] == ["eu-ai-act"]


def test_every_mapped_control_exists_and_only_organisational_or_customer_requirements_map_to_nothing():
    for pack in compliance_packs.packs():
        for req in pack["requirements"]:
            for ref in req["controls"]:
                assert registry.exists(ref), f"{pack['id']} {req['id']}: {ref}"
            if not req["controls"]:
                assert req["applicability"] in ("organisational", "customer"), f"{pack['id']} {req['id']} maps to nothing"
            assert req["evidence"] and all(e in compliance_packs.EVIDENCE_SOURCES for e in req["evidence"])
        assert pack["sources"] and all(s["url"].startswith("https://") for s in pack["sources"])


def test_the_validator_refuses_what_it_should():
    good = json.loads((compliance_packs.PACKS_DIR / "owasp-llm-top10.json").read_text(encoding="utf-8"))
    assert compliance_packs.validate(good) == []
    bad = json.loads(json.dumps(good))
    bad["requirements"][0]["controls"] = ["no.such_control"]
    bad["requirements"][1]["controls"] = []  # a product requirement mapped to nothing
    bad["requirements"][2]["applicability"] = "vendor"
    bad["requirements"][3]["id"] = bad["requirements"][4]["id"]
    bad["requirements"][5]["evidence"] = ["the whole database"]
    bad["requirements"][6]["controls"] = ["detect.coverage:nope:LLM01"]
    bad["framework"]["url"] = "http://insecure.example"
    problems = " | ".join(compliance_packs.validate(bad))
    for needle in ("not in the control registry", "must map to at least one control", "applicability must be", "repeats", "evidence must list", "detect.coverage:nope:LLM01", "framework.url"):
        assert needle in problems, needle


def test_titles_are_short_paraphrases_and_ids_are_unique():
    for pack in compliance_packs.packs():
        ids = [r["id"] for r in pack["requirements"]]
        assert len(ids) == len(set(ids)), pack["id"]
        for req in pack["requirements"]:
            assert len(req["title"]) <= 160
            # Our own wording: never the standard's "shall" text pasted in.
            assert not re.search(r"\bshall\b", req["title"], re.IGNORECASE), f"{pack['id']} {req['id']}"


# --- The control registry ----------------------------------------------------------------------------------------------


def test_the_registry_lists_each_control_once_with_a_scope_and_a_page():
    ids = [c.id for c in registry.CONTROLS]
    assert len(ids) == len(set(ids))
    legacy = [c.legacy_id for c in registry.CONTROLS if c.legacy_id]
    assert sorted(legacy) == sorted(["AC-01", "AC-02", "AC-03", "AC-04", "AC-05", "AC-06", "LG-01", "LG-02", "LG-03", "LG-04", "IR-01", "CR-01", "CR-02", "CR-03", "SI-01", "DR-01", "AI-01"])
    for control in registry.CONTROLS:
        assert control.scope in registry.SCOPES
        assert control.href.startswith("/settings/")
        assert (control.check is None) != (control.param_check is None)
        if control.planned:
            assert control.id.startswith("gap.")
    assert registry.exists("detect.coverage:owasp_llm:LLM01") and not registry.exists("detect.coverage") and not registry.exists("auth.two_step:x")


def test_every_control_has_a_real_status_on_a_fresh_installation(env):
    headers = signed_in(env)
    body = env["client"].get("/compliance/controls", headers=headers)
    assert body.status_code == 200, body.text
    controls = {c["id"]: c for c in body.json()["controls"]}
    assert all(c["status"] in registry.STATUSES and c["reason"] for c in controls.values())
    # Fresh: nothing set up yet, so these are gaps, not "met".
    for cid in ("auth.two_step", "auth.sign_in_notice", "ir.incident_report", "ai.inventory", "ai.gateway_in_use", "backup.schedule", "data.residency"):
        assert controls[cid]["status"] == registry.GAP, cid
    # Built-in behaviour proven by a self-test with this tenant's settings.
    assert controls["ai.local_detection"]["status"] == registry.MET
    assert controls["dlp.payment_cards"]["status"] == registry.MET
    assert controls["injection.detection"]["status"] == registry.MET
    assert controls["ai.approval_policy"]["status"] == registry.MET
    # Coverage from the threat registry's tags.
    assert controls["detect.coverage:owasp_llm:LLM01"]["status"] == registry.MET
    assert controls["detect.coverage:owasp_llm:LLM09"]["status"] == registry.GAP
    assert controls["detect.coverage:mitre_atlas:AML.T0051"]["status"] == registry.MET
    assert all(c["status"] == registry.GAP for c in controls.values() if c["planned"])
    assert "owasp-llm-top10" in controls["detect.coverage:owasp_llm:LLM01"]["packs"]


# --- Statuses follow the settings ------------------------------------------------------------------------------------------


def test_statuses_change_when_settings_change(env):
    headers = signed_in(env)
    client = env["client"]
    desc = client.get("/compliance/packs/desc-isr", headers=headers).json()
    assert requirement(desc, "AC-01")["status"] == "partly" and requirement(desc, "AC-05")["status"] == "gap"
    assert requirement(desc, "LG-02")["status"] == "met"
    dpdp = client.get("/compliance/packs/dpdp-india", headers=headers).json()
    assert requirement(dpdp, "R.6(1)(e)")["status"] == "partly"  # connector activity is kept 180 days, not a year
    pci = client.get("/compliance/packs/pci-dss", headers=headers).json()
    assert requirement(pci, "3.4.1")["status"] == "met"

    # The sign-in baseline, a notice and two-step sign-in.
    saved = client.put("/auth/sign-in-settings", json={"passwordRule": dict(minLength=12, classes=3, history=5, maxAgeDays=90), "sessionIdleMinutes": 15, "banner": "Authorised use only.", "twoStepRequired": True}, headers=headers)
    assert saved.status_code == 200, saved.text
    desc = client.get("/compliance/packs/desc-isr", headers=headers).json()
    assert all(requirement(desc, r)["status"] == "met" for r in ("AC-01", "AC-02", "AC-04", "AC-05"))
    # Logs kept a year.
    assert client.put("/compliance/settings", json={"activityRetentionDays": 400, "connectorRetentionDays": 365}, headers=headers).status_code == 200
    dpdp = client.get("/compliance/packs/dpdp-india", headers=headers).json()
    assert requirement(dpdp, "R.6(1)(e)")["status"] in ("met", "partly")
    assert next(c for c in requirement(dpdp, "R.6(1)(e)")["controls"] if c["id"] == "log.retention_year")["status"] == "met"

    # Card-number detection off: PCI 3.4.1 becomes a gap; prompt injection off: OWASP LLM01 is no longer met.
    off = client.put("/detection/settings", json={"dlp": {"categories": {"credit_card": False}}, "prompt_injection": {"enabled": False}}, headers=headers)
    assert off.status_code == 200, off.text
    pci = client.get("/compliance/packs/pci-dss", headers=headers).json()
    assert requirement(pci, "3.4.1")["status"] == "gap"
    owasp = client.get("/compliance/packs/owasp-llm-top10", headers=headers).json()
    assert requirement(owasp, "LLM01")["status"] in ("partly", "gap")
    assert next(c for c in requirement(owasp, "LLM01")["controls"] if c["id"] == "injection.detection")["status"] == "not_configured"
    # The DESC view (the legacy table) reads the same registry.
    legacy = {c["id"]: c for c in client.get("/compliance", headers=headers).json()["controls"]}
    assert legacy["AI-01"]["status"] in ("partial", "action")


# --- Records (attestations) --------------------------------------------------------------------------------------------------


def test_recording_an_organisational_requirement_and_not_applicable(env):
    headers = signed_in(env)
    client = env["client"]
    pack = client.get("/compliance/packs/iso-42001", headers=headers).json()
    assert requirement(pack, "A.2.2")["status"] == "yours" and pack["mayRecord"] is True
    path = "/compliance/packs/iso-42001/requirements/A.2.2/record"
    assert client.put(path, json={"status": "in_place"}, headers=headers).status_code == 400
    assert client.put(path, json={"status": "done", "note": "x"}, headers=headers).status_code == 400
    assert client.put("/compliance/packs/iso-42001/requirements/NOPE/record", json={"status": "in_place", "note": "x"}, headers=headers).status_code == 404
    saved = client.put(path, json={"status": "in_place", "note": "AI policy approved by the board, 2026-10-01.", "reference": "DMS POL-AI-001"}, headers=headers)
    assert saved.status_code == 200, saved.text
    item = requirement(saved.json(), "A.2.2")
    assert item["status"] == "attested" and item["attestation"]["reference"] == "DMS POL-AI-001" and item["attestation"]["current"]
    # Not applicable applies to a mapped requirement too.
    na = client.put("/compliance/packs/pci-dss/requirements/3.3.1/record", json={"status": "not_applicable", "note": "We never handle card data."}, headers=headers)
    assert requirement(na.json(), "3.3.1")["status"] == "not_applicable"
    removed = client.delete(path, headers=headers)
    assert removed.status_code == 200 and requirement(removed.json(), "A.2.2")["status"] == "yours"
    assert client.delete(path, headers=headers).status_code == 404
    with env["db"]() as db:
        actions = [r.action for r in db.scalars(select(AuditLog).where(AuditLog.action.startswith("compliance.pack."))).all()]
    assert actions.count("compliance.pack.recorded") == 2 and actions.count("compliance.pack.record_removed") == 1


def test_permissions(env):
    viewer = signed_in(env, "viewer@example.test", role="viewer")
    client = env["client"]
    for path in ("/compliance/packs", "/compliance/packs/pci-dss", "/compliance/controls", "/compliance/packs/pci-dss/evidence"):
        assert client.get(path, headers=viewer).status_code == 403, path
    auditor = signed_in(env, "auditor@example.test", role="auditor")
    listing = client.get("/compliance/packs", headers=auditor)
    assert listing.status_code == 200 and listing.json()["mayRecord"] is False and listing.json()["mayExport"] is True
    assert client.put("/compliance/packs/iso-42001/requirements/A.2.2/record", json={"status": "in_place", "note": "x"}, headers=auditor).status_code == 403
    assert client.get("/compliance/packs/nope", headers=auditor).status_code == 404
    assert client.get("/compliance/packs/pci-dss/evidence", headers=auditor).status_code == 200


def test_the_overview_lists_every_pack_with_counts(env):
    headers = signed_in(env)
    body = env["client"].get("/compliance/packs", headers=headers).json()
    assert {p["id"] for p in body["packs"]} == EXPECTED_PACKS
    assert "do not by themselves make" in body["disclaimer"]
    for item in body["packs"]:
        counts = item["counts"]
        assert counts["total"] == sum(counts[s] for s in compliance_packs.REQUIREMENT_STATUSES)
        assert counts["total"] == sum(v["total"] for v in counts["byApplicability"].values())


# --- The signed evidence bundle ----------------------------------------------------------------------------------------------


def test_evidence_bundle_is_signed_and_checks_with_the_offline_tool(env):
    headers = signed_in(env)
    client = env["client"]
    client.put("/detection/settings", json={"dlp": {"custom_dictionaries": [{"name": "Deal names", "category": "mna", "terms": ["Project Falcon"]}]}}, headers=headers)
    client.post("/auth/login", json={"email": "owner@example.test", "password": "wrong-password-here"})
    client.put("/compliance/packs/pci-dss/requirements/12.6.1/record", json={"status": "in_place", "note": "Annual training, LMS course SEC-101."}, headers=headers)
    response = client.get("/compliance/packs/pci-dss/evidence", headers=headers)
    assert response.status_code == 200, response.text
    assert response.headers["content-type"] == "application/zip"
    assert response.headers["content-disposition"].startswith('attachment; filename="hawk-pci-dss-evidence-')
    archive = zipfile.ZipFile(io.BytesIO(response.content))
    names = set(archive.namelist())
    assert names == {"manifest.json", "pack.json", "status.json", "controls.json", "audit-entries.jsonl", "settings.json", "records.json", "README.txt"}
    manifest = json.loads(archive.read("manifest.json"))
    assert manifest["format"] == "hawk-evidence-manifest/v1" and manifest["pack"]["id"] == "pci-dss"
    assert set(manifest["files"]) == names - {"manifest.json"}
    everything = b"".join(archive.read(n) for n in names).decode("utf-8")
    for secret in (PASSWORD, "wrong-password-here", "hashed_password", "Project Falcon", "mfa_secret", "fingerprint_salt"):
        assert secret not in everything, secret
    entries = [json.loads(line) for line in archive.read("audit-entries.jsonl").decode().splitlines()]
    assert entries and all("seq" in e and "mac" in e for e in entries)
    assert any(e["action"].startswith("auth.") for e in entries)
    records = json.loads(archive.read("records.json"))
    assert records["attestations"][0]["requirement"] == "12.6.1"

    # Offline: unzip, save the public keys, run tools/verify_evidence.py.
    folder = env["tmp"] / "bundle"
    archive.extractall(folder)
    keys = env["tmp"] / "keys.json"
    keys.write_text(json.dumps(evidence_signing.service().public_keys()), encoding="utf-8")
    tool = verifier()
    assert tool.main([str(folder / "manifest.json"), "--keys", str(keys)]) == 0
    # A changed file is caught.
    (folder / "status.json").write_text("{}", encoding="utf-8")
    assert tool.main([str(folder / "manifest.json"), "--keys", str(keys)]) == 1
    with env["db"]() as db:
        logged = db.scalar(select(AuditLog).where(AuditLog.action == "compliance.pack.evidence"))
        assert logged is not None and logged.payload["pack"] == "pci-dss"


def test_evidence_window_and_unknown_pack(env):
    headers = signed_in(env)
    client = env["client"]
    assert client.get("/compliance/packs/pci-dss/evidence?from=2026-02-01&to=2026-01-01", headers=headers).status_code == 400
    assert client.get("/compliance/packs/pci-dss/evidence?from=2020-01-01&to=2026-01-01", headers=headers).status_code == 400
    assert client.get("/compliance/packs/pci-dss/evidence?from=nonsense", headers=headers).status_code == 400
    assert client.get("/compliance/packs/nope/evidence", headers=headers).status_code == 404
    assert pack_evidence.MAX_WINDOW_DAYS == 366


def test_evidence_records_keep_other_peoples_acceptances_out(env):
    """A person's own acceptance recorded without a tenant (every one before migration 0103) can be anyone's on this
    installation: it stays out of a tenant's evidence. The organisation's acceptance for the installation stays in."""

    import datetime as dt

    from app.db.models.access import TermsAcceptance

    signed_in(env)
    with env["db"]() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == "acme"))
        other = Tenant(name="Other", slug="other", is_active=True)
        db.add(other)
        db.flush()
        common = {"version": "2.0", "text_hash": "0" * 64, "via": "page"}
        db.add_all([
            TermsAcceptance(scope="organisation", email="cio@acme.example", full_name="Installation Owner", tenant_id=None, ip="10.0.0.1", **common),
            TermsAcceptance(scope="user", email="legacy@other.example", full_name="Legacy Other", tenant_id=None, ip="10.9.9.9", **common),
            TermsAcceptance(scope="user", email="ana@other.example", full_name="Ana Other", tenant_id=other.id, ip="10.9.9.8", **common),
            TermsAcceptance(scope="user", email="bo@acme.example", full_name="Bo Acme", tenant_id=tenant.id, ip="10.0.0.2", **common),
        ])
        db.commit()
        now = dt.datetime.now(dt.timezone.utc)
        out = pack_evidence.records(db, tenant.id, since=now - dt.timedelta(days=1), until=now, pack_id="pci-dss")
    emails = sorted(a["email"] for a in out["termsAcceptances"])
    assert emails == ["bo@acme.example", "cio@acme.example"]
