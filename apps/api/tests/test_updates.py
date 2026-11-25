"""Settings → Updates, ported from CxMissionZero's test/updates.test.js and test/companion.test.js (the server's side):
the registry (its sign-in, multi-arch index, digests checked, tags listed), the check (every version listed, tags
already read never read again, latest and stable, a registry whose files cannot be read), installing through the
updater (only Hawk AI's own signed images, one at a time), auto-update's schedule (off by default; its hour; at most
every 55 minutes outside it; never a version that failed; the stable channel), and the routes."""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import re
from pathlib import Path

import httpx
import pytest

from app.services.integrity.service import IntegrityService
from app.services.updates import companion
from app.services.updates.registry import ImageRegistry, UpdateError, parse_image
from app.services.updates.service import UpdateService, compare_versions
from tests.sigstore_helpers import make_bundle, make_world

UTC = dt.timezone.utc


def sha(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode()).hexdigest()


class FakeGhcr:
    """ghcr.io as the registry API answers: an anonymous token, tags, image indexes, configs; and api.github.com's
    attestations for each image's digest."""

    def __init__(self, world=None, *, versions=("0.1.0", "0.2.0", "0.3.0"), latest="0.3.0", stable=None, blob_status=200, signed=True, reachable=True):
        self.calls: list[str] = []
        self.world = world
        self.blob_status = blob_status
        self.signed = signed
        self.reachable = reachable
        self.tags = {kind: {} for kind in ("api", "web", "proxy")}
        self.blobs: dict[str, bytes] = {}
        self.manifests: dict[str, dict] = {}
        for version in versions:
            self.publish(version)
        for channel, version in (("latest", latest), ("stable", stable)):
            if version:
                for kind in self.tags:
                    self.tags[kind][channel] = self.tags[kind][version]

    def publish(self, version: str) -> None:
        for kind in self.tags:
            config = json.dumps({"created": f"2026-11-{int(version.split('.')[1]) + 1:02d}T10:00:00Z", "config": {"Labels": {"org.opencontainers.image.version": version, "org.opencontainers.image.revision": f"{version.replace('.', '')}abcdef1234567"}}}).encode()
            config_digest = "sha256:" + hashlib.sha256(config).hexdigest()
            self.blobs[config_digest] = config
            platform_manifest = json.dumps({"schemaVersion": 2, "config": {"digest": config_digest}, "layers": []}).encode()
            platform_digest = "sha256:" + hashlib.sha256(platform_manifest).hexdigest()
            self.manifests[platform_digest] = {"body": platform_manifest}
            index = json.dumps({"schemaVersion": 2, "manifests": [{"digest": platform_digest, "platform": {"os": "linux", "architecture": "amd64"}}, {"digest": sha(f"arm-{kind}-{version}"), "platform": {"os": "linux", "architecture": "arm64"}}]}).encode()
            index_digest = "sha256:" + hashlib.sha256(index).hexdigest()
            self.manifests[index_digest] = {"body": index}
            self.tags[kind][version] = index_digest

    def digest(self, kind: str, tag: str) -> str:
        return self.tags[kind][tag]

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        self.calls.append(url)
        if request.url.host == "api.github.com":
            if not self.reachable:
                raise httpx.ConnectError("unreachable", request=request)
            digest = url.rsplit("sha256:", 1)[1]
            if not self.signed:
                return httpx.Response(404, json={})
            return httpx.Response(200, json={"attestations": [{"bundle": make_bundle(self.world, digest)}]})
        if request.url.host == "pkg-containers.githubusercontent.com":
            if self.blob_status != 200:
                return httpx.Response(self.blob_status)
            return httpx.Response(200, content=self.blobs[request.url.path.rsplit("/", 1)[1]])
        if request.url.host == "ghcr.io" and request.url.path == "/token":
            return httpx.Response(200, json={"token": "anon"})
        if request.headers.get("authorization") != "Bearer anon":
            return httpx.Response(401, headers={"www-authenticate": 'Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:cxsmtp/hk-api:pull"'})
        match = re.match(r"^/v2/cxsmtp/hk-(api|web|proxy)/(tags/list|manifests/(.+)|blobs/(.+))$", request.url.path)
        assert match, url
        kind = match.group(1)
        if match.group(2) == "tags/list":
            return httpx.Response(200, json={"name": f"cxsmtp/hk-{kind}", "tags": [*self.tags[kind], "sha-1234567", "buildcache"]})
        if match.group(3):
            ref = match.group(3)
            digest = self.tags[kind].get(ref, ref)
            found = self.manifests.get(digest)
            if not found:
                return httpx.Response(404, json={"errors": [{"code": "MANIFEST_UNKNOWN"}]})
            return httpx.Response(200, content=found["body"], headers={"docker-content-digest": digest})
        # ghcr.io sends image files to another host, as the real one does.
        return httpx.Response(307, headers={"location": f"https://pkg-containers.githubusercontent.com/ghcr1/blobs/{match.group(4)}"})

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))


def heartbeat(updater: Path, *, manages=True, at=None, error=""):
    companion.write_json(updater / "updater.json", {"at": (at or dt.datetime.now(UTC)).isoformat().replace("+00:00", "Z"), "project": "hawk", "image": "ghcr.io/cxsmtp/hk", "engine": "ok", "engineError": error, "services": {}, "manages": manages})


def make_service(tmp_path, ghcr: FakeGhcr, *, running="0.2.0", offline=False, zone=UTC, records=None) -> UpdateService:
    client = ghcr.client()
    world = ghcr.world
    integrity = IntegrityService(app_dir=tmp_path / "image", data_dir=tmp_path / "data", repository="cxsmtp/hk", client=client, trusted=world.trusted_root if world else {}, record=lambda **kw: None, api="https://api.github.com", token="")
    return UpdateService(
        running_version=running,
        image="ghcr.io/cxsmtp/hk",
        token="",
        client=client,
        arch="amd64",
        data_dir=tmp_path / "data",
        updater=tmp_path / "updater",
        integrity=integrity,
        record=(lambda **kw: records.append(kw)) if records is not None else (lambda **kw: None),
        offline=offline,
        zone=zone,
    )


# ---- The registry ------------------------------------------------------------------------------------------------------


def test_image_names_need_a_registry_and_tags_and_digests_are_ignored():
    assert parse_image("ghcr.io/cxsmtp/hk") == ("ghcr.io", "cxsmtp/hk")
    assert parse_image("ghcr.io/CXSMTP/hk-api:0.2.0") == ("ghcr.io", "cxsmtp/hk-api")
    assert parse_image(f"localhost:5000/hk-api@{sha('x')}") == ("localhost:5000", "hk-api")
    for bad in ("hk-api", "cxsmtp/hk", "ghcr.io/", "ghcr.io/Bad Name"):
        with pytest.raises(UpdateError):
            parse_image(bad)
    with pytest.raises(UpdateError, match="metadata"):
        ImageRegistry("169.254.169.254/x/y")
    assert compare_versions("0.10.0", "0.9.9") == 1 and compare_versions("1.0.0", "1.0.0") == 0 and compare_versions("0.1.0", "0.1.1") == -1


def test_the_registry_signs_in_reads_the_index_for_this_architecture_and_checks_digests():
    ghcr = FakeGhcr()
    registry = ImageRegistry("ghcr.io/cxsmtp/hk-api", client=ghcr.client(), arch="amd64")
    assert "0.3.0" in registry.tags() and "buildcache" in registry.tags()
    found = registry.manifest("0.2.0")
    assert found["digest"] == ghcr.digest("api", "0.2.0") and found["platform"] != found["digest"]
    image = registry.image("0.2.0")
    assert image["labels"]["org.opencontainers.image.version"] == "0.2.0" and image["created"].startswith("2026-11-03")
    assert any(c.startswith("https://ghcr.io/token?") and "scope=repository%3Acxsmtp%2Fhk-api%3Apull" in c for c in ghcr.calls)
    with pytest.raises(UpdateError, match="no build for linux/riscv64"):
        ImageRegistry("ghcr.io/cxsmtp/hk-api", client=ghcr.client(), arch="riscv64").manifest("0.2.0")
    # A blob that does not match its digest is refused.
    some = next(iter(ghcr.blobs))
    ghcr.blobs[some] = b"something else"
    with pytest.raises(UpdateError, match="did not match its digest"):
        registry.blob(some)
    with pytest.raises(UpdateError, match="not found"):
        registry.manifest("9.9.9")


# ---- The check ----------------------------------------------------------------------------------------------------------


def test_the_check_lists_every_version_newest_first_with_latest_and_stable_and_reads_a_tag_once(tmp_path):
    ghcr = FakeGhcr(make_world(), versions=[f"0.{n}.0" for n in range(1, 16)], latest="0.15.0", stable="0.12.0")
    service = make_service(tmp_path, ghcr, running="0.12.0")
    status = service.check()
    versions = status["lastCheck"]["versions"]
    assert [v["version"] for v in versions][:4] == ["0.15.0", "0.14.0", "0.13.0", "0.12.0"] and len(versions) == 15, "no cap, newest first"
    assert versions[0]["tags"] == ["0.15.0", "latest"] and versions[0]["label"] == "HK-00.15.00"
    assert versions[3]["tags"] == ["0.12.0", "stable"]
    assert versions[0]["revision"] == "0150abcdef12" and versions[0]["created"].startswith("2026-11-16")
    assert status["updateAvailable"] is True and status["latest"]["version"] == "0.15.0"
    assert not any("sha-1234567" in c or "buildcache" in c for c in ghcr.calls), "only version tags, latest and stable are read"
    # The next check reads only the tags list, latest and stable: version tags never move.
    ghcr.calls.clear()
    service.check()
    manifest_reads = [c for c in ghcr.calls if "/manifests/" in c]
    assert sorted(c.rsplit("/", 1)[1] for c in manifest_reads) == ["latest", "stable"]
    # A new release is read once.
    ghcr.publish("0.16.0")
    ghcr.calls.clear()
    status = service.check()
    assert status["lastCheck"]["versions"][0]["version"] == "0.16.0"
    assert sum("/manifests/0.16.0" in c for c in ghcr.calls) == 1
    # Following stable: the latest the page offers is the promoted one.
    service.save_settings({"channel": "stable"})
    assert service.status()["latest"]["version"] == "0.12.0" and service.status()["updateAvailable"] is False


def test_the_check_lists_versions_even_when_image_files_cannot_be_read_and_says_why(tmp_path):
    ghcr = FakeGhcr(make_world(), blob_status=403)
    status = make_service(tmp_path, ghcr).check()
    assert [v["version"] for v in status["lastCheck"]["versions"]] == ["0.3.0", "0.2.0", "0.1.0"]
    assert "pkg-containers.githubusercontent.com answered 403" in status["lastCheck"]["warning"]
    assert "allow pkg-containers.githubusercontent.com over HTTPS" in status["lastCheck"]["warning"]
    empty = FakeGhcr(make_world(), versions=[], latest=None)
    status = make_service(tmp_path / "other", empty).check()
    assert status["lastCheck"]["versions"] == [] and status["lastCheck"]["error"] == "No published version could be read.", "tags, but no version tag"


def test_a_registry_that_cannot_be_reached_keeps_what_was_known(tmp_path):
    ghcr = FakeGhcr(make_world())
    service = make_service(tmp_path, ghcr)
    service.check()

    def down(request):
        raise httpx.ConnectError("refused", request=request)

    service.client = httpx.Client(transport=httpx.MockTransport(down))
    status = service.check()
    assert status["lastCheck"]["error"].startswith("Could not reach ghcr.io") and len(status["lastCheck"]["versions"]) == 3


# ---- Installing through the updater ---------------------------------------------------------------------------------------


def test_install_asks_the_updater_for_every_image_by_digest_once_signed(tmp_path):
    ghcr = FakeGhcr(make_world())
    records: list[dict] = []
    service = make_service(tmp_path, ghcr, records=records)
    updater = tmp_path / "updater"
    with pytest.raises(UpdateError, match="Choose a version"):
        service.install("../../etc")
    with pytest.raises(UpdateError, match="The updater is not running"):
        service.install("0.3.0")
    heartbeat(updater, manages=False, error='"hawk-api-1" runs hawk-api:local, not ghcr.io/cxsmtp/hk-api.')
    with pytest.raises(UpdateError, match="cannot update this installation: \"hawk-api-1\" runs hawk-api:local"):
        service.install("0.3.0")
    heartbeat(updater)
    result = service.install("latest", by="owner@example.com")
    request = json.loads((updater / "request.json").read_text())
    assert result["version"] == "0.3.0" and request["version"] == "0.3.0" and request["action"] == "update" and request["tag"] == "latest"
    assert request["images"] == {kind: f"ghcr.io/cxsmtp/hk-{kind}@{ghcr.digest(kind, '0.3.0')}" for kind in ("api", "web", "proxy")}
    assert request["by"] == "owner@example.com" and request["automatic"] is False
    assert records[-1]["outcome"] == "changed" and "Update to HK-00.03.00 asked of the updater (latest; every image signed by the release workflow)" in records[-1]["reason"]
    attested = [c for c in ghcr.calls if "api.github.com/repos/cxsmtp/hk/attestations/sha256:" in c]
    assert len(attested) == 3, "each image's digest is checked"
    # One at a time.
    with pytest.raises(UpdateError, match="already under way"):
        service.install("0.1.0")
    # Going back is the same click; the record says so.
    (updater / "request.json").unlink()
    service.install("0.1.0", by="owner@example.com")
    assert "Update back to HK-00.01.00" in records[-1]["reason"]


def test_install_refuses_an_unsigned_image_unless_github_is_unreachable_and_offline_is_allowed(tmp_path):
    heartbeat(tmp_path / "updater")
    unsigned = make_service(tmp_path, FakeGhcr(make_world(), signed=False))
    with pytest.raises(UpdateError, match=r"HK-00.03.00 \(api\) is not confirmed as built by the release workflow: GitHub has no build attestation") as refused:
        unsigned.install("0.3.0")
    assert refused.value.status == 422
    elsewhere = FakeGhcr(make_world(workflow=".github/workflows/api-tests.yml"))
    elsewhere_service = make_service(tmp_path / "w", elsewhere)
    elsewhere_service.integrity._trusted = make_world().trusted_root  # another authority altogether
    heartbeat(tmp_path / "w" / "updater")
    with pytest.raises(UpdateError, match="not confirmed as built by the release workflow"):
        elsewhere_service.install("0.3.0")
    offline = FakeGhcr(make_world(), reachable=False)
    with pytest.raises(UpdateError, match="set INTEGRITY_OFFLINE=allow"):
        make_service(tmp_path, offline).install("0.3.0")
    assert not (tmp_path / "updater" / "request.json").exists()
    make_service(tmp_path, offline, offline=True).install("0.3.0")
    assert json.loads((tmp_path / "updater" / "request.json").read_text())["version"] == "0.3.0"


def test_the_updater_is_there_only_while_its_heartbeat_is_fresh(tmp_path):
    updater = tmp_path / "updater"
    assert companion.companion_state(updater)["connected"] is False
    heartbeat(updater, at=dt.datetime.now(UTC) - dt.timedelta(seconds=120))
    assert companion.companion_state(updater)["connected"] is False
    heartbeat(updater)
    state = companion.companion_state(updater)
    assert state["connected"] and state["manages"] and not state["busy"]
    companion.write_json(updater / "status.json", {"state": "running", "startedAt": dt.datetime.now(UTC).isoformat()})
    assert companion.companion_state(updater)["busy"] is True
    companion.write_json(updater / "status.json", {"state": "rolled-back"})
    assert companion.companion_state(updater)["busy"] is False
    assert companion.acknowledge_start("0.3.0", updater) is True
    assert json.loads((updater / "ack.json").read_text())["version"] == "0.3.0"
    assert companion.acknowledge_start("0.3.0", Path("/proc/hawk-cannot-write")) is False


# ---- Auto-update --------------------------------------------------------------------------------------------------------


def rolled_back(updater: Path, version: str):
    companion.write_json(updater / "status.json", {"state": "rolled-back"})
    with (updater / "events.jsonl").open("a") as file:
        file.write(json.dumps({"at": "2026-11-25T09:00:00Z", "type": "rolled-back", "to": version, "from": "0.2.0", "automatic": True}) + "\n")


def test_auto_update_is_off_by_default_installs_a_newer_release_in_its_hour_and_never_one_that_failed(tmp_path):
    ghcr = FakeGhcr(make_world())
    updater = tmp_path / "updater"
    heartbeat(updater)
    service = make_service(tmp_path, ghcr)
    now = dt.datetime(2026, 11, 25, 2, 10, tzinfo=UTC)
    assert service.settings() == {"auto": False, "windowHour": None, "channel": "latest", "lastAutoAt": None, "lastAutoResult": ""}
    assert service.auto_update(now) is None and not (updater / "request.json").exists() and ghcr.calls == []
    # On, in any hour: the newest release.
    service.save_settings({"auto": True})
    assert service.auto_update(now)["version"] == "0.3.0"
    assert json.loads((updater / "request.json").read_text())["automatic"] is True
    assert service.settings()["lastAutoResult"] == "Installing HK-00.03.00"
    # While that runs, nothing else.
    assert service.auto_update(now + dt.timedelta(minutes=15)) is None
    # It failed to start: never installed automatically again; the next newer one is.
    (updater / "request.json").unlink()
    rolled_back(updater, "0.3.0")
    assert service.auto_update(now + dt.timedelta(minutes=30)) is None
    assert service.settings()["lastAutoResult"] == "Up to date"
    ghcr.publish("0.4.0")
    assert service.auto_update(now + dt.timedelta(minutes=45))["version"] == "0.4.0"
    # Never an older one.
    (updater / "request.json").unlink()
    newest = make_service(tmp_path, ghcr, running="0.4.0")
    assert newest.auto_update(now + dt.timedelta(hours=1)) is None and newest.settings()["lastAutoResult"] == "Up to date"


def test_auto_update_waits_for_its_hour_says_what_is_waiting_and_looks_at_most_every_55_minutes(tmp_path):
    ghcr = FakeGhcr(make_world())
    updater = tmp_path / "updater"
    heartbeat(updater)
    dubai = dt.timezone(dt.timedelta(hours=4), "Asia/Dubai")
    service = make_service(tmp_path, ghcr, zone=dubai)
    service.save_settings({"auto": True, "windowHour": 2})
    at = dt.datetime(2026, 11, 25, 10, 0, tzinfo=UTC)  # 14:00 in Dubai
    assert service.auto_update(at) is None
    assert service.settings()["lastAutoResult"] == "HK-00.03.00 is ready: it installs at 02:00 (Asia/Dubai), or use Update now"
    ghcr.calls.clear()
    assert service.auto_update(at + dt.timedelta(minutes=15)) is None and ghcr.calls == [], "outside its hour, not again within 55 minutes"
    assert service.auto_update(at + dt.timedelta(minutes=56)) is None and ghcr.calls, "but once an hour, so the page says what is waiting"
    # 02:10 in Dubai is 22:10 UTC the day before.
    assert service.auto_update(dt.datetime(2026, 11, 25, 22, 10, tzinfo=UTC))["version"] == "0.3.0"


def test_auto_update_says_why_it_cannot_install(tmp_path):
    ghcr = FakeGhcr(make_world(), blob_status=403)
    service = make_service(tmp_path, ghcr)
    service.save_settings({"auto": True})
    now = dt.datetime(2026, 11, 25, 2, 0, tzinfo=UTC)
    service.auto_update(now)
    assert service.settings()["lastAutoResult"] == "Cannot install: the updater is not running. Update with deploy/install.sh"
    heartbeat(tmp_path / "updater", manages=False, error="Not Hawk AI's published images (ghcr.io/cxsmtp/hk-…): api runs hawk-api:local.")
    service.auto_update(now + dt.timedelta(minutes=15))
    assert "api runs hawk-api:local" in service.settings()["lastAutoResult"]
    heartbeat(tmp_path / "updater")
    service.auto_update(now + dt.timedelta(minutes=30))
    assert service.settings()["lastAutoResult"].startswith("HK-00.03.00 is published, but this server cannot download it: pkg-containers.githubusercontent.com answered 403")
    # A job that never finished does not block it for ever.
    companion.write_json(tmp_path / "updater" / "status.json", {"state": "running", "startedAt": (dt.datetime.now(UTC) - dt.timedelta(minutes=10)).isoformat()})
    ghcr.blob_status = 200
    service.last_check = None
    assert service.auto_update(now + dt.timedelta(minutes=40)) is None, "an update under way"
    companion.write_json(tmp_path / "updater" / "status.json", {"state": "running", "startedAt": (dt.datetime.now(UTC) - dt.timedelta(hours=2)).isoformat()})
    ghcr.blob_status = 200
    service.last_check = None
    assert service.auto_update(now + dt.timedelta(minutes=45))["version"] == "0.3.0"


def test_auto_update_on_the_stable_channel_installs_only_the_promoted_release(tmp_path):
    ghcr = FakeGhcr(make_world(), stable="0.2.0")
    heartbeat(tmp_path / "updater")
    service = make_service(tmp_path, ghcr, running="0.2.0")
    service.save_settings({"auto": True, "channel": "stable"})
    now = dt.datetime(2026, 11, 25, 2, 0, tzinfo=UTC)
    assert service.auto_update(now) is None and service.settings()["lastAutoResult"] == "Up to date with stable"
    for kind in ghcr.tags:
        ghcr.tags[kind]["stable"] = ghcr.tags[kind]["0.3.0"]
    assert service.auto_update(now + dt.timedelta(minutes=15))["version"] == "0.3.0"


def test_auto_update_first_looks_a_minute_after_start_then_every_15_minutes(monkeypatch):
    from app.jobs import update_schedule

    monkeypatch.delenv("AUTO_UPDATE_EVERY_SECONDS", raising=False)
    entry = update_schedule.beat_entries()["auto-update"]
    assert entry["task"] == "app.jobs.update_jobs.auto_update"
    assert entry["schedule"].run_every == dt.timedelta(seconds=900) and entry["schedule"].first_after == dt.timedelta(seconds=60)
    monkeypatch.setenv("AUTO_UPDATE_EVERY_SECONDS", "10")
    assert update_schedule.beat_entries()["auto-update"]["schedule"].run_every == dt.timedelta(seconds=60), "at least a minute apart"


# ---- The routes ---------------------------------------------------------------------------------------------------------


@pytest.fixture()
def api(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker

    from app.api.routers import updates as updates_router
    from app.db.session import Base, get_db
    from app.main import app

    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'u.sqlite3'}", connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr("app.db.session.SessionLocal", session_factory)
    ghcr = FakeGhcr(make_world())
    records: list[dict] = []
    monkeypatch.setitem(updates_router._factory, "updates", lambda: make_service(tmp_path, ghcr, records=records))
    monkeypatch.setitem(updates_router._factory, "integrity", lambda: make_service(tmp_path, ghcr).integrity)
    client = TestClient(app, base_url="https://localhost")
    try:
        yield {"client": client, "db": session_factory, "ghcr": ghcr, "records": records, "tmp": tmp_path}
    finally:
        client.close()
        app.dependency_overrides.clear()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def owner(client, email: str = "owner@example.com") -> dict[str, str]:
    response = client.post("/auth/register", json={"email": email, "password": "Password123!", "full_name": "Update Owner"})
    assert response.status_code == 200, response.text
    body = response.json()
    return {"Authorization": f"Bearer {body['access_token']}", "X-Tenant-ID": body["tenants"][0]["id"]}


def test_the_update_routes_are_for_owners_and_admins_only(api):
    from sqlalchemy import select

    from app.db.models.user import User, UserTenantRole

    c = api["client"]
    headers = owner(c)
    viewer = owner(c, "viewer@example.com")
    with api["db"]() as db:
        user = db.scalar(select(User).where(User.email == "viewer@example.com"))
        db.add(UserTenantRole(user_id=user.id, tenant_id=headers["X-Tenant-ID"], role="viewer"))
        db.commit()
    as_viewer = {**viewer, "X-Tenant-ID": headers["X-Tenant-ID"]}
    for method, path in [("get", "/updates"), ("post", "/updates/check"), ("post", "/updates/install"), ("put", "/updates/settings"), ("post", "/updates/restart"), ("get", "/updates/report"), ("get", "/integrity"), ("post", "/integrity/check")]:
        assert getattr(c, method)(path, headers=as_viewer).status_code == 403, path
    assert c.get("/updates").status_code in (401, 403)
    assert c.get("/integrity/notice", headers=as_viewer).json() == {"notice": None}
    assert c.get("/integrity/notice", headers=headers).json() == {"notice": None}


def test_the_page_checks_installs_saves_settings_and_reports(api):
    c = api["client"]
    headers = owner(c)
    status = c.get("/updates", headers=headers).json()
    assert status["running"] == {"version": "0.2.0", "label": "HK-00.02.00"} and status["lastCheck"] is None
    assert status["integrity"]["state"] == "checking" and status["settings"]["auto"] is False
    checked = c.post("/updates/check", headers=headers).json()
    assert [v["version"] for v in checked["lastCheck"]["versions"]] == ["0.3.0", "0.2.0", "0.1.0"] and checked["updateAvailable"] is True
    refused = c.post("/updates/install", json={"version": "0.3.0"}, headers=headers)
    assert refused.status_code == 409 and "The updater is not running" in refused.json()["error"]
    assert "refused" in api["records"][-1]["reason"]
    heartbeat(api["tmp"] / "updater")
    made = c.post("/updates/install", json={"version": "0.3.0"}, headers=headers)
    assert made.status_code == 202, made.text
    assert made.json()["to"] == "0.3.0" and made.json()["updater"]["busy"] is True
    assert c.put("/updates/settings", json={"windowHour": 24}, headers=headers).status_code == 400
    assert c.put("/updates/settings", json={"channel": "beta"}, headers=headers).status_code == 400
    saved = c.put("/updates/settings", json={"auto": True, "windowHour": "3"}, headers=headers).json()["settings"]
    assert saved["auto"] is True and saved["windowHour"] == 3 and saved["channel"] == "latest"
    saved = c.put("/updates/settings", json={"channel": "stable"}, headers=headers).json()["settings"]
    assert saved == {**saved, "auto": True, "windowHour": 3, "channel": "stable"}, "one field at a time, as the page saves"
    assert api["records"][-1]["reason"] == "Auto-update on, at 03:00, following stable."
    report = c.get("/updates/report", headers=headers)
    assert report.status_code == 200 and "attachment" in report.headers["content-disposition"]
    body = report.json()
    assert body["packageVersion"] == "0.2.0" and body["settings"]["channel"] == "stable" and "token" not in json.dumps(body).lower()
    (api["tmp"] / "updater" / "request.json").unlink()
    assert c.post("/updates/restart", headers=headers).json() == {"restarting": True}
    assert json.loads((api["tmp"] / "updater" / "request.json").read_text())["action"] == "restart"
    checked = c.post("/integrity/check", headers=headers).json()
    assert checked["state"] == "unsigned" and checked["repository"] == "cxsmtp/hk"
