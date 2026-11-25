"""Software integrity, ported from CxMissionZero's test/integrity.test.js: the file list of each image, the Sigstore
verifier (a real GitHub attestation against the real trust root, and every way a made-up one can be wrong), the states
of the running copy (genuine, files changed, not signed by the release workflow, not confirmed yet, development copy),
the CLI the updater runs, and activation's tie to a release (never the test key)."""

from __future__ import annotations

import copy
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from app.cli import integrity as integrity_cli
from app.services import activation_service
from app.services.integrity import manifest as m
from app.services.integrity.service import IntegrityService, is_release, outbound_url_problem
from app.services.integrity.sigstore import root_from_inclusion_proof, verify_bundle
from tests.sigstore_helpers import make_bundle, make_world

FIXTURES = Path(__file__).parent / "fixtures"
REPO_ROOT = Path(__file__).resolve().parents[3]
DIGEST = hashlib.sha256(b"the file list").hexdigest()
API_COVER = {"trees": ["apps/api", "packages"], "files": ["VERSION", "TERMS.md"]}


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def make_image(root: Path, *, version: str = "0.2.0", commit: str = "abc123def4567890", repository: str = "cxsmtp/hk") -> dict:
    (root / "apps" / "api" / "app").mkdir(parents=True)
    (root / "apps" / "api" / "app" / "main.py").write_text("print('hawk')\n")
    (root / "apps" / "api" / "app" / "version.py").write_text("V = 1\n")
    (root / "packages" / "sdk").mkdir(parents=True)
    (root / "packages" / "sdk" / "index.js").write_text("export {}\n")
    (root / "VERSION").write_text(f"{version}\n")
    (root / "TERMS.md").write_text("Terms\n")
    (root / "README.md").write_text("not covered\n")
    manifest = m.build_manifest(root, image="api", version=version, commit=commit, repository=repository, **API_COVER)
    (root / m.MANIFEST_FILE).write_text(m.manifest_text(manifest))
    return manifest


# ---- The file list ---------------------------------------------------------------------------------------------------


def test_the_file_list_covers_what_the_image_ships_not_what_is_written_beside_it(tmp_path):
    manifest = make_image(tmp_path)
    assert sorted(manifest["files"]) == ["TERMS.md", "VERSION", "apps/api/app/main.py", "apps/api/app/version.py", "packages/sdk/index.js"]
    assert manifest["cover"] == {"trees": ["apps/api", "packages"], "files": ["VERSION", "TERMS.md"], "skipDirs": []}
    assert manifest["image"] == "api" and manifest["version"] == "0.2.0" and manifest["format"] == 1
    # Deterministic: the same files give the same bytes (the amd64 and arm64 lists are compared byte for byte).
    again = m.build_manifest(tmp_path, image="api", version="0.2.0", commit="abc123def4567890", repository="cxsmtp/hk", **API_COVER)
    assert m.manifest_text(again) == (tmp_path / m.MANIFEST_FILE).read_text()
    # Links are never followed, and a skipped folder is not walked.
    (tmp_path / "apps" / "api" / "link.py").symlink_to(tmp_path / "README.md")
    (tmp_path / "apps" / "api" / "node_modules").mkdir()
    (tmp_path / "apps" / "api" / "node_modules" / "x.js").write_text("x")
    assert "apps/api/link.py" not in m.covered_files(tmp_path, trees=["apps/api"], files=[], skip_dirs=["apps/api/node_modules"])
    assert "apps/api/node_modules/x.js" not in m.covered_files(tmp_path, trees=["apps/api"], files=[], skip_dirs=["apps/api/node_modules"])


def test_a_changed_missing_or_added_file_is_found_and_the_rest_still_match(tmp_path):
    manifest = make_image(tmp_path)
    assert m.compare_files(tmp_path, manifest)["ok"] is True
    (tmp_path / "apps" / "api" / "app" / "main.py").write_text("print('changed')\n")
    (tmp_path / "packages" / "sdk" / "index.js").unlink()
    (tmp_path / "apps" / "api" / "app" / "backdoor.py").write_text("evil\n")
    result = m.compare_files(tmp_path, manifest)
    assert result == {"ok": False, "checked": 5, "changed": ["apps/api/app/main.py"], "missing": ["packages/sdk/index.js"], "extra": ["apps/api/app/backdoor.py"]}
    # A listed name that would leave the folder is never read: it counts as changed.
    bad = {**manifest, "files": {"../../etc/passwd": "0" * 64}}
    assert "../../etc/passwd" in m.compare_files(tmp_path, bad)["changed"]


def test_the_digest_is_of_the_exact_bytes_on_disk(tmp_path):
    make_image(tmp_path)
    read = m.read_manifest(tmp_path)
    assert read["digest"] == hashlib.sha256((tmp_path / m.MANIFEST_FILE).read_bytes()).hexdigest()
    (tmp_path / m.MANIFEST_FILE).write_text("{not json")
    assert m.read_manifest(tmp_path)["error"] == "The file list cannot be read."
    (tmp_path / m.MANIFEST_FILE).write_text(json.dumps({"format": 9, "files": {}}))
    assert m.read_manifest(tmp_path)["error"] == "The file list is not in a known format."
    (tmp_path / m.MANIFEST_FILE).unlink()
    assert m.read_manifest(tmp_path) is None


def test_the_image_build_script_writes_and_checks_the_same_list(tmp_path):
    make_image(tmp_path)
    (tmp_path / m.MANIFEST_FILE).unlink()
    script = REPO_ROOT / "infra" / "scripts" / "integrity.py"
    args = ["write", str(tmp_path), "--image", "api", "--commit", "abc", "--repository", "cxsmtp/hk", "--tree", "apps/api", "--tree", "packages", "--file", "VERSION", "--file", "TERMS.md"]
    written = subprocess.run([sys.executable, str(script), *args], capture_output=True, text=True)
    assert written.returncode == 0, written.stderr
    assert "5 files listed" in written.stdout
    assert json.loads((tmp_path / m.MANIFEST_FILE).read_text())["version"] == "0.2.0"  # from VERSION when not given
    assert subprocess.run([sys.executable, str(script), "check", str(tmp_path)], capture_output=True).returncode == 0
    (tmp_path / "VERSION").write_text("9.9.9\n")
    checked = subprocess.run([sys.executable, str(script), "check", str(tmp_path)], capture_output=True, text=True)
    assert checked.returncode == 1 and "Changed (1): VERSION" in checked.stdout


# ---- The attestation ------------------------------------------------------------------------------------------------


def test_a_good_attestation_passes_with_a_signed_timestamp_or_an_inclusion_proof():
    world = make_world()
    for proof in ("set", "checkpoint"):
        r = verify_bundle(make_bundle(world, DIGEST, proof=proof), digest=DIGEST, trusted_root=world.trusted_root, repository="cxsmtp/hk")
        assert r["ok"] is True, f"{proof}: {r.get('reason')}"
        assert r["ref"] == "refs/heads/main" and r["commit"] == "0123456789abcdef0123456789abcdef01234567"
        assert re.search(r"actions/runs/1", r["run"]) and r["logIndex"] == 7
    tag = make_world(ref="refs/tags/v0.2.0")
    assert verify_bundle(make_bundle(tag, DIGEST), digest=DIGEST, trusted_root=tag.trusted_root, repository="CXSMTP/HK")["ok"] is True, "a version tag, and the repository in any case"


def test_each_way_an_attestation_can_be_wrong_is_refused_with_the_reason():
    world = make_world()

    def check(bundle, **opts):
        return verify_bundle(bundle, **{"digest": DIGEST, "trusted_root": world.trusted_root, "repository": "cxsmtp/hk", **opts})["reason"]

    good = make_bundle(world, DIGEST)
    assert re.search("about other files", check(good, digest=sha256("other files")))
    assert re.search(r"not https://github.com/someone/else", check(good, repository="someone/else"))
    other = ec.generate_private_key(ec.SECP256R1())
    assert re.search("signature does not match", check(make_bundle(world, DIGEST, sign_key=other)))
    assert re.search("signature does not match", check(make_bundle(world, DIGEST, tamper={"payload": DIGEST}))), "a payload swapped after signing"
    assert re.search("did not confirm", check(make_bundle(world, DIGEST, tamper={"log_key": other})))
    assert re.search("did not confirm", check(make_bundle(world, DIGEST, proof="checkpoint", tamper={"log_key": other})))
    assert re.search("record is not of this signature", check(make_bundle(world, DIGEST, tamper={"logged_payload": b"else"})))
    assert re.search("not valid when it was used", check(make_bundle(world, DIGEST, integrated_time=int(world.now) + 3600)))
    stranger = make_world()
    assert re.search("not issued by Sigstore", check(make_bundle(stranger, DIGEST))), "a certificate from another authority"
    pr = make_world(ref="refs/pull/9/merge")
    assert re.search("not main or a version tag", verify_bundle(make_bundle(pr, DIGEST), digest=DIGEST, trusted_root=pr.trusted_root, repository="cxsmtp/hk")["reason"])
    # The wrong workflow: CxMissionZero's container.yml, or any other, is not Hawk AI's release.yml.
    for workflow in (".github/workflows/container.yml", ".github/workflows/api-tests.yml"):
        elsewhere = make_world(workflow=workflow)
        assert re.search(r"not \.github/workflows/release\.yml", verify_bundle(make_bundle(elsewhere, DIGEST), digest=DIGEST, trusted_root=elsewhere.trusted_root, repository="cxsmtp/hk")["reason"])
    not_actions = make_world(issuer="https://accounts.example")
    assert re.search("not signed by GitHub Actions", verify_bundle(make_bundle(not_actions, DIGEST), digest=DIGEST, trusted_root=not_actions.trusted_root, repository="cxsmtp/hk")["reason"])
    assert re.search("not a Sigstore bundle", check({"mediaType": "text/plain"}))
    assert re.search("could not be read", check({"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "verificationMaterial": {"certificate": {"rawBytes": "AAAA"}}}))


def test_inclusion_proofs_follow_rfc_9162():
    leaf = bytes([1]) * 32
    assert root_from_inclusion_proof(0, 1, leaf, []) == leaf
    assert root_from_inclusion_proof(2, 2, leaf, []) is None
    other = bytes([2]) * 32
    assert root_from_inclusion_proof(1, 2, leaf, [other]) == hashlib.sha256(b"\x01" + other + leaf).digest()


def test_a_real_github_attestation_checks_out_against_the_real_sigstore_root():
    """CxMissionZero's real attestation (a pull request build of its repository): the port reads Sigstore's real
    certificates, log key and signatures exactly as the original."""

    bundle = json.loads((FIXTURES / "github-attestation.json").read_text())
    trusted = json.loads((REPO_ROOT / "apps" / "api" / "app" / "services" / "integrity" / "trusted_root.json").read_text())
    digest = "2fde5591d80d5b4bf75440f30ce1aecdc6daedf1c81c14b1cb3715633bdadf34"
    options = {"digest": digest, "trusted_root": trusted, "repository": "cxsmtp/CxDetectionDateBaseReminder", "workflow": ".github/workflows/container.yml", "refs": re.compile(r"^refs/pull/\d+/merge$")}
    r = verify_bundle(bundle, **options)
    assert r["ok"] is True, r.get("reason")
    assert r["commit"] == "b31c365780681249137b7decd42bf477858748bb"
    for drop in ("inclusionPromise", "inclusionProof"):
        one = copy.deepcopy(bundle)
        del one["verificationMaterial"]["tlogEntries"][0][drop]
        assert verify_bundle(one, **options)["ok"] is True, f"without {drop}"
    # As shipped, only main and version tags count, and only Hawk AI's release workflow of Hawk AI's repository.
    assert re.search("not main or a version tag", verify_bundle(bundle, **{**options, "refs": re.compile(r"^refs/(heads/(main|master)|tags/v[\w.-]+)$")})["reason"])
    assert re.search("release.yml", verify_bundle(bundle, **{**options, "workflow": ".github/workflows/release.yml"})["reason"])
    assert re.search("not https://github.com/cxsmtp/hk", verify_bundle(bundle, **{**options, "repository": "cxsmtp/hk"})["reason"])
    assert re.search("about other files", verify_bundle(bundle, **{**options, "digest": sha256("x")})["reason"])
    tampered = copy.deepcopy(bundle)
    tampered["verificationMaterial"]["tlogEntries"][0]["integratedTime"] = str(int(tampered["verificationMaterial"]["tlogEntries"][0]["integratedTime"]) + 1)
    del tampered["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
    assert verify_bundle(tampered, **options)["ok"] is False, "a log time changed after the fact"


# ---- The running copy --------------------------------------------------------------------------------------------------


def github(bundles_by_digest: dict[str, list], *, reachable: bool = True, calls: list | None = None) -> httpx.Client:
    def handler(request: httpx.Request) -> httpx.Response:
        if calls is not None:
            calls.append(str(request.url))
        if not reachable:
            raise httpx.ConnectError("no route to host", request=request)
        match = re.search(r"/attestations/sha256:([0-9a-f]{64})$", request.url.path)
        if request.url.path.startswith("/bundles/"):
            return httpx.Response(200, json=bundles_by_digest.get("bundle-url"))
        bundles = bundles_by_digest.get(match.group(1)) if match else None
        if not bundles:
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(200, json={"attestations": bundles})

    return httpx.Client(transport=httpx.MockTransport(handler), base_url="https://api.github.com")


def service_for(tmp_path, world, client, records=None) -> IntegrityService:
    return IntegrityService(app_dir=tmp_path / "image", data_dir=tmp_path / "data", repository="cxsmtp/hk", client=client, trusted=world.trusted_root, record=(lambda **kw: records.append(kw)) if records is not None else (lambda **kw: None), api="https://api.github.com", token="")


def test_the_running_copy_genuine_tampered_unconfirmed_not_genuine_unsigned_and_a_confirmed_origin_is_kept(tmp_path):
    world = make_world()
    (tmp_path / "image").mkdir()
    make_image(tmp_path / "image")
    digest = m.read_manifest(tmp_path / "image")["digest"]
    records: list[dict] = []
    calls: list[str] = []

    # Genuine: every file matches, and GitHub's attestation of the list is the release workflow's.
    service = service_for(tmp_path, world, github({digest: [{"bundle": make_bundle(world, digest)}]}, calls=calls), records)
    r = service.check(reason="start")
    assert r["state"] == "genuine", r["summary"]
    assert r["summary"].startswith("Genuine: all 5 files are exactly what cxsmtp/hk's release workflow built from main (commit 0123456789ab)")
    assert r["files"]["ok"] and r["origin"]["ok"] and r["version"] == "0.2.0" and r["image"] == "api"
    assert records[-1]["outcome"] == "info" and records[-1]["details"]["state"] == "genuine"
    assert service.last["state"] == "genuine" and service.notice() is None
    # The answer is kept: offline, it is still known after a restart.
    offline = service_for(tmp_path, world, github({}, reachable=False))
    assert offline.check()["state"] == "genuine" and offline.verify_origin(digest)["cached"] is True

    # Files changed: found with no network, recorded once as a failure, and owners and admins are alerted.
    (tmp_path / "image" / "apps" / "api" / "app" / "main.py").write_text("print('changed')\n")
    records.clear()
    r = service.check()
    assert r["state"] == "tampered" and r["summary"] == "1 file differs from what the release workflow built (1 changed, 0 missing, 0 added)."
    assert records and records[0]["outcome"] == "failure" and records[0]["details"]["state"] == "tampered"
    assert service.notice() == {"state": "tampered", "summary": r["summary"]}
    records.clear()
    service.check()
    assert records == [], "the same state is recorded once, not at every check"
    (tmp_path / "image" / "apps" / "api" / "app" / "main.py").write_text("print('hawk')\n")


def test_not_signed_by_the_release_workflow_and_not_confirmed_yet(tmp_path):
    world = make_world()
    (tmp_path / "image").mkdir()
    make_image(tmp_path / "image")
    digest = m.read_manifest(tmp_path / "image")["digest"]
    # Signed, but by another workflow: not genuine, with the reason.
    other = make_world(workflow=".github/workflows/api-tests.yml")
    other.trusted_root = world.trusted_root
    elsewhere = service_for(tmp_path, other, github({digest: [{"bundle": make_bundle(make_world(workflow=".github/workflows/api-tests.yml"), digest)}]}))
    r = elsewhere.check()
    assert r["state"] == "not-genuine" and "the list is not signed by cxsmtp/hk's release workflow" in r["summary"]
    assert elsewhere.notice()["state"] == "not-genuine"
    # No attestation at all.
    (tmp_path / "data" / "integrity-last.json").unlink()
    none = service_for(tmp_path, world, github({}))
    assert none.check()["state"] == "not-genuine"
    assert "GitHub has no build attestation for this file list" in none.last["summary"]
    # GitHub unreachable: the files match, who built it is not confirmed yet (no alert).
    unreachable = service_for(tmp_path, world, github({}, reachable=False))
    r = unreachable.check()
    assert r["state"] == "unconfirmed" and r["summary"].startswith("All 5 files match their list; who built it is not confirmed yet: GitHub could not be reached")
    assert unreachable.notice() is None
    # The bundle can come from the address GitHub gives (https only, never a metadata address).
    by_url = service_for(tmp_path, world, github({digest: [{"bundle_url": "https://api.github.com/bundles/1"}], "bundle-url": make_bundle(world, digest)}))
    assert by_url.verify_origin(digest)["ok"] is True
    assert outbound_url_problem("http://169.254.169.254/latest") == "is not https"
    assert outbound_url_problem("https://169.254.169.254/latest") == "is a link-local or cloud metadata address"
    assert outbound_url_problem("http://127.0.0.1:9/x", allow_loopback_http=True) == ""


def test_a_development_copy_has_no_file_list(tmp_path):
    (tmp_path / "image").mkdir()
    service = IntegrityService(app_dir=tmp_path / "image", data_dir=tmp_path / "data", record=lambda **kw: None, client=github({}))
    r = service.check()
    assert r["state"] == "unsigned" and r["summary"].startswith("No signed file list")
    assert service.notice() is None and is_release(tmp_path / "image") is False


def test_the_cli_the_updater_runs_says_files_and_origin_by_its_exit_code(tmp_path, capsys):
    world = make_world()
    (tmp_path / "image").mkdir()
    make_image(tmp_path / "image")
    digest = m.read_manifest(tmp_path / "image")["digest"]
    root = str(tmp_path / "image")
    assert integrity_cli.main(["check", root]) == 0
    assert "Every file matches the list." in capsys.readouterr().out
    good = service_for(tmp_path, world, github({digest: [{"bundle": make_bundle(world, digest)}]}))
    assert integrity_cli.main(["check", root, "--origin"], service=good) == 0
    assert "Signed by https://github.com/cxsmtp/hk/.github/workflows/release.yml@refs/heads/main" in capsys.readouterr().out
    (tmp_path / "data" / "integrity-origin.json").unlink()
    assert integrity_cli.main(["check", root, "--origin"], service=service_for(tmp_path, world, github({}, reachable=False))) == 4
    assert integrity_cli.main(["check", root, "--origin"], service=service_for(tmp_path, world, github({}))) == 3
    (tmp_path / "image" / "TERMS.md").write_text("changed")
    assert integrity_cli.main(["check", root, "--origin"]) == 1
    assert "Changed (1): TERMS.md" in capsys.readouterr().out
    assert integrity_cli.main(["check", str(tmp_path)]) == 2


def test_a_release_never_trusts_the_activation_test_key(tmp_path, monkeypatch):
    monkeypatch.setenv(activation_service.TEST_KEY_ENV, "MCowBQYDK2VwAyEAtestkeytestkeytestkeytestkeytestkeytestkey=")
    monkeypatch.setattr(activation_service, "_production", lambda: False)
    monkeypatch.setenv("HAWK_INTEGRITY_ROOT", str(tmp_path))
    assert len(activation_service.trusted_keys()) == len(activation_service.ISSUER_KEYS) + 1, "a development copy under pytest"
    (tmp_path / "integrity.json").write_text("{}")
    assert activation_service.trusted_keys() == list(activation_service.ISSUER_KEYS), "a release image"


@pytest.mark.parametrize("hours, expected", [("", 6.0), ("2", 2.0), ("0", 0.1), ("x", 6.0)])
def test_the_check_runs_every_six_hours_by_default(monkeypatch, hours, expected):
    from app.jobs import update_schedule as update_jobs
    from app.services.integrity.service import check_hours

    monkeypatch.setenv("INTEGRITY_CHECK_HOURS", hours)
    assert check_hours() == expected
    entry = update_jobs.beat_entries()["software-integrity"]
    assert entry["schedule"].total_seconds() == expected * 3600 and entry["task"] == "app.jobs.update_jobs.check_integrity"
