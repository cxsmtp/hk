"""Evidence signing (app/services/evidence_signing.py, app/api/routers/evidence_signing.py, tools/verify_evidence.py):
asymmetric signatures on the evidence Hawk AI hands out, checkable offline with the public key alone.

- sign and check (bytes, JSON documents), tampering found, the key id is the key's fingerprint, the key file is 0600;
- rotation (and a change of backend) keeps every old public key, so what was signed before still checks; the old
  private key is destroyed;
- the offline verifier: an embedded signature, a detached one (file and header), a signed manifest and its files, a PEM;
- the backends: which one the settings choose, and what is said when one is incomplete; AWS KMS (Signature Version 4,
  the AWS test vector), Azure Key Vault and Google Cloud KMS requests over a mocked HTTPS;
- the routes and who may use them; the audit log export and the auditor export carry signatures;
- a backup carries the keys (never the lock).
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import os
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.core.config import Settings, settings
from app.core.security import get_password_hash
from app.db.models.audit import AuditLog
from app.db.models.tenant import Tenant
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import audit_chain, backup_archive, evidence_signing as es

REPO = Path(__file__).resolve().parents[3]
VERIFIER = REPO / "tools" / "verify_evidence.py"
PASSWORD = "correct-Horse-2026"


def local(directory: Path, **values: Any) -> es.EvidenceSigning:
    return es.EvidenceSigning(directory=directory, settings_obj=SimpleNamespace(evidence_signing_backend="local", **values), env={})


def keys_by_kid(signing: es.EvidenceSigning) -> dict[str, dict[str, Any]]:
    return signing.known_keys()


# ---------------------------------------------------------------------------------------------------------------------
# Signing and checking
# ---------------------------------------------------------------------------------------------------------------------


def test_a_document_and_bytes_sign_and_check_and_any_change_is_found(tmp_path):
    signing = local(tmp_path)
    document = signing.sign_document({"b": [1, 2], "a": "é", "when": dt.datetime(2026, 1, 2, tzinfo=dt.timezone.utc)}, artifact="test.doc")
    envelope = document[es.SIGNATURE_FIELD]
    assert envelope["format"] == es.FORMAT and envelope["alg"] == "EdDSA" and envelope["artifact"] == "test.doc"
    assert document["when"] == "2026-01-02 00:00:00+00:00"  # as a reader of the JSON sees it
    assert signing.verify_document(document)["valid"] is True
    # Key order does not matter (canonical JSON); a reloaded copy checks too.
    assert signing.verify_document(json.loads(json.dumps(dict(reversed(list(document.items()))))))["valid"] is True

    changed = {**document, "a": "e"}
    result = signing.verify_document(changed)
    assert result["valid"] is False and "changed after it was signed" in result["reason"]
    forged = {**document, es.SIGNATURE_FIELD: {**envelope, "signed_at": "2020-01-01T00:00:00Z"}}
    assert signing.verify_document(forged)["reason"] == "The signature does not verify."
    assert signing.verify_document({"a": 1})["valid"] is False

    data = b"seq,mac\n1,abc\n"
    detached = signing.sign_bytes(data, artifact="audit.csv")
    assert detached["digest"] == hashlib.sha256(data).hexdigest()
    assert signing.verify(detached, data=data)["valid"] is True
    assert signing.verify(detached, data=data + b"2,def\n")["valid"] is False
    # The header form is the same envelope.
    assert es.decode_header(es.encode_header(detached)) == detached


def test_the_key_id_is_the_fingerprint_the_file_is_private_and_holds_no_secret_in_the_published_list(tmp_path):
    signing = local(tmp_path)
    status = signing.status()
    kid = status["active"]["kid"]
    entry = keys_by_kid(signing)[kid]
    public = serialization.load_pem_public_key(entry["public_key_pem"].encode())
    assert kid == hashlib.sha256(public.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)).hexdigest()
    assert status["backend"] == "local" and status["active"]["alg"] == "EdDSA" and status["error"] == ""
    assert stat.S_IMODE(os.stat(tmp_path / es.KEYRING_FILE).st_mode) == 0o600
    listing = signing.public_keys()
    assert listing["format"] == es.KEYS_FORMAT
    assert [k["kid"] for k in listing["keys"]] == [kid] and listing["keys"][0]["status"] == "active"
    assert listing["keys"][0]["kty"] == "OKP" and listing["keys"][0]["crv"] == "Ed25519"
    assert "PRIVATE" not in json.dumps(listing) and "PRIVATE" not in json.dumps(status)
    # The same key from a second process (a fresh service on the same folder).
    assert local(tmp_path).status()["active"]["kid"] == kid


def test_a_damaged_key_file_is_never_replaced_by_a_new_key(tmp_path):
    (tmp_path / es.KEYRING_FILE).write_text("{not json")
    with pytest.raises(es.EvidenceSigningError, match="damaged"):
        local(tmp_path).sign_bytes(b"x", artifact="x")
    assert (tmp_path / es.KEYRING_FILE).read_text() == "{not json"


def test_rotation_keeps_old_public_keys_so_earlier_evidence_still_checks(tmp_path):
    signing = local(tmp_path)
    before = signing.sign_document({"n": 1}, artifact="before")
    first = before[es.SIGNATURE_FIELD]["kid"]
    result = signing.rotate()
    assert result["rotated"] is True and result["previous"] == first and result["active"] != first
    after = signing.sign_document({"n": 2}, artifact="after")
    assert after[es.SIGNATURE_FIELD]["kid"] == result["active"]
    old_check = signing.verify_document(before)
    assert old_check["valid"] is True and old_check["key_status"] == "retired"
    assert signing.verify_document(after)["key_status"] == "active"
    keys = keys_by_kid(signing)
    assert keys[first]["retired_at"] and "private_key_pem" not in keys[first]  # the old private key is destroyed
    listing = {k["kid"]: k["status"] for k in signing.public_keys()["keys"]}
    assert listing == {first: "retired", result["active"]: "active"}
    status = signing.status()
    assert [k["kid"] for k in status["retired"]] == [first]


# ---------------------------------------------------------------------------------------------------------------------
# The offline verifier
# ---------------------------------------------------------------------------------------------------------------------


def run_verifier(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(VERIFIER), *args], capture_output=True, text=True, timeout=60)


def test_the_offline_verifier_needs_only_the_public_key(tmp_path):
    folder = tmp_path / "server"
    signing = local(folder)
    out = tmp_path / "auditor"
    out.mkdir()
    keys = out / "hawk-evidence-keys.json"
    document = signing.sign_document({"evidence": [1, 2, 3]}, artifact="pack")
    (out / "pack.json").write_text(json.dumps(document, indent=2))
    keys.write_text(json.dumps(signing.public_keys()))

    ok = run_verifier(str(out / "pack.json"), "--keys", str(keys))
    assert ok.returncode == 0, ok.stdout + ok.stderr
    assert "Valid." in ok.stdout
    tampered = {**document, "evidence": [1, 2, 4]}
    (out / "bad.json").write_text(json.dumps(tampered))
    bad = run_verifier(str(out / "bad.json"), "--keys", str(keys))
    assert bad.returncode == 1 and "NOT valid" in bad.stdout

    # A detached signature, as a .sig.json file and as the header's value; one public key as PEM.
    data = b'{"notice":"x"}\n{"seq":1}\n'
    (out / "audit.jsonl").write_bytes(data)
    envelope = signing.sign_bytes(data, artifact="audit_log.jsonl")
    (out / "audit.jsonl.sig.json").write_text(json.dumps(envelope))
    pem = out / "key.pem"
    pem.write_text(keys_by_kid(signing)[envelope["kid"]]["public_key_pem"])
    assert run_verifier(str(out / "audit.jsonl"), "--signature", str(out / "audit.jsonl.sig.json"), "--keys", str(pem)).returncode == 0
    assert run_verifier(str(out / "audit.jsonl"), "--signature", es.encode_header(envelope), "--keys", str(keys)).returncode == 0
    (out / "audit.jsonl").write_bytes(data + b'{"seq":2}\n')
    assert run_verifier(str(out / "audit.jsonl"), "--signature", str(out / "audit.jsonl.sig.json"), "--keys", str(keys)).returncode == 1

    # After a rotation, the published list still checks what was signed before; a key that is not given does not.
    signing.rotate()
    keys.write_text(json.dumps(signing.public_keys()))
    assert run_verifier(str(out / "pack.json"), "--keys", str(keys), "--json").returncode == 0
    other = local(tmp_path / "other")
    other.status()
    (out / "other.json").write_text(json.dumps(other.public_keys()))
    refused = run_verifier(str(out / "pack.json"), "--keys", str(out / "other.json"), "--json")
    assert refused.returncode == 1 and "not in the given keys" in json.loads(refused.stdout)["signature"]["reason"]
    # A key list cannot pass a key off under another key's id.
    listing = signing.public_keys()
    listing["keys"][0]["kid"] = "0" * 64
    (out / "lying.json").write_text(json.dumps(listing))
    assert run_verifier(str(out / "pack.json"), "--keys", str(out / "lying.json")).returncode == 2


def test_the_verifier_checks_a_signed_manifest_and_every_file_it_lists(tmp_path):
    signing = local(tmp_path / "server")
    export = tmp_path / "export"
    export.mkdir()
    (export / "a.csv").write_bytes(b"x,y\n1,2\n")
    (export / "b.pdf").write_bytes(b"%PDF-1.4 ...")
    manifest = signing.sign_document(
        {"format": "hawk-evidence-manifest/v1", "files": {n: {"path": p, "sha256": hashlib.sha256((export / p).read_bytes()).hexdigest()} for n, p in (("csv", "a.csv"), ("pdf", "b.pdf"))}},
        artifact="auditor.export_manifest",
    )
    (export / "manifest.json").write_text(json.dumps(manifest))
    keys = tmp_path / "keys.json"
    keys.write_text(json.dumps(signing.public_keys()))
    assert run_verifier(str(export / "manifest.json"), "--keys", str(keys)).returncode == 0
    (export / "b.pdf").write_bytes(b"%PDF-1.4 changed")
    failed = run_verifier(str(export / "manifest.json"), "--keys", str(keys), "--json")
    assert failed.returncode == 1
    report = json.loads(failed.stdout)
    assert report["signature"]["valid"] is True and report["files"]["pdf"]["valid"] is False and report["files"]["csv"]["valid"] is True


# ---------------------------------------------------------------------------------------------------------------------
# Backends and their settings
# ---------------------------------------------------------------------------------------------------------------------


def cfg(**values: Any) -> SimpleNamespace:
    return SimpleNamespace(**values)


def test_the_backend_is_chosen_by_the_settings_and_an_incomplete_one_says_what_is_missing():
    assert es.read_config(cfg(), {}).backend == "local"
    assert es.read_config(cfg(evidence_signing_backend="LOCAL"), {}).backend == "local"
    with pytest.raises(es.EvidenceSigningConfigError, match="must be one of"):
        es.read_config(cfg(evidence_signing_backend="hsm"), {})
    with pytest.raises(ValidationError):
        Settings(evidence_signing_backend="hsm")
    assert Settings(evidence_signing_backend=" AWS_KMS ").evidence_signing_backend == "aws_kms"

    with pytest.raises(es.EvidenceSigningConfigError, match="EVIDENCE_SIGNING_AWS_KMS_KEY_ID"):
        es.read_config(cfg(evidence_signing_backend="aws_kms"), {})
    with pytest.raises(es.EvidenceSigningConfigError, match="EVIDENCE_SIGNING_AWS_REGION"):
        es.read_config(cfg(evidence_signing_backend="aws_kms", evidence_signing_aws_kms_key_id="alias/hawk"), {})
    with pytest.raises(es.EvidenceSigningConfigError, match="needs credentials"):
        es.read_config(cfg(evidence_signing_backend="aws_kms", evidence_signing_aws_kms_key_id="arn:aws:kms:eu-west-1:111122223333:key/k"), {})
    aws = es.read_config(cfg(evidence_signing_backend="aws_kms", evidence_signing_aws_kms_key_id="arn:aws:kms:eu-west-1:111122223333:key/k"), {"AWS_ACCESS_KEY_ID": "AKID", "AWS_SECRET_ACCESS_KEY": "secret"})
    assert aws.value("region") == "eu-west-1" and aws.value("access_key") == "AKID"
    with pytest.raises(es.EvidenceSigningConfigError, match="https"):
        es.read_config(cfg(evidence_signing_backend="aws_kms", evidence_signing_aws_kms_key_id="alias/k", evidence_signing_aws_region="us-east-1", evidence_signing_aws_endpoint="http://kms.local", evidence_signing_aws_access_key_id="a", evidence_signing_aws_secret_access_key="b"), {})

    with pytest.raises(es.EvidenceSigningConfigError, match="EVIDENCE_SIGNING_AZURE_KEY_ID"):
        es.read_config(cfg(evidence_signing_backend="azure_kv"), {})
    with pytest.raises(es.EvidenceSigningConfigError, match="https"):
        es.read_config(cfg(evidence_signing_backend="azure_kv", evidence_signing_azure_key_id="http://v.vault.azure.net/keys/k"), {})
    with pytest.raises(es.EvidenceSigningConfigError, match="key's address"):
        es.read_config(cfg(evidence_signing_backend="azure_kv", evidence_signing_azure_key_id="https://v.vault.azure.net/secrets/k"), {})
    with pytest.raises(es.EvidenceSigningConfigError, match="CLIENT_SECRET"):
        es.read_config(cfg(evidence_signing_backend="azure_kv", evidence_signing_azure_key_id="https://v.vault.azure.net/keys/k"), {})

    with pytest.raises(es.EvidenceSigningConfigError, match="EVIDENCE_SIGNING_GCP_KEY_VERSION"):
        es.read_config(cfg(evidence_signing_backend="gcp_kms", evidence_signing_gcp_key_version="projects/p/keyRings/r/cryptoKeys/k"), {})
    with pytest.raises(es.EvidenceSigningConfigError, match="not valid JSON"):
        es.read_config(cfg(evidence_signing_backend="gcp_kms", evidence_signing_gcp_key_version="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1", evidence_signing_gcp_credentials_json="{"), {})


def test_a_misconfigured_backend_is_shown_on_the_page_and_refuses_to_sign(tmp_path):
    signing = es.EvidenceSigning(directory=tmp_path, settings_obj=cfg(evidence_signing_backend="aws_kms"), env={})
    status = signing.status()
    assert status["backend"] == "" and "EVIDENCE_SIGNING_AWS_KMS_KEY_ID" in status["error"] and status["active"] is None
    with pytest.raises(es.EvidenceSigningConfigError):
        signing.sign_bytes(b"x", artifact="x")
    assert signing.header_for(b"x", artifact="x") == {es.STATUS_HEADER: "unavailable"}


def test_sigv4_matches_the_aws_test_suite():
    # AWS Signature Version 4 test suite, "get-vanilla".
    headers = es.sigv4_headers(
        method="GET",
        url="https://example.amazonaws.com/",
        region="us-east-1",
        service="service",
        body=b"",
        access_key="AKIDEXAMPLE",
        secret_key="wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
        now=dt.datetime(2015, 8, 30, 12, 36, tzinfo=dt.timezone.utc),
    )
    assert headers["authorization"] == (
        "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, "
        "Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
    )


def mock_factory(handler):
    return lambda: httpx.Client(transport=httpx.MockTransport(handler))


def der_public(key: ec.EllipticCurvePrivateKey) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def test_aws_kms_requests_are_signed_v4_and_ask_for_an_ecdsa_digest_signature(tmp_path):
    kms_key = ec.generate_private_key(ec.SECP256R1())
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        body = json.loads(request.content)
        target = request.headers["x-amz-target"]
        if target == "TrentService.GetPublicKey":
            return httpx.Response(200, json={"KeyId": "arn:aws:kms:eu-west-1:111122223333:key/k1", "PublicKey": base64.b64encode(der_public(kms_key)).decode(), "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"})
        assert target == "TrentService.Sign"
        assert body["MessageType"] == "DIGEST" and body["SigningAlgorithm"] == "ECDSA_SHA_256" and body["KeyId"] == "alias/hawk"
        digest = base64.b64decode(body["Message"])
        assert len(digest) == 32
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

        return httpx.Response(200, json={"Signature": base64.b64encode(kms_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))).decode()})

    settings_obj = cfg(evidence_signing_backend="aws_kms", evidence_signing_aws_kms_key_id="alias/hawk", evidence_signing_aws_region="eu-west-1", evidence_signing_aws_access_key_id="AKIDTEST", evidence_signing_aws_secret_access_key="secret", evidence_signing_aws_session_token="session-token")
    signing = es.EvidenceSigning(directory=tmp_path, settings_obj=settings_obj, env={}, client_factory=mock_factory(handler))
    document = signing.sign_document({"n": 1}, artifact="pack")
    envelope = document[es.SIGNATURE_FIELD]
    assert envelope["alg"] == "ES256" and envelope["kid"] == hashlib.sha256(der_public(kms_key)).hexdigest()
    assert signing.verify_document(document)["valid"] is True
    for request in seen:
        assert str(request.url) == "https://kms.eu-west-1.amazonaws.com/"
        assert request.method == "POST" and request.headers["content-type"] == "application/x-amz-json-1.1"
        assert request.headers["x-amz-security-token"] == "session-token"
        auth = request.headers["authorization"]
        assert auth.startswith("AWS4-HMAC-SHA256 Credential=AKIDTEST/") and "/eu-west-1/kms/aws4_request" in auth
        assert "SignedHeaders=content-type;host;x-amz-date;x-amz-security-token;x-amz-target" in auth
        # The signature is the one SigV4 gives for exactly this request.
        expected = es.sigv4_headers(method="POST", url=str(request.url), region="eu-west-1", service="kms", body=request.content, access_key="AKIDTEST", secret_key="secret", session_token="session-token", extra={"content-type": "application/x-amz-json-1.1", "x-amz-target": request.headers["x-amz-target"]}, now=dt.datetime.strptime(request.headers["x-amz-date"], "%Y%m%dT%H%M%SZ").replace(tzinfo=dt.timezone.utc))
        assert auth == expected["authorization"]
    assert [r.headers["x-amz-target"] for r in seen] == ["TrentService.GetPublicKey", "TrentService.Sign"]
    # The public key is remembered: the next signature makes one call.
    seen.clear()
    signing.sign_bytes(b"x", artifact="x")
    assert [r.headers["x-amz-target"] for r in seen] == ["TrentService.Sign"]
    assert keys_by_kid(signing)[envelope["kid"]]["key_name"] == "arn:aws:kms:eu-west-1:111122223333:key/k1"


def test_aws_kms_errors_and_a_wrong_key_are_reported(tmp_path):
    settings_obj = cfg(evidence_signing_backend="aws_kms", evidence_signing_aws_kms_key_id="alias/hawk", evidence_signing_aws_region="eu-west-1", evidence_signing_aws_access_key_id="a", evidence_signing_aws_secret_access_key="b")

    def denied(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"__type": "AccessDeniedException", "message": "not allowed to kms:GetPublicKey"})

    with pytest.raises(es.EvidenceSigningError, match="AWS KMS answered 400: not allowed"):
        es.EvidenceSigning(directory=tmp_path, settings_obj=settings_obj, env={}, client_factory=mock_factory(denied)).sign_bytes(b"x", artifact="x")

    def rsa_key(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"KeyId": "k", "PublicKey": "", "KeySpec": "RSA_2048", "KeyUsage": "SIGN_VERIFY"})

    with pytest.raises(es.EvidenceSigningConfigError, match="ECC_NIST_P256"):
        es.EvidenceSigning(directory=tmp_path, settings_obj=settings_obj, env={}, client_factory=mock_factory(rsa_key)).sign_bytes(b"x", artifact="x")

    def unreachable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(es.EvidenceSigningError, match="could not be reached"):
        es.EvidenceSigning(directory=tmp_path, settings_obj=settings_obj, env={}, client_factory=mock_factory(unreachable)).sign_bytes(b"x", artifact="x")


def azure_settings(key_url: str = "https://hawk.vault.azure.net/keys/evidence") -> SimpleNamespace:
    return cfg(evidence_signing_backend="azure_kv", evidence_signing_azure_key_id=key_url, evidence_signing_azure_tenant_id="tenant-1", evidence_signing_azure_client_id="client-1", evidence_signing_azure_client_secret="client-secret")


def test_azure_key_vault_gets_a_token_reads_the_key_and_signs_es256_with_the_versioned_key(tmp_path):
    versions = {"v1": ec.generate_private_key(ec.SECP256R1()), "v2": ec.generate_private_key(ec.SECP256R1())}
    latest = {"version": "v1"}
    seen: list[httpx.Request] = []

    def jwk_of(key: ec.EllipticCurvePrivateKey) -> dict[str, str]:
        n = key.public_key().public_numbers()
        return {"x": es.b64url(n.x.to_bytes(32, "big")), "y": es.b64url(n.y.to_bytes(32, "big"))}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        url = str(request.url)
        if url == "https://login.microsoftonline.com/tenant-1/oauth2/v2.0/token":
            form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            assert form == {"grant_type": "client_credentials", "client_id": "client-1", "client_secret": "client-secret", "scope": "https%3A%2F%2Fvault.azure.net%2F.default"}
            return httpx.Response(200, json={"access_token": "token-1", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer token-1"
        if request.method == "GET":
            assert url == "https://hawk.vault.azure.net/keys/evidence?api-version=7.4"
            version = latest["version"]
            return httpx.Response(200, json={"key": {"kid": f"https://hawk.vault.azure.net/keys/evidence/{version}", "kty": "EC", "crv": "P-256", **jwk_of(versions[version])}})
        version = url.split("/keys/evidence/")[1].split("/sign")[0]
        assert url.endswith("/sign?api-version=7.4")
        body = json.loads(request.content)
        assert body["alg"] == "ES256"
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

        der = versions[version].sign(es.b64url_decode(body["value"]), ec.ECDSA(Prehashed(hashes.SHA256())))
        return httpx.Response(200, json={"kid": f"https://hawk.vault.azure.net/keys/evidence/{version}", "value": es.b64url(es.raw_ecdsa(der))})

    signing = es.EvidenceSigning(directory=tmp_path, settings_obj=azure_settings(), env={}, client_factory=mock_factory(handler))
    first = signing.sign_bytes(b"evidence", artifact="x")
    assert signing.verify(first, data=b"evidence")["valid"] is True
    assert any(str(r.url).startswith("https://hawk.vault.azure.net/keys/evidence/v1/sign") for r in seen)

    # A new version in Key Vault: Rotate picks it up, the old public key stays.
    latest["version"] = "v2"
    assert signing.rotate()["rotated"] is True
    second = signing.sign_bytes(b"evidence", artifact="x")
    assert second["kid"] != first["kid"]
    assert str(seen[-1].url).startswith("https://hawk.vault.azure.net/keys/evidence/v2/sign")
    assert signing.verify(first, data=b"evidence")["valid"] is True and signing.verify(second, data=b"evidence")["valid"] is True
    # Nothing new in Key Vault: nothing rotates.
    assert signing.rotate()["rotated"] is False


def test_google_cloud_kms_uses_a_service_account_assertion_and_asymmetric_sign(tmp_path):
    account_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    kms_key = ec.generate_private_key(ec.SECP256R1())
    name = "projects/p/locations/europe-west1/keyRings/hawk/cryptoKeys/evidence/cryptoKeyVersions/1"
    credentials = {"type": "service_account", "client_email": "hawk@p.iam.gserviceaccount.com", "private_key": account_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode(), "token_uri": "https://oauth2.googleapis.com/token"}
    seen: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        url = str(request.url)
        seen.append(url)
        if url == "https://oauth2.googleapis.com/token":
            form = dict(x.split("=", 1) for x in request.content.decode().split("&"))
            assert form["grant_type"] == "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer"
            header, claims, signature = form["assertion"].split(".")
            account_key.public_key().verify(es.b64url_decode(signature), f"{header}.{claims}".encode(), padding.PKCS1v15(), hashes.SHA256())
            decoded = json.loads(es.b64url_decode(claims))
            assert decoded["iss"] == "hawk@p.iam.gserviceaccount.com" and decoded["scope"] == es.GCP_SCOPE and decoded["aud"] == "https://oauth2.googleapis.com/token"
            return httpx.Response(200, json={"access_token": "gcp-token", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer gcp-token"
        if url == f"https://cloudkms.googleapis.com/v1/{name}/publicKey":
            pem = kms_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
            return httpx.Response(200, json={"pem": pem, "algorithm": "EC_SIGN_P256_SHA256", "name": name})
        assert url == f"https://cloudkms.googleapis.com/v1/{name}:asymmetricSign"
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

        digest = base64.b64decode(json.loads(request.content)["digest"]["sha256"])
        return httpx.Response(200, json={"signature": base64.b64encode(kms_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))).decode()})

    settings_obj = cfg(evidence_signing_backend="gcp_kms", evidence_signing_gcp_key_version=name, evidence_signing_gcp_credentials_json=json.dumps(credentials))
    signing = es.EvidenceSigning(directory=tmp_path, settings_obj=settings_obj, env={}, client_factory=mock_factory(handler))
    document = signing.sign_document({"x": 1}, artifact="pack")
    assert document[es.SIGNATURE_FIELD]["alg"] == "ES256" and signing.verify_document(document)["valid"] is True
    assert seen.count("https://oauth2.googleapis.com/token") == 1


def test_moving_from_the_local_key_to_a_cloud_key_retires_the_local_key_and_keeps_it_published(tmp_path):
    before = local(tmp_path).sign_document({"n": 1}, artifact="before")
    kms_key = ec.generate_private_key(ec.SECP256R1())

    def handler(request: httpx.Request) -> httpx.Response:
        if request.headers["x-amz-target"] == "TrentService.GetPublicKey":
            return httpx.Response(200, json={"KeyId": "k", "PublicKey": base64.b64encode(der_public(kms_key)).decode(), "KeySpec": "ECC_NIST_P256", "KeyUsage": "SIGN_VERIFY"})
        from cryptography.hazmat.primitives.asymmetric.utils import Prehashed

        digest = base64.b64decode(json.loads(request.content)["Message"])
        return httpx.Response(200, json={"Signature": base64.b64encode(kms_key.sign(digest, ec.ECDSA(Prehashed(hashes.SHA256())))).decode()})

    settings_obj = cfg(evidence_signing_backend="aws_kms", evidence_signing_aws_kms_key_id="k", evidence_signing_aws_region="us-east-1", evidence_signing_aws_access_key_id="a", evidence_signing_aws_secret_access_key="b")
    cloud = es.EvidenceSigning(directory=tmp_path, settings_obj=settings_obj, env={}, client_factory=mock_factory(handler))
    after = cloud.sign_document({"n": 2}, artifact="after")
    assert cloud.verify_document(before)["key_status"] == "retired" and cloud.verify_document(after)["key_status"] == "active"
    assert {k["backend"]: k["status"] for k in cloud.public_keys()["keys"]} == {"local": "retired", "aws_kms": "active"}
    assert not any("private_key_pem" in k for k in keys_by_kid(cloud).values())


# ---------------------------------------------------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------------------------------------------------


def test_a_backup_carries_the_signing_keys_but_not_the_lock_and_they_do_not_make_a_new_installation_look_old(tmp_path):
    from app.services.backup_key import earlier_state

    local(tmp_path).sign_bytes(b"x", artifact="x")
    assert (tmp_path / es.LOCK_FILE).exists()
    names = [name for name, _ in backup_archive.collect_data_files(tmp_path)]
    assert f"data/{es.KEYRING_FILE}" in names and f"data/{es.LOCK_FILE}" not in names
    assert earlier_state(data_dir=tmp_path) == ""


# ---------------------------------------------------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------------------------------------------------


@pytest.fixture()
def web(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(settings, "hawk_data_dir", str(data))
    monkeypatch.setattr(settings, "evidence_signing_backend", "local")
    monkeypatch.setenv("ARTIFACT_DIR", str(tmp_path / "artifacts"))
    audit_chain.forget_key()
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'signing.sqlite3'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(bind=engine)
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)

    def override_get_db():
        db = factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {"client": client, "db": factory, "data": data}
    finally:
        client.close()
        app.dependency_overrides.clear()
        audit_chain.forget_key()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def person(web, email: str, role: str) -> dict[str, str]:
    with web["db"]() as db:
        tenant = db.scalar(select(Tenant).where(Tenant.slug == "acme"))
        if tenant is None:
            tenant = Tenant(name="Acme", slug="acme", is_active=True)
            db.add(tenant)
            db.flush()
        user = User(email=email, full_name=role.title(), hashed_password=get_password_hash(PASSWORD), is_active=True)
        db.add(user)
        db.flush()
        db.add(UserTenantRole(user_id=user.id, tenant_id=tenant.id, role=role))
        db.commit()
    answer = web["client"].post("/auth/login", json={"email": email, "password": PASSWORD})
    assert answer.status_code == 200, answer.text
    tokens = answer.json()
    return {"Authorization": f"Bearer {tokens['access_token']}", "X-Tenant-ID": tokens["selected_tenant_id"]}


def test_routes_show_the_key_publish_public_keys_verify_and_only_admins_rotate(web):
    client = web["client"]
    admin = person(web, "admin@example.test", "admin")
    auditor = person(web, "auditor@example.test", "auditor")
    viewer = person(web, "viewer@example.test", "viewer")

    assert client.get("/evidence-signing").status_code == 401
    shown = client.get("/evidence-signing", headers=viewer)
    assert shown.status_code == 200, shown.text
    body = shown.json()
    assert body["backend"] == "local" and len(body["active"]["fingerprint"]) == 64 and body["can_rotate"] is False
    assert client.get("/evidence-signing", headers=admin).json()["can_rotate"] is True
    assert client.get("/evidence-signing/keys", headers=viewer).json()["keys"][0]["kid"] == body["active"]["kid"]

    # The public keys for anyone, no account.
    public = client.get(es.WELL_KNOWN_PATH)
    assert public.status_code == 200 and public.json()["keys"][0]["kid"] == body["active"]["kid"]
    assert "private" not in public.text.lower()

    # Verify: auditors (evidence.export), not viewers.
    signing = es.service()
    document = signing.sign_document({"pack": 1}, artifact="pack")
    assert client.post("/evidence-signing/verify", headers=viewer, json={"document": document}).status_code == 403
    checked = client.post("/evidence-signing/verify", headers=auditor, json={"document": document})
    assert checked.status_code == 200 and checked.json()["valid"] is True
    assert client.post("/evidence-signing/verify", headers=auditor, json={"document": {**document, "pack": 2}}).json()["valid"] is False
    data = b"a,b\n"
    header = es.encode_header(signing.sign_bytes(data, artifact="csv"))
    detached = client.post("/evidence-signing/verify", headers=auditor, json={"content_base64": base64.b64encode(data).decode(), "signature": header})
    assert detached.json()["valid"] is True
    assert client.post("/evidence-signing/verify", headers=auditor, json={"content_base64": base64.b64encode(b"x").decode(), "signature": header}).json()["valid"] is False
    assert client.post("/evidence-signing/verify", headers=auditor, json={}).status_code == 422
    assert client.post("/evidence-signing/verify", headers=auditor, json={"content_base64": "***", "signature": header}).status_code == 422

    # Rotate: owners and admins only; written to the audit log; the old key stays published.
    assert client.post("/evidence-signing/rotate", headers=auditor).status_code == 403
    assert client.post("/evidence-signing/rotate", headers=viewer).status_code == 403
    rotated = client.post("/evidence-signing/rotate", headers=admin)
    assert rotated.status_code == 200, rotated.text
    assert rotated.json()["rotated"] is True and rotated.json()["previous"] == body["active"]["kid"]
    statuses = {k["kid"]: k["status"] for k in client.get(es.WELL_KNOWN_PATH).json()["keys"]}
    assert statuses[body["active"]["kid"]] == "retired" and statuses[rotated.json()["active"]] == "active"
    assert client.post("/evidence-signing/verify", headers=auditor, json={"document": document}).json()["key_status"] == "retired"
    with web["db"]() as db:
        assert db.scalar(select(AuditLog).where(AuditLog.action == "evidence_signing.rotated")) is not None


def test_the_audit_log_export_carries_a_detached_signature(web):
    client = web["client"]
    admin = person(web, "owner@example.test", "owner")
    for fmt in ("csv", "jsonl"):
        answer = client.get(f"/audit/log/export.{fmt}", headers=admin)
        assert answer.status_code == 200, answer.text
        assert answer.headers[es.STATUS_HEADER] == "signed"
        envelope = es.decode_header(answer.headers[es.HEADER])
        assert envelope["artifact"] == f"audit_log.{fmt}"
        assert es.service().verify(envelope, data=answer.content)["valid"] is True
    for path in ("/activity/log/export.csv", "/connector-activity/export.csv"):
        answer = client.get(path, headers=admin)
        assert es.service().verify(es.decode_header(answer.headers[es.HEADER]), data=answer.content)["valid"] is True


def test_the_auditor_export_is_signed_by_a_manifest_and_each_download_carries_its_signature(web, tmp_path):
    client = web["client"]
    owner = person(web, "owner2@example.test", "owner")
    exported = client.post("/auditor/export", headers=owner, json={})
    assert exported.status_code == 200, exported.text
    body = exported.json()
    signature = body["artifacts"]["evidence_signature"]
    assert signature["alg"] == "EdDSA" and signature["format"] == es.FORMAT
    manifest = client.get(body["download_urls"]["signature_manifest"], headers=owner)
    assert manifest.status_code == 200
    document = manifest.json()
    assert document["format"] == "hawk-evidence-manifest/v1"
    assert es.service().verify_document(document)["valid"] is True
    assert set(document["files"]) == {"json", "csv", "evidence_pack", "pdf_ready_model", "pdf"}

    # Offline: the files downloaded beside the manifest check against it with the public key alone.
    folder = tmp_path / "auditor-copy"
    folder.mkdir()
    (folder / "manifest.json").write_bytes(manifest.content)
    for name, item in document["files"].items():
        downloaded = client.get(body["download_urls"][name], headers=owner)
        assert downloaded.status_code == 200
        assert hashlib.sha256(downloaded.content).hexdigest() == item["sha256"]
        assert es.service().verify(es.decode_header(downloaded.headers[es.HEADER]), data=downloaded.content)["valid"] is True
        (folder / Path(item["path"]).name).write_bytes(downloaded.content)
    (folder / "keys.json").write_text(client.get(es.WELL_KNOWN_PATH).text)
    result = run_verifier(str(folder / "manifest.json"), "--keys", str(folder / "keys.json"))
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_front_proxy_passes_the_public_keys_to_the_api():
    from app.services import https_proxy

    text = https_proxy.render_caddyfile(mode="http", cert_file=None, key_file=None)
    assert f"handle {es.WELL_KNOWN_PATH} {{\n\t\treverse_proxy api:8000" in text
