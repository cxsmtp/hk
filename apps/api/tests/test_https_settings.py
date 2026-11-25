"""Settings → HTTPS, ported from CxMissionZero (src/https-manager.js, src/tls.js, src/routes/https.js, src/acme.js,
scripts/https.mjs): certificates checked the way a browser would, the request (CSR) for IT, the previous certificate
put back, the modes and their rules, staged HSTS, Let's Encrypt against a strict mock CA, the way back in from the
command line, and what the front proxy is told (app/services/https_proxy.py)."""

from __future__ import annotations

import datetime as dt
import os
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from app.cli import https as https_cli
from app.db.models.audit import AuditLog
from app.db.models.user import User, UserTenantRole
from app.db.session import Base, get_db
from app.main import app
from app.services import https_runtime, tls_service
from app.services.acme_service import RENEW_DAYS, AcmeService, clean_names, valid_name
from app.services.https_manager import HSTS_AGES, HttpsError, HttpsManager, inspect_certificate, read_uploads, set_mode_offline
from app.services.https_proxy import ProxyConfig, ProxySettingError, render_caddyfile, trust_proxy_ranges
from app.services.tls_service import CertificateError, Pem

from tests.https_helpers import MockAcme, company_chain, key_pem, pfx, self_signed, upload

NOW = dt.datetime.now(dt.timezone.utc)


def make_manager(tmp_path: Path, env: dict[str, str] | None = None, proxy: bool = True) -> HttpsManager:
    return HttpsManager(data_dir=tmp_path / "data", env=env or {}, proxy=ProxyConfig(tmp_path / "proxy" if proxy else None))


def caddyfile(tmp_path: Path) -> str:
    return (tmp_path / "proxy" / "Caddyfile").read_text()


def pem_files(chain) -> list[dict[str, str]]:
    # Any order, any names: the key first, then the chain, then the server certificate.
    return [upload("private.key", chain.key), upload("bundle.pem", chain.intermediate + chain.root), upload("server.crt", chain.leaf)]


# ---- How HTTPS starts --------------------------------------------------------------------------------------------


def test_start_mode_follows_https_and_the_certificate_options():
    assert tls_service.start_mode({"HTTPS": "on"}) == "https"
    assert tls_service.start_mode({"HTTPS": "off"}) == "http"
    assert tls_service.start_mode({"HTTPS": "both"}) == "both"
    assert tls_service.start_mode({}) == "http"
    assert tls_service.start_mode({"TLS_CERT_FILE": "/certs/a.crt"}) == "https"
    assert tls_service.start_mode({"HTTPS": "on", "LETSENCRYPT_DOMAIN": "hawk.example.com"}) == "both"
    with pytest.raises(CertificateError, match="on, off or both"):
        tls_service.start_mode({"HTTPS": "maybe"})


def test_the_self_signed_certificate_lasts_about_13_months_and_covers_the_names_in_use(tmp_path):
    names = tls_service.self_signed_names({"HAWK_HOST": "hawk.acme.io", "TLS_HOSTNAMES": "alt.acme.io, 10.0.0.5", "PUBLIC_URL": "https://public.acme.io:8443"})
    assert names == sorted(["127.0.0.1", "10.0.0.5", "alt.acme.io", "hawk.acme.io", "localhost", "public.acme.io"])
    cert_file, key_file = tls_service.ensure_self_signed(tmp_path, names)
    cert = x509.load_pem_x509_certificate(cert_file.read_bytes())
    assert (cert.not_valid_after_utc - cert.not_valid_before_utc).days == 397
    assert set(tls_service.san_names(cert)) == set(names)
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert os.stat(key_file).st_mode & 0o777 == 0o600
    # Kept while it covers the names; made again for new names.
    assert tls_service.ensure_self_signed(tmp_path, names)[0].read_bytes() == cert_file.read_bytes()
    first = cert_file.read_bytes()
    tls_service.ensure_self_signed(tmp_path, [*names, "new.acme.io"])
    assert cert_file.read_bytes() != first


def test_a_certificate_request_keeps_its_rsa_2048_key_and_asks_for_every_name():
    made = tls_service.certificate_request(["Hawk.Acme.io", "10.1.2.3", "hawk.acme.io"], "Acme Ltd")
    csr = x509.load_pem_x509_csr(made.csr.encode())
    assert csr.is_signature_valid
    assert made.names == ["hawk.acme.io", "10.1.2.3"]
    assert tls_service.common_name(csr.subject) == "hawk.acme.io"
    assert csr.public_key().key_size == 2048
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["hawk.acme.io"]
    with pytest.raises(CertificateError, match="not a server name"):
        tls_service.certificate_request(["bad name!"])
    with pytest.raises(CertificateError, match="at least one name"):
        tls_service.certificate_request([])


# ---- Reading uploads and checking them like a browser -------------------------------------------------------------


def test_pem_files_in_any_order_become_the_server_certificate_then_its_chain(tmp_path):
    chain = company_chain()
    m = make_manager(tmp_path)
    report = m.inspect(files=pem_files(chain), hosts=["hawk.acme.io"])
    assert report["usable"] is True
    assert report["trust"] == "company"
    assert [c["subject"] for c in report["summary"]["chain"]] == ["hawk.acme.io", "Acme Issuing CA"]
    assert {c["id"]: c["level"] for c in report["checks"]} == {"key": "ok", "dates": "ok", "names": "ok", "trust": "ok", "strength": "ok"}
    assert report["summary"]["keyType"] == "RSA 2048-bit"


def test_a_der_certificate_and_a_pfx_with_its_password_are_read(tmp_path):
    chain = company_chain()
    der = x509.load_pem_x509_certificate(chain.leaf).public_bytes(serialization.Encoding.DER)
    m = make_manager(tmp_path)
    assert m.inspect(files=[upload("server.cer", der), upload("server.key", chain.key)])["usable"] is True
    data = pfx(chain, "s3cret")
    with pytest.raises(HttpsError) as missing:
        m.inspect(files=[upload("server.pfx", data)])
    assert missing.value.extra.get("needsPassphrase") and "protected by a password" in str(missing.value)
    with pytest.raises(HttpsError, match="did not open with that password"):
        m.inspect(files=[upload("server.pfx", data)], passphrase="wrong")
    report = m.inspect(files=[upload("server.pfx", data)], passphrase="s3cret")
    assert report["kind"] == "pfx" and report["usable"] is True


def test_a_key_that_does_not_belong_or_is_missing_is_refused_with_the_reason(tmp_path):
    one, other = company_chain(), company_chain()
    m = make_manager(tmp_path)
    with pytest.raises(HttpsError, match="does not belong to any of these certificates"):
        m.inspect(files=[upload("a.crt", one.leaf), upload("b.key", other.key)])
    with pytest.raises(HttpsError, match="The private key is missing"):
        m.inspect(files=[upload("a.crt", one.leaf)])
    with pytest.raises(HttpsError, match="Only a private key was given"):
        m.inspect(files=[upload("b.key", one.key)])
    with pytest.raises(HttpsError, match="Choose the certificate files first"):
        read_uploads([])
    with pytest.raises(HttpsError, match="is not a certificate"):
        read_uploads([upload("notes.txt", b"\x01\x02 hello")])
    with pytest.raises(HttpsError, match="larger than 256 KB"):
        read_uploads([upload("big.pem", b"x" * (256 * 1024 + 1))])


def test_an_encrypted_key_asks_for_its_password(tmp_path):
    chain = company_chain()
    encrypted = chain.leaf_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.BestAvailableEncryption(b"pw"))
    m = make_manager(tmp_path)
    with pytest.raises(HttpsError) as error:
        m.inspect(files=[upload("a.crt", chain.leaf), upload("a.key", encrypted)])
    assert error.value.extra.get("needsPassphrase")
    assert m.inspect(files=[upload("a.crt", chain.leaf), upload("a.key", encrypted)], passphrase="pw")["usable"] is True


def test_certificates_outside_the_chain_are_left_out_and_said_so(tmp_path):
    chain, stranger = company_chain(), company_chain(["other.acme.io"])
    report = make_manager(tmp_path).inspect(files=[*pem_files(chain), upload("other.crt", stranger.leaf)])
    assert any("1 certificate was not part of this certificate's chain" in n for n in report["notes"])


def test_trust_self_signed_missing_chain_and_company_ca():
    cert, key = self_signed(["localhost"])
    assert inspect_certificate(Pem(cert, key), hosts=["localhost"])["trust"] == "self-signed"
    chain = company_chain()
    leaf_only = inspect_certificate(Pem(chain.leaf, chain.key), hosts=["hawk.acme.io"])
    assert leaf_only["trust"] == "incomplete"
    assert "its chain is missing" in next(c["title"] for c in leaf_only["checks"] if c["id"] == "trust")
    with_root = inspect_certificate(Pem(chain.leaf + chain.intermediate, chain.key), root=chain.root)
    assert with_root["trust"] == "company"
    assert next(c["title"] for c in with_root["checks"] if c["id"] == "trust") == "Issued by your certificate authority Acme Root CA"


def test_names_dates_key_strength_and_purpose_are_checked():
    chain = company_chain(["hawk.acme.io", "*.apps.acme.io"])
    pem = Pem(chain.leaf + chain.intermediate, chain.key)
    names = {c["id"]: c for c in inspect_certificate(pem, hosts=["x.apps.acme.io", "elsewhere.io"])["checks"]}["names"]
    assert names["level"] == "warn" and names["title"] == "Does not cover elsewhere.io"
    local = {c["id"]: c for c in inspect_certificate(pem, hosts=["localhost"])["checks"]}["names"]
    assert local["detail"].startswith("Fine: that is this machine's own name.")
    # Expiring within 30 days: flagged.
    soon = company_chain(days=10)
    dates = {c["id"]: c for c in inspect_certificate(Pem(soon.leaf + soon.intermediate, soon.key))["checks"]}["dates"]
    assert dates["level"] == "warn" and dates["title"] in ("Expires in 9 days", "Expires in 10 days")
    # Expired, and not valid yet: refused.
    old = company_chain(days=1, now=NOW - dt.timedelta(days=30), not_before=NOW - dt.timedelta(days=60))
    report = inspect_certificate(Pem(old.leaf + old.intermediate, old.key))
    assert report["usable"] is False and any(c["title"].startswith("Expired on") for c in report["checks"])
    future = company_chain(not_before=NOW + dt.timedelta(days=3))
    assert any(c["title"].startswith("Not valid until") for c in inspect_certificate(Pem(future.leaf + future.intermediate, future.key))["checks"])
    weak = company_chain(key_size=1024)
    report = inspect_certificate(Pem(weak.leaf + weak.intermediate, weak.key))
    assert report["usable"] is False and any(c["title"] == "RSA 1024-bit key: too weak" for c in report["checks"])
    client = company_chain(server_auth=False)
    assert any(c["title"] == "Not a web server certificate" for c in inspect_certificate(Pem(client.leaf + client.intermediate, client.key))["checks"])


def test_a_ca_certificate_is_flagged_and_a_certificate_without_names_refused():
    key = ec.generate_private_key(ec.SECP256R1())
    ca = tls_service.make_certificate(subject=tls_service._subject("Not a server"), public_key=key.public_key(), signer_key=key, ca=True)
    report = inspect_certificate(Pem(ca, key_pem(key)))
    assert report["usable"] is False
    titles = [c["title"] for c in report["checks"]]
    assert "This is a certificate authority, not a server certificate" in titles
    assert "It names no server (no Subject Alternative Name)" in titles


# ---- Installing, putting the previous one back, the request for IT ---------------------------------------------------


def test_a_new_certificate_goes_live_at_once_and_the_previous_one_comes_back_in_one_click(tmp_path):
    m = make_manager(tmp_path, {"HTTPS": "both"})
    m.check()
    assert m.active.source == "self-signed"
    first, second = company_chain(), company_chain()
    m.install(files=pem_files(first), hosts=["hawk.acme.io"], by="owner@acme.io")
    live = list((tmp_path / "proxy").glob("live-*.crt"))
    assert len(live) == 1 and live[0].read_bytes().startswith(first.leaf)
    assert os.stat(next((tmp_path / "proxy").glob("live-*.key"))).st_mode & 0o777 == 0o600
    assert f'tls "{live[0]}"' in caddyfile(tmp_path)
    m.install(files=pem_files(second), hosts=["hawk.acme.io"], by="owner@acme.io")
    status = m.status()
    assert status["previous"]["subject"] == "hawk.acme.io"
    assert status["uploaded"]["by"] == "owner@acme.io"
    assert next((tmp_path / "proxy").glob("live-*.crt")).read_bytes().startswith(second.leaf)
    m.restore_previous(by="owner@acme.io")
    assert next((tmp_path / "proxy").glob("live-*.crt")).read_bytes().startswith(first.leaf)
    # And back again: the two swap.
    m.restore_previous()
    assert next((tmp_path / "proxy").glob("live-*.crt")).read_bytes().startswith(second.leaf)
    # Stop using it: back to self-signed.
    assert m.remove_uploaded() == "self-signed"
    assert m.active.source == "self-signed"


def test_with_https_only_a_certificate_with_warnings_needs_confirming(tmp_path):
    m = make_manager(tmp_path, {"HTTPS": "on"})
    m.check()
    chain = company_chain()
    with pytest.raises(HttpsError) as error:
        m.install(files=[upload("a.crt", chain.leaf), upload("a.key", chain.key)], hosts=["hawk.acme.io"])
    assert error.value.status == 409 and error.value.extra["needsConfirm"]
    m.install(files=[upload("a.crt", chain.leaf), upload("a.key", chain.key)], hosts=["hawk.acme.io"], confirm=True)
    with pytest.raises(HttpsError, match="self-signed one is used"):
        m.remove_uploaded()


def test_an_unusable_certificate_never_replaces_the_one_in_use(tmp_path):
    m = make_manager(tmp_path, {"HTTPS": "both"})
    m.check()
    before = caddyfile(tmp_path)
    weak = company_chain(key_size=1024)
    with pytest.raises(HttpsError, match="too weak") as error:
        m.install(files=pem_files(weak))
    assert error.value.extra["report"]["usable"] is False
    assert caddyfile(tmp_path) == before
    with pytest.raises(HttpsError, match="no previous certificate"):
        m.restore_previous()


def test_the_certificate_from_it_pairs_with_the_key_kept_from_the_request(tmp_path):
    m = make_manager(tmp_path, {"HTTPS": "both"})
    csr_text = m.create_request(names=["hawk.acme.io"], organisation="Acme", by="owner@acme.io")
    assert m.request_csr() == csr_text
    assert os.stat(tmp_path / "data" / "tls" / "request.key").st_mode & 0o777 == 0o600
    assert m.status()["request"]["available"] is True
    # IT signs it: only the certificate (and its chain) come back.
    csr = x509.load_pem_x509_csr(csr_text.encode())
    issuer_key = ec.generate_private_key(ec.SECP256R1())
    issuer = tls_service._subject("Acme Issuing CA")
    leaf = tls_service.make_certificate(subject=csr.subject, issuer=issuer, public_key=csr.public_key(), signer_key=issuer_key, names=["hawk.acme.io"], days=200)
    report = m.install(files=[upload("from-it.cer", leaf)], hosts=["hawk.acme.io"])
    assert report["summary"]["subject"] == "hawk.acme.io"
    assert m.status()["request"] is None
    assert not (tmp_path / "data" / "tls" / "request.key").exists()
    # A certificate for another request is refused with the reason.
    m.create_request(names=["hawk.acme.io"])
    other = company_chain()
    with pytest.raises(HttpsError, match="not made for the request created here"):
        m.install(files=[upload("x.crt", other.leaf)])


# ---- Modes, HSTS and the TLS version -----------------------------------------------------------------------------


def test_https_only_needs_the_page_open_over_https_and_self_signed_needs_confirming(tmp_path):
    m = make_manager(tmp_path, {"HTTPS": "both"})
    m.check()
    with pytest.raises(HttpsError) as error:
        m.set_mode("https", secure=False)
    assert error.value.extra["needsHttps"]
    with pytest.raises(HttpsError) as error:
        m.set_mode("https", secure=True)
    assert error.value.extra["needsConfirm"] and "self-signed" in str(error.value)
    assert m.set_mode("https", secure=True, confirm=True) == "https"
    text = caddyfile(tmp_path)
    assert "http_redirect" in text and "redir https://{host}{uri} 308" in text
    # Back to plain http: confirmed, and never while HSTS is on.
    with pytest.raises(HttpsError, match="turns HTTPS off for everyone"):
        m.set_mode("http")
    m.set_mode("both")
    m.set_mode("http")
    assert "http://:8443 {" in caddyfile(tmp_path) and "https://:8443" not in caddyfile(tmp_path)
    with pytest.raises(HttpsError, match="Unknown mode"):
        m.set_mode("sometimes")


def test_hsts_is_staged_never_sent_with_self_signed_and_blocks_going_back_to_http(tmp_path):
    m = make_manager(tmp_path, {"HTTPS": "both"})
    m.check()
    with pytest.raises(HttpsError, match="after switching to HTTPS only"):
        m.set_hardening(hsts={"enabled": True})
    m.set_mode("https", secure=True, confirm=True)
    with pytest.raises(HttpsError, match="Not with a self-signed certificate"):
        m.set_hardening(hsts={"enabled": True})
    assert m.hsts_header() == ""
    chain = company_chain()
    m.install(files=pem_files(chain), hosts=["hawk.acme.io"], confirm=True)
    # First a day…
    m.set_hardening(hsts={"enabled": True, "maxAge": 86_400})
    assert m.hsts_header() == "max-age=86400"
    assert 'header Strict-Transport-Security "max-age=86400"' in caddyfile(tmp_path)
    # …then a year, with subdomains.
    m.set_hardening(hsts={"enabled": True, "maxAge": 31_536_000, "includeSubDomains": True})
    assert m.hsts_header() == "max-age=31536000; includeSubDomains"
    assert HSTS_AGES == (86_400, 604_800, 15_768_000, 31_536_000)
    # Any other age falls back to a day.
    m.set_hardening(hsts={"maxAge": 12345})
    assert m.state["hsts"]["maxAge"] == 86_400
    with pytest.raises(HttpsError, match="Turn HSTS off first"):
        m.set_mode("http", confirm=True)
    # TLS 1.3 only.
    m.set_hardening(min_version="TLSv1.3")
    assert "protocols tls1.3\n" in caddyfile(tmp_path)
    with pytest.raises(HttpsError, match="TLSv1.2 or TLSv1.3"):
        m.set_hardening(min_version="TLSv1.0")


def test_the_page_choice_wins_over_https_and_survives_a_restart(tmp_path):
    m = make_manager(tmp_path, {"HTTPS": "on"})
    m.check()
    m.set_mode("both", by="owner@acme.io")
    again = make_manager(tmp_path, {"HTTPS": "on"})
    assert again.mode == "both" and again.status()["chosenHere"] is True and again.status()["startMode"] == "https"
    assert os.stat(tmp_path / "data" / "https.json").st_mode & 0o777 == 0o600


def test_a_damaged_https_json_is_never_taken_for_nothing_chosen(tmp_path):
    m = make_manager(tmp_path, {"HTTPS": "both"})
    m.set_mode("http", confirm=True)
    m.set_mode("both")
    (tmp_path / "data" / "https.json").write_text("{ cut short")
    # The last good copy is used instead.
    assert make_manager(tmp_path, {"HTTPS": "on"}).mode in ("http", "both")


# ---- What the proxy is told ----------------------------------------------------------------------------------------


def test_the_caddyfile_for_each_mode():
    https_only = render_caddyfile(mode="https", cert_file="/p/c.crt", key_file="/p/c.key", hsts="max-age=86400", https_port=3000, trusted=["10.0.0.0/8"])
    assert "https://:8443 {" in https_only and "protocols tls1.2 tls1.3" in https_only
    assert "redir https://{host}:3000{uri} 308" in https_only
    assert "@acme path /.well-known/acme-challenge/*" in https_only
    assert "trusted_proxies static 10.0.0.0/8" in https_only
    assert "admin off" in https_only and "auto_https off" in https_only
    both = render_caddyfile(mode="both", cert_file="/p/c.crt", key_file="/p/c.key")
    assert "http_redirect" in both and "redir https" not in both and "http://:8080 {\n\timport hawk" in both
    assert "Strict-Transport-Security" not in both
    plain = render_caddyfile(mode="http", cert_file=None, key_file=None)
    assert "https://:8443" not in plain and "\ttls " not in plain
    assert "http://:8443 {\n\timport hawk" in plain and "http_redirect" not in plain


def test_trust_proxy_reads_as_cxmissionzero_reads_it():
    assert trust_proxy_ranges("", serving_https=True) == []
    assert trust_proxy_ranges("", serving_https=False) == ["127.0.0.0/8", "::1/128"]
    assert trust_proxy_ranges("off", True) == []
    assert trust_proxy_ranges("on", True) == ["0.0.0.0/0", "::/0"]
    assert trust_proxy_ranges("uniquelocal", True) == ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"]
    assert trust_proxy_ranges("10.20.0.15, 10.89.0.0/24, loopback", True) == ["10.20.0.15/32", "10.89.0.0/24", "127.0.0.0/8", "::1/128"]
    with pytest.raises(ProxySettingError):
        trust_proxy_ranges("2", True)
    with pytest.raises(ProxySettingError):
        trust_proxy_ranges("proxy.local", True)


def test_a_bad_certificate_stops_the_start_and_nothing_is_served(tmp_path):
    chain, other = company_chain(), company_chain()
    (tmp_path / "server.crt").write_bytes(chain.leaf)
    (tmp_path / "server.key").write_bytes(other.key)
    m = make_manager(tmp_path, {"HTTPS": "on", "TLS_CERT_FILE": str(tmp_path / "server.crt"), "TLS_KEY_FILE": str(tmp_path / "server.key")})
    with pytest.raises(CertificateError, match="does not belong"):
        m.check()
    text = caddyfile(tmp_path)
    assert "8443" not in text and "8080" not in text and "503" in text
    with pytest.raises(CertificateError, match="both TLS_CERT_FILE and TLS_KEY_FILE"):
        make_manager(tmp_path, {"TLS_CERT_FILE": "/x.crt"})


def test_a_pfx_given_to_the_deployment_is_served_and_a_wrong_password_stops_the_start(tmp_path):
    chain = company_chain()
    (tmp_path / "server.pfx").write_bytes(pfx(chain, "pw"))
    env = {"HTTPS": "on", "TLS_PFX_FILE": str(tmp_path / "server.pfx"), "TLS_PFX_PASSPHRASE": "pw"}
    m = make_manager(tmp_path, env)
    m.check()
    assert m.active.source == "environment"
    assert next((tmp_path / "proxy").glob("live-*.crt")).read_bytes().startswith(chain.leaf)
    with pytest.raises(CertificateError, match="wrong TLS_PFX_PASSPHRASE"):
        make_manager(tmp_path, {**env, "TLS_PFX_PASSPHRASE": "nope"}).check()


def test_renewed_certificate_files_are_picked_up_and_a_broken_one_keeps_the_previous(tmp_path):
    first = company_chain()
    crt, key = tmp_path / "server.crt", tmp_path / "server.key"
    crt.write_bytes(first.leaf + first.intermediate)
    key.write_bytes(first.key)
    m = make_manager(tmp_path, {"HTTPS": "on", "TLS_CERT_FILE": str(crt), "TLS_KEY_FILE": str(key)})
    m.check()
    # Given to the deployment: HSTS starts on, a year with subdomains (as CxMissionZero).
    assert m.hsts_header() == "max-age=31536000; includeSubDomains"
    assert m.poll() == ""
    renewed = company_chain()
    time.sleep(0.01)
    crt.write_bytes(renewed.leaf + renewed.intermediate)
    key.write_bytes(renewed.key)
    assert m.poll() == "certificate"
    assert next((tmp_path / "proxy").glob("live-*.crt")).read_bytes().startswith(renewed.leaf)
    time.sleep(0.01)
    crt.write_bytes(company_chain().leaf)  # without its key
    assert m.poll() == "failed"
    assert next((tmp_path / "proxy").glob("live-*.crt")).read_bytes().startswith(renewed.leaf)


# ---- The way back in -----------------------------------------------------------------------------------------------


def test_the_command_line_brings_http_back_next_to_https_and_turns_hsts_off(tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("HAWK_PROXY_DIR", str(tmp_path / "proxy"))
    monkeypatch.setenv("HTTPS", "on")
    running = make_manager(tmp_path, {"HTTPS": "on"})
    running.check()
    chain = company_chain()
    running.install(files=pem_files(chain), hosts=["hawk.acme.io"], confirm=True)
    running.set_hardening(hsts={"enabled": True})
    assert "redir https" in caddyfile(tmp_path)
    audits = []
    assert https_cli.main(["both"], data_dir=str(tmp_path / "data"), audit=lambda **kw: audits.append(kw)) == 0
    # The proxy is given http next to HTTPS at once (it reloads within a second).
    text = caddyfile(tmp_path)
    assert "redir https" not in text and "http://:8080 {\n\timport hawk" in text and "Strict-Transport-Security" not in text
    assert audits[0]["action"] == "https.mode.changed" and "HSTS turned off" in audits[0]["reason"]
    assert "A running server switches within 5 seconds." in capsys.readouterr().out
    # The running API sees the change at its next look (every 5 seconds).
    assert running.poll() == "settings"
    assert running.mode == "both" and running.state["hsts"]["enabled"] is False
    assert https_cli.main(["sometimes"], data_dir=str(tmp_path / "data"), audit=lambda **kw: None) == 1
    assert https_cli.main([], data_dir=str(tmp_path / "data"), audit=lambda **kw: None) == 0
    assert "HTTPS mode: both; HSTS off." in capsys.readouterr().out


def test_set_mode_offline_refuses_unknown_modes(tmp_path):
    with pytest.raises(ValueError, match="Use one of"):
        set_mode_offline(tmp_path, "nope")
    before, after = set_mode_offline(tmp_path, "http")
    assert before == {} and after["mode"] == "http" and after["hsts"]["enabled"] is False


# ---- Let's Encrypt -------------------------------------------------------------------------------------------------


def acme_env(tmp_path, *, reachable=("hawk.example.com",), **ca_options):
    m = make_manager(tmp_path, {"HTTPS": "both"})
    m.check()
    holder: dict = {}

    def answer(name: str, token: str):
        if name not in reachable:
            return None
        return holder["service"].challenge(token) or ""

    ca = MockAcme(answer, **ca_options)
    service = AcmeService(data_dir=tmp_path / "data", https=m, http=ca.client(), directories={"production": ca.directory_url, "staging": ca.directory_url}, poll_seconds=0.01)
    holder["service"] = service
    events: list = []
    service.on_event(events.append)
    return m, service, ca, events


def test_names_public_dns_names_only():
    assert valid_name("hawk.company.com") is True
    for bad in ["10.0.0.5", "*.company.com", "localhost", "server", "hawk.local", "host.internal", "a..b.com", ""]:
        assert valid_name(bad) is False, bad
    assert clean_names("HAWK.Company.com, www.company.com hawk.company.com") == ["hawk.company.com", "www.company.com"]
    with pytest.raises(HttpsError, match="Enter the name"):
        clean_names("")
    with pytest.raises(HttpsError, match="IP address"):
        clean_names("10.1.2.3")
    with pytest.raises(HttpsError, match="wildcard"):
        clean_names("*.company.com")


def test_a_certificate_is_obtained_end_to_end_and_put_to_use(tmp_path):
    m, service, ca, events = acme_env(tmp_path)
    service.start(names="hawk.example.com", email="appsec@example.com", agree=True, by="owner@acme.io")
    service.settled(10)
    status = service.status()
    assert status["last"]["ok"] is True, status["last"]
    assert status["enabled"] is True and status["issued"]["names"] == ["hawk.example.com"]
    assert 88 <= status["daysLeft"] <= 90
    # The self-check went first, then the CA checked the same answer.
    assert ca.self_checks and all(v["ok"] for v in ca.validations)
    assert m.status()["uploaded"]["by"] == "Let's Encrypt, for owner@acme.io"
    live = next((tmp_path / "proxy").glob("live-*.crt")).read_bytes()
    assert b"BEGIN CERTIFICATE" in live and x509.load_pem_x509_certificate(live).issuer == ca.ca_name
    assert events[-1]["kind"] == "issued"
    assert service.challenge("anything-longer-than-8") is None
    assert os.stat(tmp_path / "data" / "tls" / "acme" / "account.key").st_mode & 0o777 == 0o600


def test_a_stale_nonce_is_retried_the_agreement_is_needed_and_one_request_at_a_time(tmp_path):
    _, service, _, _ = acme_env(tmp_path, bad_nonce_once=True)
    with pytest.raises(HttpsError, match="Subscriber Agreement"):
        service.start(names="hawk.example.com")
    service.start(names="hawk.example.com", agree=True)
    with pytest.raises(HttpsError, match="already being requested"):
        service.start(names="hawk.example.com", agree=True)
    service.settled(10)
    assert service.status()["last"]["ok"] is True, service.status()["last"]


def test_the_self_check_stops_a_request_whose_name_does_not_reach_this_server(tmp_path):
    m, service, ca, events = acme_env(tmp_path, reachable=())
    service.start(names="hawk.example.com", agree=True)
    service.settled(10)
    last = service.status()["last"]
    assert last["ok"] is False and "could not reach itself" in last["error"]
    assert last["precheck"][0]["ok"] is False
    assert not [r for r in ca.requests if "new-order" in r], "the CA was not asked"
    assert m.status()["uploaded"] is None
    assert events[-1]["kind"] == "failed"


def test_skipping_the_self_check_and_a_failed_ca_check(tmp_path):
    _, service, ca, _ = acme_env(tmp_path, fail_challenge=True)
    service.start(names="hawk.example.com", agree=True, skip_precheck=True)
    service.settled(10)
    last = service.status()["last"]
    assert not ca.self_checks
    assert last["ok"] is False and "refused (on purpose)" in last["error"] and last["error"].startswith("Let's Encrypt:")
    assert service.status()["enabled"] is False


def test_renewal_30_days_before_expiry_not_after_a_recent_failure_and_off_when_disabled(tmp_path):
    m, service, _, _ = acme_env(tmp_path)
    service.start(names="hawk.example.com", agree=True)
    service.settled(10)
    valid_to = dt.datetime.fromisoformat(service.status()["issued"]["validTo"].replace("Z", "+00:00"))
    assert RENEW_DAYS == 30
    assert service.renewal_due() is False
    assert service.renewal_due(valid_to - dt.timedelta(days=RENEW_DAYS - 1)) is True
    first = m.status()["uploaded"]["at"]
    service.renew(by="test")
    service.settled(10)
    assert m.status()["uploaded"]["at"] != first and m.status()["previous"] is not None
    check_at = valid_to - dt.timedelta(days=1)
    service.state["last"] = {"at": (check_at - dt.timedelta(hours=1)).isoformat(), "ok": False}
    assert service.renewal_due(check_at) is False, "a failure an hour ago: not again for 6 hours"
    assert service.renewal_due(check_at + dt.timedelta(hours=6)) is True
    service.disable()
    assert service.renewal_due(valid_to) is False
    with pytest.raises(HttpsError, match="not on"):
        service.disable()


# ---- The routes: owners and admins, audited --------------------------------------------------------------------------


@pytest.fixture()
def api(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite+pysqlite:///{tmp_path / 'https.sqlite3'}", connect_args={"check_same_thread": False})
    session_factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_factory()
        try:
            yield db
        finally:
            db.close()

    app.dependency_overrides[get_db] = override_get_db
    manager = make_manager(tmp_path, {"HTTPS": "both"})
    manager.check()
    https_runtime.reset_for_tests(manager, AcmeService(data_dir=tmp_path / "data", https=manager))
    monkeypatch.setattr("app.db.session.SessionLocal", session_factory)
    http_client = TestClient(app, base_url="http://localhost")
    secure_client = TestClient(app, base_url="https://localhost")
    try:
        yield {"http": http_client, "https": secure_client, "db": session_factory, "manager": manager}
    finally:
        http_client.close()
        secure_client.close()
        app.dependency_overrides.clear()
        https_runtime.reset_for_tests()
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


def owner(client: TestClient, email: str = "owner@example.com") -> dict[str, str]:
    response = client.post("/auth/register", json={"email": email, "password": "Password123!", "full_name": "HTTPS Owner"})
    assert response.status_code == 200, response.text
    body = response.json()
    return {"Authorization": f"Bearer {body['access_token']}", "X-Tenant-ID": body["tenants"][0]["id"]}


def actions(api) -> list[str]:
    with api["db"]() as db:
        return [row.action for row in db.scalars(select(AuditLog).where(AuditLog.resource_type == "https")).all()]


def test_the_routes_are_for_owners_and_admins_only(api):
    headers = owner(api["http"])
    viewer = owner(api["http"], "viewer@example.com")
    with api["db"]() as db:
        user = db.scalar(select(User).where(User.email == "viewer@example.com"))
        db.add(UserTenantRole(user_id=user.id, tenant_id=headers["X-Tenant-ID"], role="viewer"))
        db.commit()
    as_viewer = {**viewer, "X-Tenant-ID": headers["X-Tenant-ID"]}
    assert api["http"].get("/https", headers=as_viewer).status_code == 403
    assert api["http"].post("/https/mode", json={"mode": "http"}, headers=as_viewer).status_code == 403
    assert api["http"].get("/https").status_code in (401, 403)
    status = api["http"].get("/https", headers=headers).json()
    assert status["mode"] == "both" and status["viewing"]["secure"] is False
    assert status["certificate"]["trust"] == "self-signed" and status["hstsAges"] == list(HSTS_AGES)
    assert status["viewing"]["httpsUrl"] == "https://localhost" and status["acme"]["running"] is False


def test_switching_to_https_only_works_only_from_a_page_open_over_https_and_is_audited(api):
    headers = owner(api["http"])
    refused = api["http"].post("/https/mode", json={"mode": "https"}, headers=headers)
    assert refused.status_code == 409 and refused.json()["needsHttps"] is True
    needs = api["https"].post("/https/mode", json={"mode": "https"}, headers=headers)
    assert needs.status_code == 409 and needs.json()["needsConfirm"] is True
    done = api["https"].post("/https/mode", json={"mode": "https", "confirm": True}, headers=headers)
    assert done.status_code == 200 and done.json()["mode"] == "https" and done.json()["viewing"]["secure"] is True
    assert actions(api) == ["https.mode.changed"]


def test_upload_csr_revert_and_hardening_through_the_routes(api):
    headers = owner(api["https"])
    chain = company_chain(["localhost", "hawk.acme.io"])
    files = pem_files(chain)
    checked = api["https"].post("/https/inspect", json={"files": files}, headers=headers).json()
    assert checked["usable"] is True and checked["trust"] == "company"
    put = api["https"].post("/https/certificate", json={"files": files}, headers=headers)
    assert put.status_code == 200, put.text
    assert put.json()["status"]["uploaded"]["subject"] == "localhost"
    second = api["https"].post("/https/certificate", json={"files": pem_files(company_chain(["localhost"]))}, headers=headers).json()
    assert second["status"]["previous"]["subject"] == "localhost"
    assert api["https"].post("/https/certificate/previous", headers=headers).status_code == 200
    made = api["https"].post("/https/request", json={"names": ["hawk.acme.io"], "organization": "Acme"}, headers=headers).json()
    assert made["csr"].startswith("-----BEGIN CERTIFICATE REQUEST-----")
    download = api["https"].get("/https/request.csr", headers=headers)
    assert download.headers["content-type"].startswith("application/pkcs10") and "hawk-ai.csr" in download.headers["content-disposition"]
    bad = api["https"].post("/https/certificate", json={"files": [upload("x.key", chain.key)]}, headers=headers)
    assert bad.status_code == 400 and "Only a private key" in bad.json()["error"]
    api["https"].post("/https/mode", json={"mode": "https", "confirm": True}, headers=headers)
    hardened = api["https"].post("/https/hardening", json={"hsts": {"enabled": True, "maxAge": 86400}, "minVersion": "TLSv1.3"}, headers=headers).json()
    assert hardened["hstsActive"] is True and hardened["minVersion"] == "TLSv1.3"
    assert api["https"].post("/https/browser-check", json={"ok": True, "url": "https://localhost"}, headers=headers).json() == {"ok": True}
    assert actions(api) == [
        "https.certificate.installed",
        "https.certificate.installed",
        "https.certificate.restored",
        "https.request.created",
        "https.mode.changed",
        "https.hardening.changed",
    ]


def test_the_acme_challenge_is_answered_without_signing_in(api):
    service = https_runtime.acme()
    service.challenges["token-123456789"] = "token-123456789.thumb"
    answer = api["http"].get("/.well-known/acme-challenge/token-123456789")
    assert answer.status_code == 200 and answer.text == "token-123456789.thumb"
    assert api["http"].get("/.well-known/acme-challenge/unknown-token-1").status_code == 404
    headers = owner(api["http"])
    refused = api["http"].post("/https/acme", json={"names": ["hawk.example.com"]}, headers=headers)
    assert refused.status_code == 400 and "Subscriber Agreement" in refused.json()["error"]


def test_failed_lets_encrypt_attempts_are_audited(api, monkeypatch):
    chain = company_chain(["hawk.example.com"])
    api["manager"].install(files=pem_files(chain), hosts=["hawk.example.com"])
    audits = []
    monkeypatch.setattr(https_runtime, "audit_system", lambda **kw: audits.append(kw))
    https_runtime._audit_acme_event({"kind": "failed", "names": ["hawk.example.com"], "error": "nope", "by": "owner@example.com"})
    assert audits[0]["action"] == "https.letsencrypt.failed" and audits[0]["outcome"] == "failed"
    https_runtime._audit_acme_event({"kind": "issued", "names": ["hawk.example.com"], "validTo": "2027-03-01T00:00:00Z", "by": "LETSENCRYPT_DOMAIN"})
    assert audits[1]["action"] == "https.letsencrypt.issued"
    # Deployed with LETSENCRYPT_DOMAIN: HTTPS only by itself.
    assert api["manager"].mode == "https" and audits[2]["action"] == "https.mode.changed"
