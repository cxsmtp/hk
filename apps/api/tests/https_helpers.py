"""Certificates, chains and a strict mock ACME certificate authority for the HTTPS tests (ported from CxMissionZero's
test/mock-acme.js): every request's JWS signature, nonce and url are checked, the HTTP-01 answer is really asked of
the service under test, and the CSR's key is signed into a real certificate chain."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import secrets
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.serialization import pkcs12

from app.services import tls_service


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def b64(data: bytes | str) -> str:
    return base64.b64encode(data.encode() if isinstance(data, str) else data).decode()


def upload(name: str, data: bytes | str) -> dict[str, str]:
    return {"name": name, "data": b64(data)}


@dataclass
class Chain:
    root: bytes
    intermediate: bytes
    leaf: bytes
    key: bytes
    leaf_key: Any = field(repr=False)


def company_chain(names: list[str] | None = None, *, days: int = 90, key_size: int = 2048, not_before: dt.datetime | None = None, server_auth: bool = True, now: dt.datetime | None = None) -> Chain:
    names = names or ["hawk.acme.io"]
    root_key = ec.generate_private_key(ec.SECP256R1())
    inter_key = ec.generate_private_key(ec.SECP256R1())
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    root_name = tls_service._subject("Acme Root CA", "Acme")
    inter_name = tls_service._subject("Acme Issuing CA", "Acme")
    root = tls_service.make_certificate(subject=root_name, public_key=root_key.public_key(), signer_key=root_key, ca=True, days=3650)
    inter = tls_service.make_certificate(subject=inter_name, issuer=root_name, public_key=inter_key.public_key(), signer_key=root_key, ca=True, days=1825)
    leaf = tls_service.make_certificate(
        subject=tls_service._subject(names[0]),
        issuer=inter_name,
        public_key=leaf_key.public_key(),
        signer_key=inter_key,
        names=names,
        days=days,
        not_before=not_before,
        server_auth=server_auth,
        now=now,
    )
    return Chain(root=root, intermediate=inter, leaf=leaf, key=key_pem(leaf_key), leaf_key=leaf_key)


def self_signed(names: list[str] | None = None, *, days: int = 397) -> tuple[bytes, bytes]:
    names = names or ["localhost", "127.0.0.1"]
    key = ec.generate_private_key(ec.SECP256R1())
    cert = tls_service.make_certificate(subject=tls_service._subject(names[0]), public_key=key.public_key(), signer_key=key, names=names, days=days)
    return cert, key_pem(key)


def pfx(chain: Chain, password: str = "") -> bytes:
    leaf = x509.load_pem_x509_certificate(chain.leaf)
    extra = [x509.load_pem_x509_certificate(chain.intermediate)]
    encryption = serialization.BestAvailableEncryption(password.encode()) if password else serialization.NoEncryption()
    return pkcs12.serialize_key_and_certificates(b"hawk", chain.leaf_key, leaf, extra, encryption)


# ---------------------------------------------------------------------------
# A strict mock ACME v2 certificate authority, as an httpx transport
# ---------------------------------------------------------------------------


def _b64u(data: bytes | str) -> str:
    return base64.urlsafe_b64encode(data.encode() if isinstance(data, str) else data).rstrip(b"=").decode()


def _from_b64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _thumbprint(jwk: dict[str, str]) -> str:
    return _b64u(hashlib.sha256(json.dumps({"crv": jwk["crv"], "kty": jwk["kty"], "x": jwk["x"], "y": jwk["y"]}, separators=(",", ":")).encode()).digest())


class MockAcme:
    """``answer(name, token)`` is how the CA (and the self-check) reach a name's challenge address: it returns the
    body served there, or None for no answer (a name that does not reach this server)."""

    base = "http://ca.test"

    def __init__(self, answer: Callable[[str, str], str | None], *, bad_nonce_once: bool = False, fail_challenge: bool = False) -> None:
        self.answer = answer
        self.bad_nonce_once = bad_nonce_once
        self.fail_challenge = fail_challenge
        self.ca_key = ec.generate_private_key(ec.SECP256R1())
        self.ca_name = tls_service._subject("Mock ACME Root", "Tests")
        self.root = tls_service.make_certificate(subject=self.ca_name, public_key=self.ca_key.public_key(), signer_key=self.ca_key, ca=True, days=3650)
        self.nonces: set[str] = set()
        self.accounts: dict[str, dict[str, Any]] = {}
        self.orders: dict[str, dict[str, Any]] = {}
        self.authzs: dict[str, dict[str, Any]] = {}
        self.challenges: dict[str, dict[str, Any]] = {}
        self.requests: list[str] = []
        self.validations: list[dict[str, Any]] = []
        self.self_checks: list[str] = []

    @property
    def directory_url(self) -> str:
        return f"{self.base}/directory"

    def _nonce(self) -> str:
        n = secrets.token_urlsafe(16)
        self.nonces.add(n)
        return n

    def _send(self, status: int, body: Any, headers: dict[str, str] | None = None) -> httpx.Response:
        if isinstance(body, str):
            content, kind = body.encode(), "application/pem-certificate-chain"
        else:
            content, kind = json.dumps(body).encode(), "application/json"
        return httpx.Response(status, content=content, headers={"Replay-Nonce": self._nonce(), "Content-Type": kind, **(headers or {})})

    def _problem(self, status: int, kind: str, detail: str) -> httpx.Response:
        return self._send(status, {"type": f"urn:ietf:params:acme:error:{kind}", "detail": detail}, {"Content-Type": "application/problem+json"})

    def _signed(self, request: httpx.Request, *, allow_jwk: bool = False) -> tuple[Any, str, dict | None] | httpx.Response:
        jws = json.loads(request.content)
        header = json.loads(_from_b64u(jws["protected"]))
        if header.get("alg") != "ES256":
            return self._problem(400, "badSignatureAlgorithm", "ES256 only.")
        if self.bad_nonce_once:
            self.bad_nonce_once = False
            self.nonces.discard(header.get("nonce"))
            return self._problem(400, "badNonce", "Stale nonce (on purpose).")
        if header.get("nonce") not in self.nonces:
            return self._problem(400, "badNonce", "Unknown or used nonce.")
        self.nonces.discard(header["nonce"])
        if header.get("url") != str(request.url):
            return self._problem(401, "unauthorized", f"url {header.get('url')} is not {request.url}.")
        if header.get("jwk"):
            if not allow_jwk:
                return self._problem(400, "malformed", "Use kid.")
            jwk, kid = header["jwk"], ""
        else:
            kid = header.get("kid", "")
            if kid not in self.accounts:
                return self._problem(400, "accountDoesNotExist", "No such account.")
            jwk = self.accounts[kid]["jwk"]
        public = ec.EllipticCurvePublicNumbers(int.from_bytes(_from_b64u(jwk["x"]), "big"), int.from_bytes(_from_b64u(jwk["y"]), "big"), ec.SECP256R1()).public_key()
        raw = _from_b64u(jws["signature"])
        try:
            public.verify(encode_dss_signature(int.from_bytes(raw[:32], "big"), int.from_bytes(raw[32:], "big")), f"{jws['protected']}.{jws['payload']}".encode(), ec.ECDSA(hashes.SHA256()))
        except Exception:  # noqa: BLE001
            return self._problem(400, "malformed", "Bad signature.")
        payload = "" if jws["payload"] == "" else json.loads(_from_b64u(jws["payload"]))
        return payload, kid, header.get("jwk")

    def _validate(self, challenge: dict[str, Any]) -> None:
        authz = self.authzs[challenge["authz"]]
        expected = f"{challenge['token']}.{_thumbprint(self.accounts[challenge['kid']]['jwk'])}"
        got = self.answer(authz["identifier"]["value"], challenge["token"])
        ok = got is not None and got.strip() == expected
        self.validations.append({"name": authz["identifier"]["value"], "ok": ok})
        if ok and not self.fail_challenge:
            challenge["status"] = authz["status"] = "valid"
        else:
            challenge["status"] = authz["status"] = "invalid"
            challenge["error"] = {"type": "urn:ietf:params:acme:error:unauthorized", "detail": f"Invalid response: {'refused (on purpose)' if self.fail_challenge else str(got)[:80]}"}

    def handler(self, request: httpx.Request) -> httpx.Response:
        url = request.url
        if url.host != "ca.test":
            # The self-check, from the service under test, to http://<name>/.well-known/acme-challenge/<token>.
            self.self_checks.append(str(url))
            token = url.path.rsplit("/", 1)[-1]
            body = self.answer(url.host, token)
            if body is None:
                raise httpx.ConnectError("connection refused", request=request)
            return httpx.Response(200 if body else 404, text=body or "Not found")
        path = url.path
        self.requests.append(f"{request.method} {path}")
        if path == "/directory":
            return self._send(200, {"newNonce": f"{self.base}/new-nonce", "newAccount": f"{self.base}/new-account", "newOrder": f"{self.base}/new-order"})
        if path == "/new-nonce":
            return httpx.Response(200, headers={"Replay-Nonce": self._nonce()})
        if request.method != "POST":
            return self._problem(405, "malformed", "POST only.")
        if path == "/new-account":
            signed = self._signed(request, allow_jwk=True)
            if isinstance(signed, httpx.Response):
                return signed
            payload, _, jwk = signed
            if payload.get("termsOfServiceAgreed") is not True:
                return self._problem(403, "userActionRequired", "Agree to the terms.")
            existing = next((kid for kid, a in self.accounts.items() if _thumbprint(a["jwk"]) == _thumbprint(jwk)), None)
            kid = existing or f"{self.base}/acct/{len(self.accounts) + 1}"
            if not existing:
                self.accounts[kid] = {"jwk": jwk, "contact": payload.get("contact", [])}
            return self._send(200 if existing else 201, {"status": "valid"}, {"Location": kid})
        signed = self._signed(request)
        if isinstance(signed, httpx.Response):
            return signed
        payload, kid, _ = signed
        if path == "/new-order":
            oid = str(len(self.orders) + 1)
            authorizations = []
            for identifier in payload["identifiers"]:
                aid = f"{oid}-{len(self.authzs) + 1}"
                self.challenges[aid] = {"url": f"{self.base}/chall/{aid}", "type": "http-01", "token": secrets.token_urlsafe(24), "status": "pending", "authz": aid, "kid": kid}
                self.authzs[aid] = {"identifier": identifier, "status": "pending", "challenge": aid}
                authorizations.append(f"{self.base}/authz/{aid}")
            self.orders[oid] = {"status": "pending", "identifiers": payload["identifiers"], "authorizations": authorizations, "finalize": f"{self.base}/finalize/{oid}"}
            return self._send(201, self.orders[oid], {"Location": f"{self.base}/order/{oid}"})
        if path.startswith("/authz/"):
            a = self.authzs[path.split("/authz/")[1]]
            c = self.challenges[a["challenge"]]
            if c["status"] == "processing":
                self._validate(c)
            return self._send(200, {"identifier": a["identifier"], "status": a["status"], "challenges": [{"type": "dns-01", "url": f"{self.base}/chall/dns", "token": "x", "status": "pending"}, {k: c[k] for k in ("type", "url", "token", "status")} | ({"error": c["error"]} if c.get("error") else {})]})
        if path.startswith("/chall/"):
            c = self.challenges[path.split("/chall/")[1]]
            if c["status"] == "pending":
                c["status"] = "processing"
            return self._send(200, {k: c[k] for k in ("type", "url", "token", "status")})
        if path.startswith("/order/"):
            o = self.orders[path.split("/order/")[1]]
            states = [self.authzs[u.split("/authz/")[1]]["status"] for u in o["authorizations"]]
            if o["status"] == "pending" and all(s == "valid" for s in states):
                o["status"] = "ready"
            if o["status"] == "pending" and any(s == "invalid" for s in states):
                o["status"] = "invalid"
            return self._send(200, o)
        if path.startswith("/finalize/"):
            oid = path.split("/finalize/")[1]
            o = self.orders[oid]
            if o["status"] != "ready":
                return self._problem(403, "orderNotReady", f"Order is {o['status']}.")
            csr = x509.load_der_x509_csr(_from_b64u(payload["csr"]))
            names = [i["value"] for i in o["identifiers"]]
            leaf = tls_service.make_certificate(subject=tls_service._subject(names[0]), issuer=self.ca_name, public_key=csr.public_key(), signer_key=self.ca_key, names=names, days=90)
            o.update(status="valid", certificate=f"{self.base}/cert/{oid}", chain=(leaf + self.root).decode())
            return self._send(200, {k: v for k, v in o.items() if k != "chain"})
        if path.startswith("/cert/"):
            return self._send(200, self.orders[path.split("/cert/")[1]]["chain"])
        return self._problem(404, "malformed", "Not found.")

    def client(self) -> httpx.Client:
        return httpx.Client(transport=httpx.MockTransport(self.handler))
