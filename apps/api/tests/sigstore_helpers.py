"""Test-only: a Sigstore-like world in memory (ported from CxMissionZero's test/sigstore-helpers.js) — a certificate
authority, a GitHub Actions signing certificate with Fulcio's extensions, a transparency log key — and bundles made with
them, so the verifier can be checked against good and tampered attestations without any real key."""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import time
from dataclasses import dataclass
from typing import Any

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ObjectIdentifier

ACTIONS = "https://token.actions.githubusercontent.com"


def utf8(text: str) -> bytes:
    data = text.encode("utf-8")
    length = bytes([len(data)]) if len(data) < 128 else bytes([0x81, len(data)]) if len(data) < 256 else bytes([0x82, len(data) >> 8, len(data) & 255])
    return b"\x0c" + length + data


def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]) if cn else x509.Name([])


def make_cert(*, subject: str, issuer: str, public_key, sign_key, serial: int, not_before: dt.datetime, not_after: dt.datetime, ca: bool = False, extensions: list[tuple[str, bytes]] = (), san: str = "") -> bytes:
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(subject))
        .issuer_name(_name(issuer))
        .public_key(public_key)
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.UniformResourceIdentifier(san)]), critical=True)
    for oid, value in extensions:
        builder = builder.add_extension(x509.UnrecognizedExtension(ObjectIdentifier(oid), value), critical=False)
    return builder.sign(sign_key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def _spki(key) -> bytes:
    return key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


@dataclass
class World:
    trusted_root: dict[str, Any]
    leaf_der: bytes
    leaf_key: Any
    log_key: Any
    key_id: str
    now: float
    repository: str


def make_world(*, repository: str = "cxsmtp/hk", ref: str = "refs/heads/main", workflow: str = ".github/workflows/release.yml", issuer: str = ACTIONS, now: float | None = None, valid_seconds: int = 600) -> World:
    now = time.time() if now is None else now
    at = dt.datetime.fromtimestamp(now, dt.timezone.utc)
    year = dt.timedelta(days=365)
    root, intermediate, leaf, log = (ec.generate_private_key(ec.SECP256R1()) for _ in range(4))
    root_der = make_cert(subject="test root", issuer="test root", public_key=root.public_key(), sign_key=root, serial=1, not_before=at - year, not_after=at + year, ca=True)
    inter_der = make_cert(subject="test intermediate", issuer="test root", public_key=intermediate.public_key(), sign_key=root, serial=2, not_before=at - year, not_after=at + year, ca=True)
    signer = f"https://github.com/{repository}/{workflow}@{ref}"
    leaf_der = make_cert(
        subject="",
        issuer="test intermediate",
        public_key=leaf.public_key(),
        sign_key=intermediate,
        serial=3,
        not_before=at - dt.timedelta(seconds=60),
        not_after=at - dt.timedelta(seconds=60) + dt.timedelta(seconds=valid_seconds),
        san=signer,
        extensions=[
            ("1.3.6.1.4.1.57264.1.1", issuer.encode()),
            ("1.3.6.1.4.1.57264.1.8", utf8(issuer)),
            ("1.3.6.1.4.1.57264.1.9", utf8(signer)),
            ("1.3.6.1.4.1.57264.1.12", utf8(f"https://github.com/{repository}")),
            ("1.3.6.1.4.1.57264.1.13", utf8("0123456789abcdef0123456789abcdef01234567")),
            ("1.3.6.1.4.1.57264.1.14", utf8(ref)),
            ("1.3.6.1.4.1.57264.1.21", utf8(f"https://github.com/{repository}/actions/runs/1/attempts/1")),
        ],
    )
    log_der = _spki(log)
    key_id = base64.b64encode(hashlib.sha256(log_der).digest()).decode()
    trusted_root = {
        "certificateAuthorities": [{"certChain": {"certificates": [{"rawBytes": base64.b64encode(inter_der).decode()}, {"rawBytes": base64.b64encode(root_der).decode()}]}, "validFor": {"start": (at - year).isoformat().replace("+00:00", "Z")}}],
        "tlogs": [{"baseUrl": "https://log.test", "publicKey": {"rawBytes": base64.b64encode(log_der).decode(), "keyDetails": "PKIX_ECDSA_P256_SHA_256"}, "logId": {"keyId": key_id}}],
    }
    return World(trusted_root, leaf_der, leaf, log, key_id, now, repository)


def _pae(kind: str, payload: bytes) -> bytes:
    return f"DSSEv1 {len(kind.encode())} {kind} {len(payload)} ".encode() + payload


def _sign(key, data: bytes) -> bytes:
    return key.sign(data, ec.ECDSA(hashes.SHA256()))


def make_bundle(world: World, digest: str, *, proof: str = "set", sign_key=None, integrated_time: int | None = None, tamper: dict[str, Any] | None = None) -> dict[str, Any]:
    """A bundle about ``digest``, signed with the world's leaf and logged in its log, with a signed entry timestamp
    (proof="set") or an inclusion proof and signed checkpoint (proof="checkpoint")."""

    tamper = tamper or {}
    sign_key = sign_key or world.leaf_key
    integrated_time = int(world.now) if integrated_time is None else integrated_time
    statement = {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "integrity.json", "digest": {"sha256": digest}}], "predicateType": "https://slsa.dev/provenance/v1", "predicate": {}}
    payload = json.dumps(statement).encode()
    kind = "application/vnd.in-toto+json"
    sig = _sign(sign_key, _pae(kind, payload))
    signed_payload = json.dumps({**statement, "subject": [{"name": "x", "digest": {"sha256": tamper["payload"]}}]}).encode() if tamper.get("payload") else payload
    b64 = base64.b64encode(world.leaf_der).decode()
    pem = "-----BEGIN CERTIFICATE-----\n" + "\n".join(b64[i : i + 64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE-----\n"
    body = {
        "apiVersion": "0.0.1",
        "kind": "dsse",
        "spec": {
            "payloadHash": {"algorithm": "sha256", "value": hashlib.sha256(tamper.get("logged_payload", payload)).hexdigest()},
            "signatures": [{"signature": base64.b64encode(sig).decode(), "verifier": base64.b64encode(pem.encode()).decode()}],
        },
    }
    canonicalized = base64.b64encode(json.dumps(body).encode()).decode()
    entry: dict[str, Any] = {"logIndex": "7", "logId": {"keyId": world.key_id}, "kindVersion": {"kind": "dsse", "version": "0.0.1"}, "integratedTime": str(integrated_time), "canonicalizedBody": canonicalized}
    log_key = tamper.get("log_key") or world.log_key
    if proof == "set":
        signed = json.dumps({"body": canonicalized, "integratedTime": integrated_time, "logID": base64.b64decode(world.key_id).hex(), "logIndex": 7}, separators=(",", ":"))
        entry["inclusionPromise"] = {"signedEntryTimestamp": base64.b64encode(_sign(log_key, signed.encode())).decode()}
    else:
        h = lambda *parts: hashlib.sha256(b"".join(parts)).digest()  # noqa: E731
        ours = h(b"\x00", base64.b64decode(canonicalized))
        other = h(b"\x00", b"another entry")
        root = h(b"\x01", ours, other)
        note = f"log.test\n2\n{base64.b64encode(root).decode()}\n"
        note_sig = b"\x00\x00\x00\x00" + _sign(log_key, note.encode())
        entry["inclusionProof"] = {"logIndex": "0", "rootHash": base64.b64encode(root).decode(), "treeSize": "2", "hashes": [base64.b64encode(other).decode()], "checkpoint": {"envelope": f"{note}\n— log.test {base64.b64encode(note_sig).decode()}\n"}}
    return {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "verificationMaterial": {"certificate": {"rawBytes": b64}, "tlogEntries": [entry]},
        "dsseEnvelope": {"payload": base64.b64encode(signed_payload).decode(), "payloadType": kind, "signatures": [{"sig": base64.b64encode(sig).decode()}]},
    }
