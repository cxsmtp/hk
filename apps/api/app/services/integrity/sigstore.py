"""Checks one GitHub build attestation (a Sigstore bundle) here, with no Sigstore library: ported line for line from
CxMissionZero's src/integrity/sigstore.js. CxMissionZero uses Node.js's own X.509 and signature code; this uses the
``cryptography`` package Hawk AI already depends on for the same two things (no new dependency).

 1. the signing certificate was issued by Sigstore's certificate authority (the trust root kept in trusted_root.json)
    and was valid when the signature was logged;
 2. it names the release workflow of this repository, run by GitHub Actions, on main or a version tag;
 3. the signature over the attestation is good;
 4. the attestation is about these exact bytes (its subject's SHA-256);
 5. Sigstore's public transparency log recorded it (its signed timestamp, or its inclusion proof and signed
    checkpoint), and that record is of this signature and this certificate.

Returns {ok: True, signedAt, repository, ref, commit, workflow, run, logIndex} or {ok: False, reason}.
"""

from __future__ import annotations

import base64
import binascii
import datetime as dt
import hashlib
import json
import re
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.x509.oid import ObjectIdentifier

ISSUER = "https://token.actions.githubusercontent.com"
#: The workflow that builds and signs Hawk AI's images.
RELEASE_WORKFLOW = ".github/workflows/release.yml"
#: Which git refs may have built a release: main (or master) and version tags.
RELEASE_REFS = re.compile(r"^refs/(heads/(main|master)|tags/v[\w.-]+)$")
OID = {
    "issuerV1": "1.3.6.1.4.1.57264.1.1",
    "issuerV2": "1.3.6.1.4.1.57264.1.8",
    "buildSignerUri": "1.3.6.1.4.1.57264.1.9",
    "sourceRepositoryUri": "1.3.6.1.4.1.57264.1.12",
    "sourceRepositoryDigest": "1.3.6.1.4.1.57264.1.13",
    "sourceRepositoryRef": "1.3.6.1.4.1.57264.1.14",
    "runInvocationUri": "1.3.6.1.4.1.57264.1.21",
}


def b64(value: Any) -> bytes:
    try:
        return base64.b64decode(str(value or ""), validate=False)
    except (binascii.Error, ValueError):
        return b""


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def fail(reason: str) -> dict[str, Any]:
    return {"ok": False, "reason": reason}


def _ms(value: dt.datetime) -> float:
    return value.timestamp() * 1000


def _parse_time(text: Any) -> float | None:
    if not text:
        return None
    try:
        return _ms(dt.datetime.fromisoformat(str(text).replace("Z", "+00:00")))
    except ValueError:
        return None


# ---- A little DER, enough to read the text of a Fulcio extension -----------------------------------------------------


def _tlv(buf: bytes, offset: int) -> tuple[int, int, int]:
    if offset + 2 > len(buf):
        raise ValueError("truncated")
    tag = buf[offset]
    length = buf[offset + 1]
    start = offset + 2
    if length & 0x80:
        n = length & 0x7F
        if n < 1 or n > 4 or start + n > len(buf):
            raise ValueError("bad length")
        length = int.from_bytes(buf[start : start + n], "big")
        start += n
    end = start + length
    if end > len(buf):
        raise ValueError("truncated")
    return tag, start, end


def extension_text(value: bytes | None) -> str:
    """Fulcio writes its newer extensions as a DER UTF8String and the oldest ones as raw text."""

    if not value:
        return ""
    if value[0] == 0x0C:
        try:
            _, start, end = _tlv(value, 0)
            return value[start:end].decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            pass
    return value.decode("utf-8", errors="replace")


def certificate_extensions(cert: x509.Certificate) -> dict[str, bytes]:
    """A certificate's extensions: {OID: the extension's value bytes}."""

    out: dict[str, bytes] = {}
    for ext in cert.extensions:
        value = ext.value
        raw = value.value if isinstance(value, x509.UnrecognizedExtension) else value.public_bytes()
        out[ext.oid.dotted_string] = raw
    return out


# ---- Pieces of the check -----------------------------------------------------------------------------------------


def pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE's pre-authentication encoding: what the signature is over."""

    kind = payload_type.encode("utf-8")
    return b"DSSEv1 " + str(len(kind)).encode() + b" " + kind + b" " + str(len(payload)).encode() + b" " + payload


def key_of(raw_bytes_b64: str):
    return load_der_public_key(b64(raw_bytes_b64))


def verify_with(key, data: bytes, signature: bytes) -> bool:
    try:
        if isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(signature, data)
        elif isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            return False
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def _issued_by(cert: x509.Certificate, issuer: x509.Certificate) -> bool:
    try:
        cert.verify_directly_issued_by(issuer)
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False


def chain_to_trust_root(leaf: x509.Certificate, signed_at: float, trusted_root: dict[str, Any]) -> bool:
    """The certificate authority in the trust root that issued ``leaf``, checked link by link to its root."""

    for ca in trusted_root.get("certificateAuthorities") or []:
        valid_for = ca.get("validFor") or {}
        start = _parse_time(valid_for.get("start")) or 0
        end = _parse_time(valid_for.get("end")) if valid_for.get("end") else float("inf")
        if not (start <= signed_at <= (end if end is not None else float("inf"))):
            continue
        try:
            chain = [x509.load_der_x509_certificate(b64(c.get("rawBytes"))) for c in (ca.get("certChain") or {}).get("certificates") or []]
        except ValueError:
            continue
        if not chain or not _issued_by(leaf, chain[0]):
            continue
        linked = True
        for i, cert in enumerate(chain):
            issuer = chain[i + 1] if i + 1 < len(chain) else cert  # the last is the root, signed by itself
            if not _issued_by(cert, issuer):
                linked = False
        if linked:
            return True
    return False


def root_from_inclusion_proof(index: Any, size: Any, leaf_hash: bytes, proof: list[bytes]) -> bytes | None:
    """RFC 9162: the root a leaf's inclusion proof leads to."""

    fn = int(index)
    sn = int(size) - 1
    if fn > sn:
        return None
    r = leaf_hash
    for p in proof:
        if sn == 0:
            return None
        if fn & 1 == 1 or fn == sn:
            r = _sha256(b"\x01" + p + r)
            if fn & 1 == 0:
                while not (fn & 1 == 1 or fn == 0):
                    fn >>= 1
                    sn >>= 1
        else:
            r = _sha256(b"\x01" + r + p)
        fn >>= 1
        sn >>= 1
    return r if sn == 0 else None


def checkpoint_root(envelope: str, key) -> bytes | None:
    """A signed checkpoint (a signed note): its root hash when one of its signatures is the log's."""

    split = envelope.find("\n\n")
    if split < 0:
        return None
    body = envelope[: split + 1]
    lines = body.split("\n")
    if len(lines) < 3:
        return None
    root = b64(lines[2])
    for line in envelope[split + 2 :].split("\n"):
        match = re.match(r"^— (\S+) (\S+)$", line)
        if not match:
            continue
        sig = b64(match.group(2))[4:]  # a 4-byte key hint first
        if verify_with(key, body.encode("utf-8"), sig):
            return root
    return None


def _strings(value: Any, out: list[str] | None = None) -> list[str]:
    """Every string anywhere in a JSON value."""

    out = [] if out is None else out
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for v in value.values():
            _strings(v, out)
    elif isinstance(value, list):
        for v in value:
            _strings(v, out)
    return out


def _entry_is_ours(body_bytes: bytes, payload: bytes, leaf_der: bytes) -> bool:
    """The log entry is this signature's: it carries the payload's hash and the signing certificate."""

    try:
        body = json.loads(body_bytes.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        return False
    digest = _sha256(payload)
    found = _strings(body)
    hashed = any(s in (digest.hex(), base64.b64encode(digest).decode()) for s in found)
    cert_b64 = base64.b64encode(leaf_der).decode()

    def certified(s: str) -> bool:
        if s == cert_b64:
            return True
        text = b64(s).decode("utf-8", errors="replace")
        return "BEGIN CERTIFICATE" in text and re.sub(r"-----[^-]+-----|\s", "", text) == cert_b64

    return hashed and any(certified(s) for s in found)


def _logged(entry: dict[str, Any], payload: bytes, leaf_der: bytes, trusted_root: dict[str, Any]) -> str:
    key_id = (entry.get("logId") or {}).get("keyId")
    log = next((t for t in trusted_root.get("tlogs") or [] if (t.get("logId") or {}).get("keyId") == key_id), None)
    if not log:
        return "the transparency log that recorded it is not one this server trusts"
    key = key_of(log["publicKey"]["rawBytes"])
    body = b64(entry.get("canonicalizedBody"))
    if not _entry_is_ours(body, payload, leaf_der):
        return "the transparency log record is not of this signature"
    signed_entry_timestamp = (entry.get("inclusionPromise") or {}).get("signedEntryTimestamp")
    if signed_entry_timestamp:
        signed = json.dumps(
            {"body": entry.get("canonicalizedBody"), "integratedTime": int(entry.get("integratedTime")), "logID": b64(key_id).hex(), "logIndex": int(entry.get("logIndex"))},
            separators=(",", ":"),
        )
        if verify_with(key, signed.encode("utf-8"), b64(signed_entry_timestamp)):
            return ""
    proof = entry.get("inclusionProof") or {}
    envelope = (proof.get("checkpoint") or {}).get("envelope")
    if envelope:
        root = root_from_inclusion_proof(proof.get("logIndex"), proof.get("treeSize"), _sha256(b"\x00" + body), [b64(h) for h in proof.get("hashes") or []])
        signed_root = checkpoint_root(envelope, key)
        if root and signed_root and root == signed_root and root == b64(proof.get("rootHash")):
            return ""
    return "the transparency log did not confirm it"


# ---- The whole check ---------------------------------------------------------------------------------------------


def verify_bundle(
    bundle: Any,
    *,
    digest: str,
    trusted_root: dict[str, Any],
    repository: str,
    workflow: str = RELEASE_WORKFLOW,
    refs: re.Pattern[str] = RELEASE_REFS,
) -> dict[str, Any]:
    """
    bundle      a Sigstore bundle (as GitHub's attestations API returns it)
    digest      the SHA-256 (hex) of the file or image it must be about
    repository  "owner/name" of the repository whose workflow must have signed it
    workflow    that workflow's path in the repository
    refs        which git refs may have built it
    """

    try:
        if not isinstance(bundle, dict) or not str(bundle.get("mediaType") or "").startswith("application/vnd.dev.sigstore.bundle"):
            return fail("not a Sigstore bundle")
        material = bundle.get("verificationMaterial") or {}
        cert_b64 = (material.get("certificate") or {}).get("rawBytes") or (((material.get("x509CertificateChain") or {}).get("certificates") or [{}])[0]).get("rawBytes")
        if not cert_b64:
            return fail("no signing certificate")
        leaf_der = b64(cert_b64)
        leaf = x509.load_der_x509_certificate(leaf_der)
        entry = (material.get("tlogEntries") or [None])[0]
        try:
            signed_at = float(entry.get("integratedTime")) * 1000 if entry else float("nan")
        except (TypeError, ValueError):
            signed_at = float("nan")
        if not entry or not signed_at == signed_at or signed_at <= 0:  # NaN never equals itself
            return fail("no transparency log time")

        # 1. Issued by Sigstore, valid when it was used.
        if not chain_to_trust_root(leaf, signed_at, trusted_root):
            return fail("the signing certificate was not issued by Sigstore")
        if signed_at < _ms(leaf.not_valid_before_utc) or signed_at > _ms(leaf.not_valid_after_utc):
            return fail("the signing certificate was not valid when it was used")

        # 2. Who signed: this repository's release workflow on GitHub Actions.
        ext = certificate_extensions(leaf)
        issuer = extension_text(ext.get(OID["issuerV2"])) or extension_text(ext.get(OID["issuerV1"]))
        if issuer != ISSUER:
            return fail("not signed by GitHub Actions")
        repo_uri = extension_text(ext.get(OID["sourceRepositoryUri"]))
        wanted = f"https://github.com/{repository}"
        if repo_uri.lower() != wanted.lower():
            return fail(f"built from {repo_uri or 'another repository'}, not {wanted}")
        ref = extension_text(ext.get(OID["sourceRepositoryRef"]))
        signer = extension_text(ext.get(OID["buildSignerUri"]))
        if not signer:
            try:
                san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
                signer = next(iter(san.get_values_for_type(x509.UniformResourceIdentifier)), "")
            except x509.ExtensionNotFound:
                signer = ""
        if not signer.lower().startswith(f"{wanted}/{workflow}@".lower()):
            return fail(f"signed by {signer or 'an unknown workflow'}, not {workflow}")
        if not refs.match(ref):
            return fail(f"built from {ref or 'an unknown ref'}, not main or a version tag")

        # 3. The signature.
        envelope = bundle.get("dsseEnvelope") or {}
        if not envelope.get("payload") or not envelope.get("signatures"):
            return fail("no signed attestation")
        payload = b64(envelope["payload"])
        signed = any(verify_with(leaf.public_key(), pae(str(envelope.get("payloadType") or ""), payload), b64(s.get("sig"))) for s in envelope["signatures"])
        if not signed:
            return fail("the signature does not match")

        # 4. About these bytes.
        statement = json.loads(payload.decode("utf-8"))
        if not any(isinstance(s, dict) and (s.get("digest") or {}).get("sha256") == digest for s in statement.get("subject") or []):
            return fail("the attestation is about other files")

        # 5. In the public log.
        not_logged = _logged(entry, payload, leaf_der, trusted_root)
        if not_logged:
            return fail(not_logged)

        return {
            "ok": True,
            "signedAt": dt.datetime.fromtimestamp(signed_at / 1000, dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "repository": repo_uri.replace("https://github.com/", ""),
            "ref": ref,
            "commit": extension_text(ext.get(OID["sourceRepositoryDigest"])),
            "workflow": signer,
            "run": extension_text(ext.get(OID["runInvocationUri"])),
            "logIndex": int(entry.get("logIndex")),
        }
    except Exception as error:  # noqa: BLE001 - anything unreadable is "not verified", with why
        return fail(f"the attestation could not be read ({error})")
