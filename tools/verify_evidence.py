#!/usr/bin/env python3
"""Check Hawk AI evidence offline, with the public key alone (Python 3.9+ and the ``cryptography`` package).

Hawk AI signs the evidence it hands out (app/services/evidence_signing.py, ``hawk-evidence-signature/v1``) with a key
that never leaves the server or its key service. Nothing here needs the server, an account or a secret: only the
public keys, saved from <server>/.well-known/hawk-evidence-keys.json (or Settings -> Audit log -> Evidence signing),
or one public key as a PEM file.

  # A JSON document with its signature inside (the auditor export's evidence pack, its signed manifest):
  python3 tools/verify_evidence.py audit_evidence_pack_....json --keys hawk-evidence-keys.json

  # The signed manifest of an auditor export, and every file it lists (looked for beside the manifest, or in --dir):
  python3 tools/verify_evidence.py audit_export_manifest_....json --keys hawk-evidence-keys.json --dir ./export

  # A file with a detached signature (an audit log export and its .sig.json, or the X-Hawk-Evidence-Signature header):
  python3 tools/verify_evidence.py audit-2026-11-26.jsonl --signature audit-2026-11-26.jsonl.sig.json --keys key.pem

Exit status: 0 when every check passes, 1 when one fails, 2 when the command is wrong. ``--json`` prints the result
as JSON.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

FORMAT = "hawk-evidence-signature/v1"
MANIFEST_FORMAT = "hawk-evidence-manifest/v1"
SIGNATURE_FIELD = "evidence_signature"


def b64url_decode(text: str) -> bytes:
    value = str(text or "").strip()
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def fingerprint(public_key: Any) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _key_from_jwk(entry: Mapping[str, Any]) -> Any:
    if entry.get("public_key_pem"):
        return serialization.load_pem_public_key(str(entry["public_key_pem"]).encode("ascii"))
    if entry.get("kty") == "OKP" and entry.get("crv") == "Ed25519":
        return ed25519.Ed25519PublicKey.from_public_bytes(b64url_decode(entry["x"]))
    if entry.get("kty") == "EC" and entry.get("crv") == "P-256":
        x = int.from_bytes(b64url_decode(entry["x"]), "big")
        y = int.from_bytes(b64url_decode(entry["y"]), "big")
        return ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
    raise ValueError(f"Unsupported key {entry.get('kid')}: {entry.get('kty')} {entry.get('crv')}")


def load_keys(path: Path) -> Dict[str, Dict[str, Any]]:
    """{kid: {"alg", "key", "status"}} from the published key list (JSON) or one PEM public key. The key id is always
    worked out from the key itself, so a list cannot pass one key off under another's id."""

    data = path.read_bytes()
    keys: Dict[str, Dict[str, Any]] = {}
    if data.lstrip().startswith(b"-----BEGIN"):
        key = serialization.load_pem_public_key(data)
        alg = "EdDSA" if isinstance(key, ed25519.Ed25519PublicKey) else "ES256"
        keys[fingerprint(key)] = {"alg": alg, "key": key, "status": "given"}
        return keys
    listing = json.loads(data)
    for entry in listing.get("keys", []) if isinstance(listing, dict) else []:
        key = _key_from_jwk(entry)
        kid = fingerprint(key)
        if entry.get("kid") and entry["kid"] != kid:
            raise ValueError(f"The key list names a key {entry['kid']} whose fingerprint is {kid}.")
        keys[kid] = {"alg": entry.get("alg") or ("EdDSA" if isinstance(key, ed25519.Ed25519PublicKey) else "ES256"), "key": key, "status": entry.get("status") or ""}
    return keys


def verify_signature(public_key: Any, alg: str, message: bytes, signature: bytes) -> bool:
    try:
        if alg == "EdDSA" and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, message)
            return True
        if alg == "ES256" and isinstance(public_key, ec.EllipticCurvePublicKey) and len(signature) == 64:
            der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
            public_key.verify(der, message, ec.ECDSA(hashes.SHA256()))
            return True
    except InvalidSignature:
        return False
    return False


def check(envelope: Mapping[str, Any], digest: str, keys: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"valid": False, "kid": envelope.get("kid"), "alg": envelope.get("alg"), "signed_at": envelope.get("signed_at"), "artifact": envelope.get("artifact")}
    if envelope.get("format") != FORMAT or envelope.get("digest_alg") != "sha256":
        return {**out, "reason": f"not a {FORMAT} signature"}
    if not hmac.compare_digest(str(envelope.get("digest") or ""), digest):
        return {**out, "reason": "the evidence was changed after it was signed (digest mismatch)"}
    key = keys.get(str(envelope.get("kid") or ""))
    if not key:
        return {**out, "reason": "signed with a key that is not in the given keys"}
    if key["alg"] != envelope.get("alg"):
        return {**out, "reason": "the signature's algorithm does not match its key"}
    unsigned = {k: v for k, v in envelope.items() if k != "signature"}
    try:
        signature = b64url_decode(str(envelope.get("signature") or ""))
    except ValueError:
        return {**out, "reason": "the signature is malformed"}
    if not verify_signature(key["key"], str(envelope["alg"]), canonical_json(unsigned), signature):
        return {**out, "reason": "the signature does not verify"}
    return {**out, "valid": True, "reason": "valid", "key_status": key.get("status") or ""}


def verify_document(document: Mapping[str, Any], keys: Mapping[str, Mapping[str, Any]]) -> Dict[str, Any]:
    envelope = document.get(SIGNATURE_FIELD)
    if not isinstance(envelope, Mapping):
        return {"valid": False, "reason": "the document carries no evidence_signature"}
    body = {k: v for k, v in document.items() if k != SIGNATURE_FIELD}
    return check(envelope, hashlib.sha256(canonical_json(body)).hexdigest(), keys)


def verify_manifest_files(manifest: Mapping[str, Any], directory: Path) -> Dict[str, Any]:
    files: Dict[str, Any] = {}
    for name, item in sorted((manifest.get("files") or {}).items()):
        path = directory / Path(str(item.get("path") or "")).name
        if not path.is_file():
            files[name] = {"valid": False, "reason": f"{path.name} not found in {directory}"}
            continue
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        ok = hmac.compare_digest(actual, str(item.get("sha256") or ""))
        files[name] = {"valid": ok, "reason": "unchanged" if ok else "changed since it was signed (sha256 mismatch)", "path": path.name}
    return files


def read_signature(value: str) -> Dict[str, Any]:
    text = value.strip()
    if not text.startswith("{"):
        try:  # a file, or else the header's value itself (too long to be a file name, or no such file)
            if Path(value).is_file():
                text = Path(value).read_text(encoding="utf-8").strip()
        except OSError:
            pass
    if text.startswith("{"):
        return json.loads(text)
    return json.loads(b64url_decode(text))  # the X-Hawk-Evidence-Signature header's value


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description="Check Hawk AI evidence offline with its public key.")
    parser.add_argument("evidence", help="the evidence file: a signed JSON document, a signed manifest, or any file with --signature")
    parser.add_argument("--keys", required=True, help="the public keys: hawk-evidence-keys.json, or one public key as PEM")
    parser.add_argument("--signature", help="a detached signature: a .sig.json file, or the X-Hawk-Evidence-Signature header value")
    parser.add_argument("--dir", help="where the files a signed manifest lists are (default: beside the manifest)")
    parser.add_argument("--json", action="store_true", help="print the result as JSON")
    args = parser.parse_args(argv)

    try:
        keys = load_keys(Path(args.keys))
        evidence_path = Path(args.evidence)
        data = evidence_path.read_bytes()
        files: Dict[str, Any] = {}
        if args.signature:
            result = check(read_signature(args.signature), hashlib.sha256(data).hexdigest(), keys)
        else:
            document = json.loads(data)
            if not isinstance(document, dict):
                raise ValueError("The evidence is not a signed JSON document; give its detached signature with --signature.")
            result = verify_document(document, keys)
            if document.get("format") == MANIFEST_FORMAT:
                files = verify_manifest_files(document, Path(args.dir) if args.dir else evidence_path.parent)
    except (OSError, ValueError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    ok = bool(result.get("valid")) and all(f["valid"] for f in files.values())
    if args.json:
        print(json.dumps({"valid": ok, "signature": result, "files": files}, indent=2))
    else:
        mark = "OK " if result.get("valid") else "BAD"
        print(f"{mark} signature: {result.get('reason')} (key {str(result.get('kid') or '?')[:16]}…, {result.get('alg')}, signed {result.get('signed_at')})")
        for name, item in files.items():
            print(f"{'OK ' if item['valid'] else 'BAD'} {name}: {item['reason']}")
        print("Valid." if ok else "NOT valid.")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
