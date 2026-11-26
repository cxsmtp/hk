"""Evidence signing: asymmetric signatures on the evidence Hawk AI hands to auditors and regulators.

The audit log's own chain (app/services/audit_chain.py) is an HMAC: whoever can check it can also forge it, which is
fine for the server's internal integrity but not for evidence that leaves the system. Evidence that leaves is signed
here with a private key nobody else holds, and anyone can check it offline with the public key alone
(tools/verify_evidence.py, or POST /evidence-signing/verify).

Backends (EVIDENCE_SIGNING_BACKEND):

- ``local`` (default): an Ed25519 key made once per installation and kept in the data folder
  (``evidence-signing.json``, 0600). It is in every backup (app/services/backup_archive.py carries the data folder), so
  a restored server signs with the same key and every signature it made stays verifiable.
- ``aws_kms``: an asymmetric AWS KMS key (key spec ECC_NIST_P256, usage SIGN_VERIFY), ECDSA_SHA_256 over a digest.
  Called with plain HTTPS and Signature Version 4 made here (no boto3). Credentials come from
  EVIDENCE_SIGNING_AWS_ACCESS_KEY_ID / EVIDENCE_SIGNING_AWS_SECRET_ACCESS_KEY (or its _FILE) /
  EVIDENCE_SIGNING_AWS_SESSION_TOKEN, else the standard AWS_* variables. Limitation: instance roles (EC2 IMDS, ECS
  task roles, web identity) are not read; give static or session credentials.
- ``azure_kv``: an Azure Key Vault (or Managed HSM) EC key on P-256, ES256. The key URL may name a version; without one
  the latest version is used and a new version in Key Vault is picked up by "Rotate". The token comes from the client
  credentials of an app registration (EVIDENCE_SIGNING_AZURE_TENANT_ID / _CLIENT_ID / _CLIENT_SECRET). Limitation:
  managed identities are not read.
- ``gcp_kms``: a Cloud KMS key version with algorithm EC_SIGN_P256_SHA256, from a service account's JSON key
  (EVIDENCE_SIGNING_GCP_CREDENTIALS_JSON, or its _FILE). Limitation: workload identity / the metadata server is not read.

Every call to a cloud goes through the outbound HTTPS client (trust store: app/services/trust_store.py; the company
proxy is in each process's environment: app/services/network_proxy.py) and is recorded in the connector API activity.

Keys and rotation: every key ever used is in the keyring (``evidence-signing.json``), named by its key id, which is the
SHA-256 fingerprint of its public key (SubjectPublicKeyInfo, DER). Rotating makes a new local key (the old private key
is destroyed, its public key kept) or, for a cloud key, reads the configured key again and keeps the old public key when
it changed. Moving to another backend retires the previous key the same way. Old public keys are published
(GET /.well-known/hawk-evidence-keys.json) with their status, so evidence signed before a rotation stays verifiable.

What a signature is (``hawk-evidence-signature/v1``): a JSON envelope

    {"format", "alg" (EdDSA | ES256), "kid", "digest_alg": "sha256", "digest", "artifact", "signed_at", "signature"}

where ``digest`` is the SHA-256 of the evidence and ``signature`` (base64url, ECDSA as raw r||s as in JWS) is over the
canonical JSON of the envelope without ``signature`` (keys sorted, no spaces, UTF-8). For ES256 that is signed as its
SHA-256 digest. The evidence is either

- bytes (a file, a CSV): the envelope travels beside it (``<file>.sig.json``, or the ``X-Hawk-Evidence-Signature``
  header: base64url of the envelope's canonical JSON); or
- a JSON document: the envelope is inside it, under ``evidence_signature``, and the digest is over the canonical JSON of
  the document without that member.
"""

from __future__ import annotations

import base64
import contextlib
import datetime as dt
import hashlib
import hmac
import json
import os
import threading
import time
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import quote, urlsplit

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature

try:  # pragma: no cover - always there on Linux, where Hawk AI runs
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None  # type: ignore[assignment]

FORMAT = "hawk-evidence-signature/v1"
KEYS_FORMAT = "hawk-evidence-keys/v1"
KEYRING_FILE = "evidence-signing.json"
LOCK_FILE = "evidence-signing.lock"
SIGNATURE_FIELD = "evidence_signature"
HEADER = "X-Hawk-Evidence-Signature"
STATUS_HEADER = "X-Hawk-Evidence-Signature-Status"
WELL_KNOWN_PATH = "/.well-known/hawk-evidence-keys.json"
BACKENDS = ("local", "aws_kms", "azure_kv", "gcp_kms")
EDDSA = "EdDSA"
ES256 = "ES256"
ALGORITHMS = (EDDSA, ES256)
HTTP_TIMEOUT = httpx.Timeout(20.0, connect=10.0)
AZURE_API_VERSION = "7.4"
GCP_SCOPE = "https://www.googleapis.com/auth/cloudkms"
BACKEND_LABELS = {"local": "Local key (data folder)", "aws_kms": "AWS KMS", "azure_kv": "Azure Key Vault", "gcp_kms": "Google Cloud KMS"}


class EvidenceSigningError(RuntimeError):
    """Evidence could not be signed (or the keys read): the message says what to do."""


class EvidenceSigningConfigError(EvidenceSigningError):
    """The signing settings are incomplete or wrong."""


# ---------------------------------------------------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------------------------------------------------


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    value = str(text or "").strip()
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def canonical_json(value: Any) -> bytes:
    """Keys sorted, no spaces, UTF-8: the same bytes whatever the order a document was written or read in."""

    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def plain_json(value: Any) -> Any:
    """The document as a reader of the exported JSON sees it (datetimes and the like as their text)."""

    return json.loads(json.dumps(value, default=str))


def _now_iso(now: dt.datetime | None = None) -> str:
    moment = now or dt.datetime.now(dt.timezone.utc)
    return moment.astimezone(dt.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def public_key_der(public_key: Any) -> bytes:
    return public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)


def public_key_pem(public_key: Any) -> str:
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")


def fingerprint(public_key: Any) -> str:
    """The key id: SHA-256 of the public key (SubjectPublicKeyInfo, DER), hex."""

    return hashlib.sha256(public_key_der(public_key)).hexdigest()


def algorithm_for(public_key: Any) -> str:
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return EDDSA
    if isinstance(public_key, ec.EllipticCurvePublicKey) and isinstance(public_key.curve, ec.SECP256R1):
        return ES256
    raise EvidenceSigningConfigError("The signing key must be Ed25519 or ECDSA on P-256 (ECC_NIST_P256, EC P-256, EC_SIGN_P256_SHA256).")


def load_public_key(pem_or_der: str | bytes) -> Any:
    data = pem_or_der.encode("ascii") if isinstance(pem_or_der, str) else pem_or_der
    if data.lstrip().startswith(b"-----BEGIN"):
        return serialization.load_pem_public_key(data)
    return serialization.load_der_public_key(data)


def raw_ecdsa(der_signature: bytes) -> bytes:
    r, s = decode_dss_signature(der_signature)
    return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def der_ecdsa(raw_signature: bytes) -> bytes:
    if len(raw_signature) != 64:
        raise ValueError("An ES256 signature is 64 bytes (r||s).")
    return encode_dss_signature(int.from_bytes(raw_signature[:32], "big"), int.from_bytes(raw_signature[32:], "big"))


def jwk(public_key: Any) -> dict[str, str]:
    """The public key as a JSON Web Key (RFC 7517 / 8037)."""

    if isinstance(public_key, ed25519.Ed25519PublicKey):
        raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        return {"kty": "OKP", "crv": "Ed25519", "x": b64url(raw)}
    numbers = public_key.public_numbers()
    return {"kty": "EC", "crv": "P-256", "x": b64url(numbers.x.to_bytes(32, "big")), "y": b64url(numbers.y.to_bytes(32, "big"))}


def verify_raw(public_key: Any, alg: str, message: bytes, signature: bytes) -> bool:
    """Does ``signature`` (raw: 64 bytes for both algorithms) sign ``message`` with this key?"""

    try:
        if alg == EDDSA and isinstance(public_key, ed25519.Ed25519PublicKey):
            public_key.verify(signature, message)
            return True
        if alg == ES256 and isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(der_ecdsa(signature), message, ec.ECDSA(hashes.SHA256()))
            return True
    except (InvalidSignature, ValueError):
        return False
    return False


def unsigned_envelope(envelope: Mapping[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in envelope.items() if k != "signature"}


def document_digest(document: Mapping[str, Any]) -> str:
    """The digest a JSON document's embedded signature covers: the document without ``evidence_signature``."""

    body = {k: v for k, v in plain_json(dict(document)).items() if k != SIGNATURE_FIELD}
    return hashlib.sha256(canonical_json(body)).hexdigest()


def encode_header(envelope: Mapping[str, Any]) -> str:
    return b64url(canonical_json(dict(envelope)))


def decode_header(value: str) -> dict[str, Any]:
    try:
        decoded = json.loads(b64url_decode(value))
    except (ValueError, UnicodeDecodeError) as error:
        raise ValueError("The signature header is not a Hawk AI evidence signature.") from error
    if not isinstance(decoded, dict):
        raise ValueError("The signature header is not a Hawk AI evidence signature.")
    return decoded


# ---------------------------------------------------------------------------------------------------------------------
# Signers: what holds the private key
# ---------------------------------------------------------------------------------------------------------------------


class Signer:
    backend = ""
    alg = ""

    def public_key(self) -> tuple[Any, str]:
        """The public key and the name of the exact key that signs (ARN, versioned key URL, key version)."""

        raise NotImplementedError

    def sign(self, message: bytes) -> bytes:
        """The raw signature over ``message`` (Ed25519: 64 bytes; ES256: r||s over SHA-256(message))."""

        raise NotImplementedError


class LocalSigner(Signer):
    backend = "local"
    alg = EDDSA

    def __init__(self, private_key: ed25519.Ed25519PrivateKey) -> None:
        self._key = private_key

    def public_key(self) -> tuple[Any, str]:
        return self._key.public_key(), "local"

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def http_client() -> httpx.Client:
    """The outbound HTTPS client: the trust store's roots and the administrator's extra ones, the company proxy from the
    environment, no redirects, and every call in the connector API activity."""

    from app.services import connector_activity, trust_store

    return httpx.Client(verify=trust_store.outbound_ssl_context(), timeout=HTTP_TIMEOUT, follow_redirects=False, event_hooks=connector_activity.httpx_hooks("evidence signing"))


ClientFactory = Callable[[], httpx.Client]


def _https_url(value: str, *, what: str) -> str:
    parts = urlsplit(str(value or "").strip())
    if parts.scheme != "https" or not parts.hostname:
        raise EvidenceSigningConfigError(f"{what} must be an https address.")
    return parts.geturl()


def _cloud_error(service: str, response: httpx.Response) -> EvidenceSigningError:
    detail = ""
    try:
        body = response.json()
        if isinstance(body, dict):
            error = body.get("error")
            if isinstance(error, dict):
                detail = str(error.get("message") or error.get("code") or "")
            elif error:
                detail = str(body.get("error_description") or error)
            detail = detail or str(body.get("message") or body.get("Message") or body.get("__type") or "")
    except ValueError:
        detail = ""
    return EvidenceSigningError(f"{service} answered {response.status_code}{': ' + detail[:300] if detail else ''}.")


class _RemoteSigner(Signer):
    alg = ES256
    service = ""

    def __init__(self, client_factory: ClientFactory | None = None) -> None:
        self._client_factory = client_factory or http_client
        self._token: tuple[str, float] | None = None

    def _request(self, method: str, url: str, **kwargs: Any) -> Any:
        try:
            with self._client_factory() as client:
                response = client.request(method, url, **kwargs)
        except httpx.HTTPError as error:
            raise EvidenceSigningError(f"{self.service} could not be reached: {error.__class__.__name__}. Check Settings → Network & proxy.") from error
        if response.status_code >= 400:
            raise _cloud_error(self.service, response)
        try:
            return response.json()
        except ValueError as error:
            raise EvidenceSigningError(f"{self.service} did not answer with JSON.") from error


# ---- AWS KMS --------------------------------------------------------------------------------------------------------


def sigv4_headers(
    *,
    method: str,
    url: str,
    region: str,
    service: str,
    body: bytes,
    access_key: str,
    secret_key: str,
    session_token: str = "",
    extra: Mapping[str, str] | None = None,
    now: dt.datetime | None = None,
) -> dict[str, str]:
    """AWS Signature Version 4 for one request (no query string), as https://docs.aws.amazon.com/IAM/latest/UserGuide/
    reference_sigv4-signing-request.html describes it. Returns every header to send."""

    moment = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    amz_date = moment.strftime("%Y%m%dT%H%M%SZ")
    datestamp = moment.strftime("%Y%m%d")
    parts = urlsplit(url)
    headers = {"host": parts.netloc, "x-amz-date": amz_date, **{k.lower(): str(v).strip() for k, v in (extra or {}).items()}}
    if session_token:
        headers["x-amz-security-token"] = session_token
    names = sorted(headers)
    canonical_headers = "".join(f"{name}:{' '.join(headers[name].split())}\n" for name in names)
    signed_headers = ";".join(names)
    payload_hash = hashlib.sha256(body).hexdigest()
    canonical_request = "\n".join([method.upper(), quote(parts.path or "/", safe="/-_.~"), "", canonical_headers, signed_headers, payload_hash])
    scope = f"{datestamp}/{region}/{service}/aws4_request"
    string_to_sign = "\n".join(["AWS4-HMAC-SHA256", amz_date, scope, hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()])

    def _hmac(key: bytes, text: str) -> bytes:
        return hmac.new(key, text.encode("utf-8"), hashlib.sha256).digest()

    key = _hmac(_hmac(_hmac(_hmac(f"AWS4{secret_key}".encode("utf-8"), datestamp), region), service), "aws4_request")
    signature = hmac.new(key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()
    headers["authorization"] = f"AWS4-HMAC-SHA256 Credential={access_key}/{scope}, SignedHeaders={signed_headers}, Signature={signature}"
    return headers


class AwsKmsSigner(_RemoteSigner):
    backend = "aws_kms"
    service = "AWS KMS"

    def __init__(self, *, key_id: str, region: str, access_key: str, secret_key: str, session_token: str = "", endpoint: str = "", client_factory: ClientFactory | None = None) -> None:
        super().__init__(client_factory)
        self.key_id = key_id
        self.region = region
        self.access_key = access_key
        self.secret_key = secret_key
        self.session_token = session_token
        self.endpoint = endpoint or f"https://kms.{region}.amazonaws.com/"

    def call(self, action: str, payload: Mapping[str, Any]) -> dict[str, Any]:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = sigv4_headers(
            method="POST",
            url=self.endpoint,
            region=self.region,
            service="kms",
            body=body,
            access_key=self.access_key,
            secret_key=self.secret_key,
            session_token=self.session_token,
            extra={"content-type": "application/x-amz-json-1.1", "x-amz-target": f"TrentService.{action}"},
        )
        headers.pop("host", None)  # httpx sends the same Host itself
        return self._request("POST", self.endpoint, content=body, headers=headers)

    def public_key(self) -> tuple[Any, str]:
        answer = self.call("GetPublicKey", {"KeyId": self.key_id})
        if answer.get("KeyUsage") not in (None, "SIGN_VERIFY") or answer.get("KeySpec") not in (None, "ECC_NIST_P256"):
            raise EvidenceSigningConfigError(f"The AWS KMS key {self.key_id} must be an asymmetric ECC_NIST_P256 key for SIGN_VERIFY (it is {answer.get('KeySpec')}, {answer.get('KeyUsage')}).")
        key = load_public_key(base64.b64decode(str(answer.get("PublicKey") or "")))
        algorithm_for(key)
        return key, str(answer.get("KeyId") or self.key_id)

    def sign(self, message: bytes) -> bytes:
        digest = hashlib.sha256(message).digest()
        answer = self.call("Sign", {"KeyId": self.key_id, "Message": base64.b64encode(digest).decode("ascii"), "MessageType": "DIGEST", "SigningAlgorithm": "ECDSA_SHA_256"})
        return raw_ecdsa(base64.b64decode(str(answer.get("Signature") or "")))


# ---- Azure Key Vault ------------------------------------------------------------------------------------------------


class AzureKeyVaultSigner(_RemoteSigner):
    backend = "azure_kv"
    service = "Azure Key Vault"

    def __init__(self, *, key_url: str, tenant_id: str, client_id: str, client_secret: str, authority_host: str = "https://login.microsoftonline.com", client_factory: ClientFactory | None = None) -> None:
        super().__init__(client_factory)
        self.key_url = key_url.rstrip("/")
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.authority_host = authority_host.rstrip("/")
        host = urlsplit(self.key_url).hostname or ""
        # https://<vault>.vault.azure.net -> https://vault.azure.net/.default (the same for Managed HSM and other clouds).
        self.scope = f"https://{host.split('.', 1)[1] if '.' in host else host}/.default"
        self._versioned = ""

    def token(self) -> str:
        if self._token and self._token[1] > time.time() + 60:
            return self._token[0]
        answer = self._request(
            "POST",
            f"{self.authority_host}/{quote(self.tenant_id, safe='')}/oauth2/v2.0/token",
            data={"grant_type": "client_credentials", "client_id": self.client_id, "client_secret": self.client_secret, "scope": self.scope},
        )
        token = str(answer.get("access_token") or "")
        if not token:
            raise EvidenceSigningError("Microsoft Entra ID gave no access token for Key Vault.")
        self._token = (token, time.time() + float(answer.get("expires_in") or 300))
        return token

    def public_key(self) -> tuple[Any, str]:
        answer = self._request("GET", f"{self.key_url}?api-version={AZURE_API_VERSION}", headers={"Authorization": f"Bearer {self.token()}"})
        key = answer.get("key") if isinstance(answer.get("key"), dict) else {}
        if key.get("kty") not in ("EC", "EC-HSM") or key.get("crv") != "P-256":
            raise EvidenceSigningConfigError(f"The Key Vault key must be an EC key on P-256 (it is {key.get('kty')}, {key.get('crv')}).")
        numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(b64url_decode(key["x"]), "big"), int.from_bytes(b64url_decode(key["y"]), "big"), ec.SECP256R1())
        self._versioned = str(key.get("kid") or self.key_url)
        return numbers.public_key(), self._versioned

    def use_version(self, versioned_kid: str) -> None:
        self._versioned = versioned_kid

    def sign(self, message: bytes) -> bytes:
        target = self._versioned or self.key_url
        answer = self._request(
            "POST",
            f"{target}/sign?api-version={AZURE_API_VERSION}",
            json={"alg": "ES256", "value": b64url(hashlib.sha256(message).digest())},
            headers={"Authorization": f"Bearer {self.token()}"},
        )
        return b64url_decode(str(answer.get("value") or ""))


# ---- Google Cloud KMS -----------------------------------------------------------------------------------------------


class GcpKmsSigner(_RemoteSigner):
    backend = "gcp_kms"
    service = "Google Cloud KMS"
    api = "https://cloudkms.googleapis.com/v1"

    def __init__(self, *, key_version: str, credentials: Mapping[str, Any], client_factory: ClientFactory | None = None) -> None:
        super().__init__(client_factory)
        self.key_version = key_version.strip("/")
        self.credentials = dict(credentials)

    def assertion(self, now: float | None = None) -> str:
        issued = int(now if now is not None else time.time())
        header = {"alg": "RS256", "typ": "JWT"}
        token_uri = str(self.credentials.get("token_uri") or "https://oauth2.googleapis.com/token")
        claims = {"iss": self.credentials.get("client_email"), "scope": GCP_SCOPE, "aud": token_uri, "iat": issued, "exp": issued + 3600}
        signing_input = f"{b64url(canonical_json(header))}.{b64url(canonical_json(claims))}".encode("ascii")
        try:
            private_key = serialization.load_pem_private_key(str(self.credentials.get("private_key") or "").encode("utf-8"), password=None)
        except ValueError as error:
            raise EvidenceSigningConfigError("The Google service account key (EVIDENCE_SIGNING_GCP_CREDENTIALS_JSON) holds no usable private key.") from error
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise EvidenceSigningConfigError("The Google service account key must be an RSA key.")
        signature = private_key.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        return f"{signing_input.decode('ascii')}.{b64url(signature)}"

    def token(self) -> str:
        if self._token and self._token[1] > time.time() + 60:
            return self._token[0]
        token_uri = _https_url(str(self.credentials.get("token_uri") or "https://oauth2.googleapis.com/token"), what="The service account's token_uri")
        answer = self._request("POST", token_uri, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": self.assertion()})
        token = str(answer.get("access_token") or "")
        if not token:
            raise EvidenceSigningError("Google gave no access token for Cloud KMS.")
        self._token = (token, time.time() + float(answer.get("expires_in") or 300))
        return token

    def public_key(self) -> tuple[Any, str]:
        answer = self._request("GET", f"{self.api}/{self.key_version}/publicKey", headers={"Authorization": f"Bearer {self.token()}"})
        if answer.get("algorithm") not in (None, "EC_SIGN_P256_SHA256"):
            raise EvidenceSigningConfigError(f"The Cloud KMS key version must use EC_SIGN_P256_SHA256 (it uses {answer.get('algorithm')}).")
        key = load_public_key(str(answer.get("pem") or ""))
        algorithm_for(key)
        return key, str(answer.get("name") or self.key_version)

    def sign(self, message: bytes) -> bytes:
        digest = base64.b64encode(hashlib.sha256(message).digest()).decode("ascii")
        answer = self._request("POST", f"{self.api}/{self.key_version}:asymmetricSign", json={"digest": {"sha256": digest}}, headers={"Authorization": f"Bearer {self.token()}"})
        return raw_ecdsa(base64.b64decode(str(answer.get("signature") or "")))


# ---------------------------------------------------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Config:
    backend: str
    key_ref: str = ""
    values: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def value(self, name: str) -> str:
        return dict(self.values).get(name, "")


def _setting(settings_obj: Any, name: str) -> str:
    return str(getattr(settings_obj, name, "") or "").strip()


def _env(name: str, env: Mapping[str, str]) -> str:
    from app.services.backup_key import env_secret

    return env_secret(name, env).strip()


def read_config(settings_obj: Any = None, env: Mapping[str, str] | None = None) -> Config:
    """What EVIDENCE_SIGNING_* says, checked: raises EvidenceSigningConfigError naming what is missing or wrong."""

    if settings_obj is None:
        from app.core.config import settings as settings_obj  # noqa: N806
    env = os.environ if env is None else env
    backend = (_setting(settings_obj, "evidence_signing_backend") or "local").lower()
    if backend not in BACKENDS:
        raise EvidenceSigningConfigError(f"EVIDENCE_SIGNING_BACKEND is {backend!r}; it must be one of {', '.join(BACKENDS)}.")
    if backend == "local":
        return Config("local", "local")
    if backend == "aws_kms":
        key_id = _setting(settings_obj, "evidence_signing_aws_kms_key_id")
        if not key_id:
            raise EvidenceSigningConfigError("EVIDENCE_SIGNING_BACKEND=aws_kms needs EVIDENCE_SIGNING_AWS_KMS_KEY_ID (the key's ARN, id or alias/…).")
        arn_region = key_id.split(":")[3] if key_id.startswith("arn:") and len(key_id.split(":")) > 4 else ""
        region = _setting(settings_obj, "evidence_signing_aws_region") or arn_region or _env("AWS_REGION", env) or _env("AWS_DEFAULT_REGION", env)
        if not region:
            raise EvidenceSigningConfigError("EVIDENCE_SIGNING_AWS_REGION is needed when the key is not given as an ARN.")
        access = _setting(settings_obj, "evidence_signing_aws_access_key_id") or _env("AWS_ACCESS_KEY_ID", env)
        secret = _setting(settings_obj, "evidence_signing_aws_secret_access_key") or _env("AWS_SECRET_ACCESS_KEY", env)
        token = _setting(settings_obj, "evidence_signing_aws_session_token") or _env("AWS_SESSION_TOKEN", env)
        if not access or not secret:
            raise EvidenceSigningConfigError("AWS KMS needs credentials: EVIDENCE_SIGNING_AWS_ACCESS_KEY_ID and EVIDENCE_SIGNING_AWS_SECRET_ACCESS_KEY (or its _FILE), or AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. Instance roles are not read.")
        endpoint = _setting(settings_obj, "evidence_signing_aws_endpoint")
        if endpoint:
            endpoint = _https_url(endpoint, what="EVIDENCE_SIGNING_AWS_ENDPOINT")
        return Config("aws_kms", key_id, (("region", region), ("access_key", access), ("secret_key", secret), ("session_token", token), ("endpoint", endpoint)))
    if backend == "azure_kv":
        key_url = _setting(settings_obj, "evidence_signing_azure_key_id")
        if not key_url:
            raise EvidenceSigningConfigError("EVIDENCE_SIGNING_BACKEND=azure_kv needs EVIDENCE_SIGNING_AZURE_KEY_ID (https://<vault>.vault.azure.net/keys/<name>[/<version>]).")
        key_url = _https_url(key_url, what="EVIDENCE_SIGNING_AZURE_KEY_ID")
        if "/keys/" not in urlsplit(key_url).path:
            raise EvidenceSigningConfigError("EVIDENCE_SIGNING_AZURE_KEY_ID must be a key's address: https://<vault>.vault.azure.net/keys/<name>[/<version>].")
        tenant = _setting(settings_obj, "evidence_signing_azure_tenant_id") or _env("AZURE_TENANT_ID", env)
        client_id = _setting(settings_obj, "evidence_signing_azure_client_id") or _env("AZURE_CLIENT_ID", env)
        secret = _setting(settings_obj, "evidence_signing_azure_client_secret") or _env("AZURE_CLIENT_SECRET", env)
        if not (tenant and client_id and secret):
            raise EvidenceSigningConfigError("Azure Key Vault needs EVIDENCE_SIGNING_AZURE_TENANT_ID, EVIDENCE_SIGNING_AZURE_CLIENT_ID and EVIDENCE_SIGNING_AZURE_CLIENT_SECRET (or its _FILE). Managed identities are not read.")
        authority = _https_url(_setting(settings_obj, "evidence_signing_azure_authority_host") or "https://login.microsoftonline.com", what="EVIDENCE_SIGNING_AZURE_AUTHORITY_HOST")
        return Config("azure_kv", key_url.rstrip("/"), (("tenant_id", tenant), ("client_id", client_id), ("client_secret", secret), ("authority_host", authority)))
    key_version = _setting(settings_obj, "evidence_signing_gcp_key_version")
    if not key_version or "/cryptoKeyVersions/" not in key_version:
        raise EvidenceSigningConfigError("EVIDENCE_SIGNING_BACKEND=gcp_kms needs EVIDENCE_SIGNING_GCP_KEY_VERSION (projects/…/locations/…/keyRings/…/cryptoKeys/…/cryptoKeyVersions/N).")
    raw = _setting(settings_obj, "evidence_signing_gcp_credentials_json")
    adc = str(env.get("GOOGLE_APPLICATION_CREDENTIALS") or "").strip()
    if not raw and adc:
        try:
            raw = Path(adc).read_text(encoding="utf-8")
        except OSError as error:
            raise EvidenceSigningConfigError(f"GOOGLE_APPLICATION_CREDENTIALS ({adc}) cannot be read.") from error
    try:
        credentials = json.loads(raw) if raw else None
    except json.JSONDecodeError as error:
        raise EvidenceSigningConfigError("EVIDENCE_SIGNING_GCP_CREDENTIALS_JSON is not valid JSON.") from error
    if not isinstance(credentials, dict) or not credentials.get("client_email") or not credentials.get("private_key"):
        raise EvidenceSigningConfigError("Google Cloud KMS needs a service account key: EVIDENCE_SIGNING_GCP_CREDENTIALS_JSON (or its _FILE, or GOOGLE_APPLICATION_CREDENTIALS). Workload identity is not read.")
    return Config("gcp_kms", key_version.strip("/"), (("credentials", json.dumps(credentials, sort_keys=True)),))


def remote_signer(config: Config, client_factory: ClientFactory | None = None) -> _RemoteSigner:
    if config.backend == "aws_kms":
        return AwsKmsSigner(key_id=config.key_ref, region=config.value("region"), access_key=config.value("access_key"), secret_key=config.value("secret_key"), session_token=config.value("session_token"), endpoint=config.value("endpoint"), client_factory=client_factory)
    if config.backend == "azure_kv":
        return AzureKeyVaultSigner(key_url=config.key_ref, tenant_id=config.value("tenant_id"), client_id=config.value("client_id"), client_secret=config.value("client_secret"), authority_host=config.value("authority_host"), client_factory=client_factory)
    if config.backend == "gcp_kms":
        return GcpKmsSigner(key_version=config.key_ref, credentials=json.loads(config.value("credentials")), client_factory=client_factory)
    raise EvidenceSigningConfigError(f"{config.backend} is not a cloud backend.")


# ---------------------------------------------------------------------------------------------------------------------
# The keyring and the service
# ---------------------------------------------------------------------------------------------------------------------

_signers_lock = threading.Lock()
_signers: dict[Config, _RemoteSigner] = {}


def forget() -> None:
    """For tests and after a restore: drop the cloud clients (and their tokens) made so far."""

    with _signers_lock:
        _signers.clear()


def data_dir() -> Path:
    from app.core.config import settings

    return Path(str(settings.hawk_data_dir or ".runtime/data"))


class EvidenceSigning:
    """Signs and checks evidence with the configured backend; keeps every public key ever used."""

    def __init__(self, *, directory: Path | str | None = None, settings_obj: Any = None, env: Mapping[str, str] | None = None, client_factory: ClientFactory | None = None) -> None:
        self.directory = Path(directory) if directory is not None else data_dir()
        self.file = self.directory / KEYRING_FILE
        self.settings_obj = settings_obj
        self.env = env
        self.client_factory = client_factory
        self._own_signers: dict[Config, _RemoteSigner] = {}

    # ---- the keyring file ----

    @contextlib.contextmanager
    def _locked(self) -> Iterator[None]:
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.directory / LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)

    def read(self) -> dict[str, Any]:
        try:
            raw = self.file.read_bytes()
        except FileNotFoundError:
            return {"version": 1, "active": "", "keys": []}
        except OSError as error:
            raise EvidenceSigningError(f"The evidence signing keys ({self.file}) cannot be read: {error}.") from error
        try:
            state = json.loads(raw)
            if not isinstance(state, dict) or not isinstance(state.get("keys"), list):
                raise ValueError("not a keyring")
        except ValueError as error:
            # Never replaced by a new key without a word: every signature made so far would lose its public key.
            raise EvidenceSigningError(
                f"The evidence signing keys ({self.file}) are damaged. They are not replaced, because evidence signed so far could not be checked any more: restore the file from a backup of the data folder."
            ) from error
        return state

    def _write(self, state: Mapping[str, Any]) -> None:
        from app.services.state_file import write_state

        write_state(self.file, dict(state), mode=0o600, keep_last=False)

    def config(self) -> Config:
        return read_config(self.settings_obj, self.env)

    def _remote(self, config: Config) -> _RemoteSigner:
        if self.client_factory is not None:  # tests: this service's own clients
            if config not in self._own_signers:
                self._own_signers[config] = remote_signer(config, self.client_factory)
            return self._own_signers[config]
        with _signers_lock:
            signer = _signers.get(config)
            if signer is None:
                signer = _signers[config] = remote_signer(config)
            return signer

    @staticmethod
    def _entry_for(state: Mapping[str, Any], kid: str) -> dict[str, Any] | None:
        return next((k for k in state.get("keys", []) if isinstance(k, dict) and k.get("kid") == kid), None)

    def _add_active(self, state: dict[str, Any], entry: dict[str, Any], now: str) -> dict[str, Any]:
        """Make ``entry`` the active key; the one before is retired (a local private key destroyed)."""

        for key in state["keys"]:
            if key.get("kid") != entry["kid"] and not key.get("retired_at"):
                key["retired_at"] = now
                key.pop("private_key_pem", None)
        existing = self._entry_for(state, entry["kid"])
        if existing is not None:
            existing.update({k: v for k, v in entry.items() if k not in ("created_at",)})
            existing.pop("retired_at", None)
        else:
            state["keys"].append(entry)
        state["active"] = entry["kid"]
        return state

    @staticmethod
    def _new_local_entry(now: str) -> dict[str, Any]:
        private = ed25519.Ed25519PrivateKey.generate()
        public = private.public_key()
        return {
            "kid": fingerprint(public),
            "alg": EDDSA,
            "backend": "local",
            "key_ref": "local",
            "key_name": "local",
            "public_key_pem": public_key_pem(public),
            "private_key_pem": private.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode("ascii"),
            "created_at": now,
        }

    def _remote_entry(self, config: Config, signer: _RemoteSigner, now: str) -> dict[str, Any]:
        public, name = signer.public_key()
        return {"kid": fingerprint(public), "alg": algorithm_for(public), "backend": config.backend, "key_ref": config.key_ref, "key_name": name, "public_key_pem": public_key_pem(public), "created_at": now}

    @staticmethod
    def _matches(entry: Mapping[str, Any] | None, config: Config) -> bool:
        return bool(entry) and entry.get("backend") == config.backend and entry.get("key_ref") == config.key_ref and not entry.get("retired_at") and (config.backend != "local" or bool(entry.get("private_key_pem")))

    def active_entry(self) -> dict[str, Any]:
        """The key that signs now, made or registered the first time (and when the backend or key setting changed)."""

        config = self.config()
        state = self.read()
        entry = self._entry_for(state, str(state.get("active") or ""))
        if self._matches(entry, config):
            return entry  # type: ignore[return-value]
        with self._locked():
            state = self.read()
            entry = self._entry_for(state, str(state.get("active") or ""))
            if self._matches(entry, config):
                return entry  # type: ignore[return-value]
            now = _now_iso()
            new = self._new_local_entry(now) if config.backend == "local" else self._remote_entry(config, self._remote(config), now)
            self._write(self._add_active(state, new, now))
            return new

    def signer(self) -> tuple[Signer, dict[str, Any]]:
        entry = self.active_entry()
        if entry["backend"] == "local":
            private = serialization.load_pem_private_key(str(entry["private_key_pem"]).encode("ascii"), password=None)
            if not isinstance(private, ed25519.Ed25519PrivateKey):
                raise EvidenceSigningError("The local evidence signing key is not an Ed25519 key.")
            return LocalSigner(private), entry
        signer = self._remote(self.config())
        if isinstance(signer, AzureKeyVaultSigner) and entry.get("key_name"):
            signer.use_version(str(entry["key_name"]))
        return signer, entry

    # ---- signing ----

    def sign_digest(self, digest_hex: str, *, artifact: str, now: dt.datetime | None = None) -> dict[str, Any]:
        signer, entry = self.signer()
        unsigned = {"format": FORMAT, "alg": entry["alg"], "kid": entry["kid"], "digest_alg": "sha256", "digest": digest_hex, "artifact": str(artifact), "signed_at": _now_iso(now)}
        message = canonical_json(unsigned)
        signature = signer.sign(message)
        # A cloud key answers for itself: check what it gave against the public key on record before handing it out.
        if not verify_raw(load_public_key(entry["public_key_pem"]), entry["alg"], message, signature):
            raise EvidenceSigningError("The signing key gave a signature that its recorded public key does not verify. Rotate the evidence signing key (Settings → Audit log) and try again.")
        return {**unsigned, "signature": b64url(signature)}

    def sign_bytes(self, data: bytes, *, artifact: str, now: dt.datetime | None = None) -> dict[str, Any]:
        """A detached signature (envelope) over ``data``."""

        return self.sign_digest(hashlib.sha256(data).hexdigest(), artifact=artifact, now=now)

    def sign_document(self, document: Mapping[str, Any], *, artifact: str, now: dt.datetime | None = None) -> dict[str, Any]:
        """The JSON document (as its readers will see it) with its signature inside, under ``evidence_signature``."""

        body = {k: v for k, v in plain_json(dict(document)).items() if k != SIGNATURE_FIELD}
        return {**body, SIGNATURE_FIELD: self.sign_digest(hashlib.sha256(canonical_json(body)).hexdigest(), artifact=artifact, now=now)}

    def header_for(self, data: bytes, *, artifact: str) -> dict[str, str]:
        """Response headers carrying a detached signature over ``data``; when signing fails the export still goes out,
        saying so (``X-Hawk-Evidence-Signature-Status: unavailable``)."""

        try:
            return {HEADER: encode_header(self.sign_bytes(data, artifact=artifact)), STATUS_HEADER: "signed"}
        except EvidenceSigningError:
            return {STATUS_HEADER: "unavailable"}

    # ---- checking ----

    def known_keys(self) -> dict[str, Any]:
        return {str(k.get("kid")): k for k in self.read().get("keys", []) if isinstance(k, dict) and k.get("kid")}

    def verify(self, envelope: Mapping[str, Any], *, data: bytes | None = None, document: Mapping[str, Any] | None = None) -> dict[str, Any]:
        return verify_envelope(envelope, data=data, document=document, keys=self.known_keys())

    def verify_document(self, document: Mapping[str, Any]) -> dict[str, Any]:
        envelope = document.get(SIGNATURE_FIELD)
        if not isinstance(envelope, Mapping):
            return {"valid": False, "reason": "The document carries no evidence_signature."}
        return self.verify(envelope, document=document)

    # ---- what the page and the key list show ----

    def public_keys(self) -> dict[str, Any]:
        """Every public key ever used (JWKS-style): what an auditor needs to check evidence offline."""

        state = self.read()
        active = str(state.get("active") or "")
        keys = []
        for entry in state.get("keys", []):
            if not isinstance(entry, dict) or not entry.get("public_key_pem"):
                continue
            public = load_public_key(entry["public_key_pem"])
            keys.append(
                {
                    **jwk(public),
                    "kid": entry["kid"],
                    "alg": entry["alg"],
                    "use": "sig",
                    "status": "active" if entry["kid"] == active and not entry.get("retired_at") else "retired",
                    "backend": entry.get("backend"),
                    "created_at": entry.get("created_at"),
                    "retired_at": entry.get("retired_at"),
                    "public_key_pem": entry["public_key_pem"],
                }
            )
        return {"format": KEYS_FORMAT, "signature_format": FORMAT, "keys": keys}

    def status(self) -> dict[str, Any]:
        """What Settings shows: the backend, the key that signs (made now for a new local installation), the retired
        keys, and what is wrong when something is. Never a private key."""

        out: dict[str, Any] = {"backend": "", "backend_label": "", "key_ref": "", "active": None, "retired": [], "error": "", "well_known_path": WELL_KNOWN_PATH}
        try:
            config = self.config()
            out.update({"backend": config.backend, "backend_label": BACKEND_LABELS[config.backend], "key_ref": "" if config.backend == "local" else config.key_ref})
            entry = self.active_entry()
        except EvidenceSigningError as error:
            out["error"] = str(error)
            entry = None
        try:
            keys = self.read().get("keys", [])
        except EvidenceSigningError as error:
            out["error"] = out["error"] or str(error)
            keys = []

        def shown(key: Mapping[str, Any]) -> dict[str, Any]:
            return {"kid": key.get("kid"), "fingerprint": key.get("kid"), "alg": key.get("alg"), "backend": key.get("backend"), "key_name": "" if key.get("backend") == "local" else key.get("key_name"), "created_at": key.get("created_at"), "retired_at": key.get("retired_at")}

        out["active"] = shown(entry) if entry else None
        out["retired"] = [shown(k) for k in keys if isinstance(k, dict) and k.get("retired_at")]
        return out

    def rotate(self) -> dict[str, Any]:
        """A new signing key. Local: a new Ed25519 key (the old private key destroyed, its public key kept). Cloud: the
        configured key is read again; when it is a different key (a new KMS key set in the settings, a new Key Vault
        version), it becomes the active one. Returns {"rotated", "active", "previous"}."""

        config = self.config()
        with self._locked():
            state = self.read()
            previous = str(state.get("active") or "")
            now = _now_iso()
            new = self._new_local_entry(now) if config.backend == "local" else self._remote_entry(config, self._remote(config), now)
            rotated = new["kid"] != previous
            if rotated or not self._matches(self._entry_for(state, previous), config):
                self._write(self._add_active(state, new, now))
            return {"rotated": rotated, "active": new["kid"], "previous": previous or None}


def verify_envelope(envelope: Mapping[str, Any], *, keys: Mapping[str, Mapping[str, Any]], data: bytes | None = None, document: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """Check one signature against the evidence (bytes, or the JSON document it is embedded in) and the public keys
    (by kid: {"alg", "public_key_pem"}, as the key list gives them). Returns {"valid", "reason", "kid", ...}."""

    result: dict[str, Any] = {"valid": False, "kid": envelope.get("kid"), "alg": envelope.get("alg"), "signed_at": envelope.get("signed_at"), "artifact": envelope.get("artifact")}
    if envelope.get("format") != FORMAT or envelope.get("digest_alg") != "sha256":
        return {**result, "reason": f"Not a {FORMAT} signature."}
    if envelope.get("alg") not in ALGORITHMS:
        return {**result, "reason": f"Unsupported algorithm {envelope.get('alg')!r}."}
    if document is not None:
        digest = document_digest(document)
    elif data is not None:
        digest = hashlib.sha256(data).hexdigest()
    else:
        return {**result, "reason": "Nothing to check the signature against."}
    if not hmac.compare_digest(str(envelope.get("digest") or ""), digest):
        return {**result, "reason": "The evidence was changed after it was signed (its digest does not match)."}
    key = keys.get(str(envelope.get("kid") or ""))
    if not key:
        return {**result, "reason": "Signed with a key that is not among the published keys."}
    if key.get("alg") != envelope.get("alg"):
        return {**result, "reason": "The signature's algorithm does not match its key."}
    try:
        public = load_public_key(str(key.get("public_key_pem") or ""))
        signature = b64url_decode(str(envelope.get("signature") or ""))
    except ValueError:
        return {**result, "reason": "The signature or the key is malformed."}
    if fingerprint(public) != envelope.get("kid"):
        return {**result, "reason": "The published key does not match its key id."}
    if not verify_raw(public, str(envelope["alg"]), canonical_json(unsigned_envelope(envelope)), signature):
        return {**result, "reason": "The signature does not verify."}
    return {**result, "valid": True, "reason": "Valid: signed by this key, and unchanged since.", "key_status": "retired" if key.get("retired_at") else "active"}


def service() -> EvidenceSigning:
    return EvidenceSigning()


__all__ = [
    "ALGORITHMS",
    "AwsKmsSigner",
    "AzureKeyVaultSigner",
    "BACKENDS",
    "Config",
    "EvidenceSigning",
    "EvidenceSigningConfigError",
    "EvidenceSigningError",
    "FORMAT",
    "GcpKmsSigner",
    "HEADER",
    "KEYRING_FILE",
    "KEYS_FORMAT",
    "LOCK_FILE",
    "SIGNATURE_FIELD",
    "STATUS_HEADER",
    "WELL_KNOWN_PATH",
    "canonical_json",
    "decode_header",
    "document_digest",
    "encode_header",
    "fingerprint",
    "forget",
    "read_config",
    "service",
    "sigv4_headers",
    "verify_envelope",
]
