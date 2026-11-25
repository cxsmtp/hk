"""Free certificates from Let's Encrypt (any ACME v2 certificate authority, RFC 8555), got and renewed by Hawk AI
itself, from Settings → HTTPS: no request to IT. Ported from CxMissionZero's src/acme.js.

How it works:
- An ECDSA P-256 account key (<HAWK_DATA_DIR>/tls/acme/, one per CA directory) signs every request to the CA (JWS,
  ES256).
- The CA checks that each name points at this server with the HTTP-01 challenge: it fetches
  http://<name>/.well-known/acme-challenge/<token> on port 80, which the front proxy hands to the API in every HTTPS
  mode (app/services/https_proxy.py). Before asking, the API tries that address itself, so a wrong DNS entry or a
  closed port 80 is found without using up the CA's limits.
- A CSR with a new RSA key (app/services/tls_service.py) is sent; the certificate chain that comes back is put to use
  like an uploaded one (HttpsManager.install: checked, swapped in without a restart, the previous certificate kept).
- It is renewed by itself 30 days before it expires.

Nothing but these requests to the CA leaves the server.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import json
import logging
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from app.services.https_manager import HttpsError
from app.services.state_file import read_state, write_bytes_atomic, write_state
from app.services.tls_service import certificate_request, is_ip

log = logging.getLogger("hawk.https")

DIRECTORIES = {
    "production": "https://acme-v02.api.letsencrypt.org/directory",
    "staging": "https://acme-staging-v02.api.letsencrypt.org/directory",
}
SUBSCRIBER_AGREEMENT = "https://letsencrypt.org/repository/"
CHALLENGE_PREFIX = "/.well-known/acme-challenge/"
#: Renewed when it has fewer days left than this.
RENEW_DAYS = 30
#: After a failed attempt, the automatic renewal waits this long before trying again.
RETRY_AFTER_FAILURE_SECONDS = 6 * 60 * 60
POLL_TIMEOUT_SECONDS = 3 * 60
MAX_NAMES = 20
_TOKEN = re.compile(r"^[A-Za-z0-9_-]{8,128}$")
_NAME = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$")


def _b64u(data: bytes | str) -> str:
    raw = data.encode() if isinstance(data, str) else data
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _iso(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _parse_iso(value: Any) -> dt.datetime | None:
    try:
        return dt.datetime.fromisoformat(str(value).replace("Z", "+00:00")) if value else None
    except ValueError:
        return None


def valid_name(name: Any) -> bool:
    """A name a CA can issue for with HTTP-01: a DNS name with a dot, no IP address, no wildcard."""

    n = str(name or "").strip().lower()
    if not n or len(n) > 253 or is_ip(n) or n.startswith("*.") or "." not in n:
        return False
    if n == "localhost" or n.endswith((".localhost", ".local", ".internal")):
        return False
    return bool(_NAME.match(n))


def clean_names(names: Any) -> list[str]:
    """The names to ask for: lower case, each once, checked. Raises with what is wrong."""

    items = names if isinstance(names, list) else re.split(r"[\s,]+", str(names or ""))
    unique = list(dict.fromkeys(str(n).strip().lower() for n in items if str(n).strip()))
    if not unique:
        raise HttpsError(400, "Enter the name people use to reach this server, e.g. hawk.company.com.")
    if len(unique) > MAX_NAMES:
        raise HttpsError(400, f"At most {MAX_NAMES} names.")
    bad = next((n for n in unique if not valid_name(n)), None)
    if bad:
        why = "an IP address" if is_ip(bad) else "a wildcard (it needs a DNS check this server cannot do)" if bad.startswith("*.") else "not a public DNS name"
        raise HttpsError(400, f'"{bad}" cannot get a Let\'s Encrypt certificate: it is {why}. Use a DNS name that points at this server.')
    return unique


def _problem(body: Any, status: int) -> HttpsError:
    """Read an ACME error into one sentence a person can act on."""

    body = body if isinstance(body, dict) else {"detail": body if isinstance(body, str) else ""}
    kind = str(body.get("type") or "").replace("urn:ietf:params:acme:error:", "")
    detail = str(body.get("detail") or "")[:400] or f"HTTP {status}"
    hints = {
        "rateLimited": " Let's Encrypt limits how often certificates are issued: wait, or test with the staging service.",
        "connection": " Let's Encrypt could not reach this server on port 80: check the DNS name and that port 80 is open to the internet.",
        "dns": " Check that the DNS name exists and points at this server.",
        "unauthorized": " The answer at that address did not come from this server: check the DNS name and any proxy or firewall in front.",
        "rejectedIdentifier": " Let's Encrypt does not issue for this name.",
        "caa": " A CAA record in DNS forbids Let's Encrypt for this name.",
    }
    return HttpsError(502, f"Let's Encrypt: {detail}{hints.get(kind, '')}", acmeType=kind)


class AcmeClient:
    """A minimal ACME v2 client: account, order, HTTP-01, finalize, download."""

    def __init__(self, *, directory_url: str, account_key: bytes, http: httpx.Client, poll_seconds: float = 1.0) -> None:
        self.directory_url = directory_url
        self.key = serialization.load_pem_private_key(account_key, password=None)
        if not isinstance(self.key, ec.EllipticCurvePrivateKey):
            raise HttpsError(500, "The ACME account key is not an EC P-256 key.")
        numbers = self.key.public_key().public_numbers()
        self.jwk = {"crv": "P-256", "kty": "EC", "x": _b64u(numbers.x.to_bytes(32, "big")), "y": _b64u(numbers.y.to_bytes(32, "big"))}
        self.http = http
        self.poll_seconds = poll_seconds
        self.kid = ""
        self.nonce = ""
        self._directory: dict[str, Any] | None = None

    @property
    def thumbprint(self) -> str:
        """RFC 7638 thumbprint of the account key: the second half of every key authorization."""

        canonical = json.dumps({"crv": self.jwk["crv"], "kty": self.jwk["kty"], "x": self.jwk["x"], "y": self.jwk["y"]}, separators=(",", ":"))
        return _b64u(hashlib.sha256(canonical.encode()).digest())

    def key_authorization(self, token: str) -> str:
        return f"{token}.{self.thumbprint}"

    def directory(self) -> dict[str, Any]:
        if self._directory is None:
            res = self.http.get(self.directory_url, timeout=30)
            if res.status_code >= 400:
                raise HttpsError(502, f"The certificate authority's directory answered HTTP {res.status_code}.")
            self._directory = res.json()
        return self._directory

    def _new_nonce(self) -> str:
        res = self.http.head(self.directory()["newNonce"], timeout=30)
        nonce = res.headers.get("replay-nonce")
        if not nonce:
            raise HttpsError(502, "The certificate authority gave no nonce.")
        return nonce

    def _sign(self, data: bytes) -> bytes:
        der = self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")

    def post(self, url: str, payload: Any, *, use_jwk: bool = False, accept: str | None = None) -> httpx.Response:
        """A signed POST (payload '' is POST-as-GET). Retries once on a stale nonce."""

        for attempt in range(2):
            nonce = self.nonce or self._new_nonce()
            self.nonce = ""
            header = {"alg": "ES256", "nonce": nonce, "url": url, **({"jwk": self.jwk} if use_jwk else {"kid": self.kid})}
            protected = _b64u(json.dumps(header))
            body = "" if payload == "" else _b64u(json.dumps(payload))
            signature = _b64u(self._sign(f"{protected}.{body}".encode()))
            headers = {"Content-Type": "application/jose+json", **({"Accept": accept} if accept else {})}
            res = self.http.post(url, content=json.dumps({"protected": protected, "payload": body, "signature": signature}), headers=headers, timeout=60)
            if res.headers.get("replay-nonce"):
                self.nonce = res.headers["replay-nonce"]
            kind = res.headers.get("content-type", "")
            parsed: Any = res.text
            if "json" in kind:
                try:
                    parsed = res.json()
                except ValueError:
                    parsed = {}
            if res.status_code < 400:
                res.parsed = parsed  # type: ignore[attr-defined]
                return res
            if attempt == 0 and isinstance(parsed, dict) and parsed.get("type") == "urn:ietf:params:acme:error:badNonce":
                continue
            raise _problem(parsed, res.status_code)
        raise HttpsError(502, "The certificate authority kept refusing the request.")

    def account(self, email: str = "") -> str:
        """Register (or find) the account for this key; the terms of service must have been agreed to."""

        res = self.post(self.directory()["newAccount"], {"termsOfServiceAgreed": True, **({"contact": [f"mailto:{email}"]} if email else {})}, use_jwk=True)
        self.kid = res.headers.get("location", "")
        if not self.kid:
            raise HttpsError(502, "The certificate authority did not return an account.")
        return self.kid

    def _get(self, url: str) -> Any:
        return self.post(url, "").parsed  # type: ignore[attr-defined]

    def _poll(self, url: str, done: list[str], failed: tuple[str, ...] = ("invalid",)) -> dict[str, Any]:
        until = time.monotonic() + POLL_TIMEOUT_SECONDS
        wait = self.poll_seconds
        while True:
            body = self._get(url)
            if body.get("status") in done or body.get("status") in failed:
                return body
            if time.monotonic() > until:
                raise HttpsError(504, "The certificate authority took too long to answer; try again in a few minutes.")
            time.sleep(wait)
            wait = min(wait * 2, 5.0)

    def obtain(self, *, names: list[str], email: str = "", publish: Callable[[str, str], None], unpublish: Callable[[str], None] = lambda _t: None) -> tuple[str, bytes]:
        """Get a certificate for ``names``. ``publish(token, key_authorization)`` makes the challenge answer available
        on port 80 and ``unpublish(token)`` removes it. Returns (chain PEM, key PEM)."""

        directory = self.directory()
        self.account(email)
        created = self.post(directory["newOrder"], {"identifiers": [{"type": "dns", "value": n} for n in names]})
        order_url = created.headers.get("location", "")
        order = created.parsed  # type: ignore[attr-defined]
        tokens: list[str] = []
        try:
            for authz_url in order.get("authorizations") or []:
                authz = self._get(authz_url)
                if authz.get("status") == "valid":
                    continue
                challenge = next((c for c in authz.get("challenges") or [] if c.get("type") == "http-01"), None)
                if not challenge:
                    raise HttpsError(502, f"The certificate authority offers no HTTP check for {(authz.get('identifier') or {}).get('value', 'a name')}.")
                publish(challenge["token"], self.key_authorization(challenge["token"]))
                tokens.append(challenge["token"])
                self.post(challenge["url"], {})
                result = self._poll(authz_url, ["valid"])
                if result.get("status") != "valid":
                    problem = next((c.get("error") for c in result.get("challenges") or [] if c.get("type") == "http-01"), None)
                    raise _problem(problem or {"detail": f"{(authz.get('identifier') or {}).get('value')}: the check failed."}, 403)
            request = certificate_request(names)
            order = self._poll(order_url, ["ready", "valid"])
            if order.get("status") == "ready":
                der = x509.load_pem_x509_csr(request.csr.encode()).public_bytes(serialization.Encoding.DER)
                self.post(order["finalize"], {"csr": _b64u(der)})
                order = self._poll(order_url, ["valid"])
            if order.get("status") != "valid" or not order.get("certificate"):
                raise _problem(order.get("error") or {"detail": "The order was not completed."}, 502)
            chain = self.post(order["certificate"], "", accept="application/pem-certificate-chain").text
            if "-----BEGIN CERTIFICATE-----" not in chain:
                raise HttpsError(502, "The certificate authority did not send a certificate.")
            return chain, request.key
        finally:
            for token in tokens:
                unpublish(token)


class AcmeService:
    """The Let's Encrypt option of Settings → HTTPS: its choices (<HAWK_DATA_DIR>/acme.json), the challenge answers,
    getting a certificate in the background, and renewing it."""

    def __init__(
        self,
        *,
        data_dir: str | Path,
        https: Any,
        http: httpx.Client | None = None,
        directories: dict[str, str] | None = None,
        poll_seconds: float = 1.0,
    ) -> None:
        self.file = Path(data_dir) / "acme.json"
        self.key_dir = Path(data_dir) / "tls" / "acme"
        self.https = https
        self.http = http or httpx.Client(follow_redirects=False)
        self.directories = directories or dict(DIRECTORIES)
        self.poll_seconds = poll_seconds
        self.challenges: dict[str, str] = {}
        self._lock = threading.Lock()
        self._running: threading.Thread | None = None
        self._listeners: list[Callable[[dict[str, Any]], None]] = []
        self._stop = threading.Event()
        self.state = self._load()

    def _load(self) -> dict[str, Any]:
        # No file yet: automatic certificates are off. A damaged file is never "off": taken for that, the certificate
        # would quietly stop being renewed.
        raw = read_state(self.file, fallback={}, holds="the automatic (ACME) certificate settings") or {}
        return {"enabled": False, "names": [], "email": "", "staging": False, "skipPrecheck": False, "last": None, "issued": None, **raw}

    def _save(self) -> None:
        write_state(self.file, self.state)

    def on_event(self, listener: Callable[[dict[str, Any]], None]) -> None:
        """Called with {kind: 'issued' | 'failed', ...} after every attempt (for the audit log)."""

        self._listeners.append(listener)

    def _emit(self, event: dict[str, Any]) -> None:
        for listener in self._listeners:
            try:
                listener(event)
            except Exception as error:  # noqa: BLE001 - one listener never stops the others
                log.warning("! [https] %s", error)

    def challenge(self, token: Any) -> str | None:
        """The answer the CA expects at /.well-known/acme-challenge/<token>, or None."""

        t = str(token or "")
        return self.challenges.get(t) if _TOKEN.match(t) else None

    def _directory_url(self, staging: bool) -> str:
        return self.directories["staging" if staging else "production"]

    def _account_key(self, staging: bool) -> bytes:
        """The account key for one CA directory, made the first time (kept: the account is reused)."""

        file = self.key_dir / ("account-staging.key" if staging else "account.key")
        try:
            return file.read_bytes()
        except OSError:
            pass
        key = ec.generate_private_key(ec.SECP256R1())
        pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
        write_bytes_atomic(file, pem, mode=0o600)
        return pem

    @property
    def running(self) -> bool:
        return bool(self._running and self._running.is_alive())

    def status(self, now: dt.datetime | None = None) -> dict[str, Any]:
        now = now or _now()
        s = self.state
        valid_to = _parse_iso((s.get("issued") or {}).get("validTo"))
        return {
            "enabled": bool(s.get("enabled")),
            "names": s.get("names") or [],
            "email": s.get("email") or "",
            "staging": bool(s.get("staging")),
            "skipPrecheck": bool(s.get("skipPrecheck")),
            "running": self.running,
            "last": s.get("last"),
            "issued": s.get("issued"),
            "daysLeft": int((valid_to - now).total_seconds() // 86_400) if valid_to else None,
            "renewsFrom": _iso(valid_to - dt.timedelta(days=RENEW_DAYS)) if valid_to else None,
            "agreement": SUBSCRIBER_AGREEMENT,
        }

    def precheck(self, names: list[str]) -> list[dict[str, Any]]:
        """Before asking the CA: fetch each name's challenge address the way the CA will, so a DNS name that points
        elsewhere or a closed port 80 is found first (failed checks count against the CA's limits)."""

        results: list[dict[str, Any]] = []
        for name in names:
            token = f"hawk-check-{secrets.token_urlsafe(12)}"
            expected = f"{token}.self-check"
            self.challenges[token] = expected
            try:
                res = self.http.get(f"http://{name}{CHALLENGE_PREFIX}{token}", timeout=10, follow_redirects=False)
                body = res.text.strip() if res.status_code < 300 else ""
                if body == expected:
                    results.append({"name": name, "ok": True})
                else:
                    results.append({"name": name, "ok": False, "error": "another server answered at this name" if res.status_code < 300 else f"HTTP {res.status_code}"})
            except httpx.TimeoutException:
                results.append({"name": name, "ok": False, "error": "no answer (timeout)"})
            except httpx.HTTPError as error:
                results.append({"name": name, "ok": False, "error": f"no answer ({type(error).__name__}: {str(error)[:120]})"})
            finally:
                self.challenges.pop(token, None)
        return results

    def start(self, *, names: Any, email: Any = "", staging: bool = False, agree: bool = False, skip_precheck: bool = False, by: str = "") -> dict[str, Any]:
        """Get a certificate, in the background (poll status()). ``agree``: the person accepted the CA's subscriber
        agreement. ``skip_precheck``: for a server that cannot reach its own public name (hairpin NAT) although the
        internet can."""

        with self._lock:
            if self.running:
                raise HttpsError(409, "A certificate is already being requested.")
            if agree is not True:
                raise HttpsError(400, "Agree to the Let's Encrypt Subscriber Agreement first.")
            clean = clean_names(names)
            mail = str(email or "").strip()[:200]
            if mail and not re.match(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", mail):
                raise HttpsError(400, "Enter a valid email address, or leave it empty.")
            job = {"names": clean, "email": mail, "staging": bool(staging), "skipPrecheck": bool(skip_precheck), "by": str(by or "")}
            self.state["last"] = {"at": _iso(_now()), "running": True, "by": job["by"], "names": clean, "staging": job["staging"]}
            self._save()
            self._running = threading.Thread(target=self._run, args=(job,), name="hawk-acme", daemon=True)
            self._running.start()
        return self.status()

    def settled(self, timeout: float | None = None) -> None:
        """Wait for the attempt in progress (tests, and shutdown)."""

        thread = self._running
        if thread:
            thread.join(timeout)

    def _run(self, job: dict[str, Any]) -> None:
        at = _iso(_now())
        try:
            if not job["skipPrecheck"]:
                checks = self.precheck(job["names"])
                failed = [c for c in checks if not c["ok"]]
                if failed:
                    where = ", ".join(f"http://{c['name']}/ ({c['error']})" for c in failed)
                    raise HttpsError(
                        409,
                        f"This server could not reach itself at {where}. Let's Encrypt checks the same address on port 80: point the DNS name at this server and open port 80 to the internet. If the internet can reach it but this server cannot reach its own public name, tick \"Skip the self-check\".",
                        precheck=checks,
                    )
            client = AcmeClient(directory_url=self._directory_url(job["staging"]), account_key=self._account_key(job["staging"]), http=self.http, poll_seconds=self.poll_seconds)
            chain, key = client.obtain(
                names=job["names"],
                email=job["email"],
                publish=lambda token, value: self.challenges.__setitem__(token, value),
                unpublish=lambda token: self.challenges.pop(token, None),
            )
            report = self.https.install(
                files=[
                    {"name": "letsencrypt.crt", "data": base64.b64encode(chain.encode()).decode()},
                    {"name": "letsencrypt.key", "data": base64.b64encode(key).decode()},
                ],
                hosts=job["names"],
                confirm=True,
                by=f"Let's Encrypt, for {job['by']}" if job["by"] else "Let's Encrypt",
            )
            leaf = x509.load_pem_x509_certificate(chain.encode())
            summary = (report or {}).get("summary") or {}
            self.state = {
                **self.state,
                "enabled": True,
                "names": job["names"],
                "email": job["email"],
                "staging": job["staging"],
                "skipPrecheck": job["skipPrecheck"],
                "issued": {
                    "at": _iso(_now()),
                    "validTo": _iso(leaf.not_valid_after_utc),
                    "names": job["names"],
                    "issuer": summary.get("issuer") or leaf.issuer.rfc4514_string(),
                    "staging": job["staging"],
                    "fingerprint": summary.get("fingerprint") or "",
                },
                "last": {"at": at, "ok": True, "by": job["by"], "names": job["names"], "staging": job["staging"]},
            }
            self._save()
            log.warning(
                "[https] Let's Encrypt certificate for %s put to use (valid until %s%s).",
                ", ".join(job["names"]),
                self.state["issued"]["validTo"][:10],
                ", staging: not trusted by browsers" if job["staging"] else "",
            )
            self._emit({"kind": "issued", "names": job["names"], "staging": job["staging"], "validTo": self.state["issued"]["validTo"], "by": job["by"]})
        except Exception as error:  # noqa: BLE001 - every failure is recorded and audited
            message = str(error)
            precheck = error.extra.get("precheck") if isinstance(error, HttpsError) else None
            self.state = {**self.state, "last": {"at": at, "ok": False, "error": message, "by": job["by"], "names": job["names"], "staging": job["staging"], **({"precheck": precheck} if precheck else {})}}
            self._save()
            log.warning("! [https] Let's Encrypt certificate for %s not obtained: %s", ", ".join(job["names"]), message)
            self._emit({"kind": "failed", "names": job["names"], "staging": job["staging"], "error": message, "by": job["by"]})

    def disable(self) -> None:
        """Stop renewing on its own (the certificate in use stays until it expires or is replaced)."""

        if not self.state.get("enabled"):
            raise HttpsError(400, "Automatic renewal is not on.")
        self.state = {**self.state, "enabled": False}
        self._save()

    def renewal_due(self, now: dt.datetime | None = None) -> bool:
        now = now or _now()
        s = self.state
        valid_to = _parse_iso((s.get("issued") or {}).get("validTo"))
        if not s.get("enabled") or not valid_to or self.running:
            return False
        if valid_to - now > dt.timedelta(days=RENEW_DAYS):
            return False
        last = s.get("last") or {}
        last_at = _parse_iso(last.get("at"))
        if last and not last.get("ok") and not last.get("running") and last_at and (now - last_at).total_seconds() < RETRY_AFTER_FAILURE_SECONDS:
            return False
        return True

    def renew(self, *, by: str = "automatic renewal") -> dict[str, Any]:
        """Renew now, with the names and choices of the certificate in use."""

        s = self.state
        if not s.get("names"):
            raise HttpsError(400, "No Let's Encrypt certificate has been requested yet.")
        return self.start(names=s["names"], email=s.get("email") or "", staging=bool(s.get("staging")), skip_precheck=bool(s.get("skipPrecheck")), agree=True, by=by)

    def start_renewal(self, *, interval: float = 12 * 60 * 60, first: float = 2 * 60) -> None:
        """Check twice a day whether a renewal is due (and once soon after start)."""

        def check() -> None:
            try:
                if self.renewal_due():
                    log.warning("[https] Renewing the Let's Encrypt certificate for %s.", ", ".join(self.state["names"]))
                    self.renew()
            except Exception as error:  # noqa: BLE001
                log.warning("! [https] Let's Encrypt renewal could not start: %s", error)

        def loop() -> None:
            if self._stop.wait(first):
                return
            check()
            while not self._stop.wait(interval):
                check()

        threading.Thread(target=loop, name="hawk-acme-renewal", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
