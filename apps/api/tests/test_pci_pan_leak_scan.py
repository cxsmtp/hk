"""PCI DSS v4.0.1 3.3 / 3.4 / 3.5 / 10: Hawk never stores, logs or exports a full card number (PAN).

Realistic test card numbers (Visa, Mastercard, Amex, Discover, RuPay; plain, spaced, dashed, inside JSON, split across
streamed chunks, inside an uploaded file, base64-encoded) are pushed through the main entry points: the gateway's LLM
intercept, the governed chat (buffered and streamed), the OpenAI-compatible chat (buffered and streamed), the browser
interaction check, browser and endpoint telemetry, MCP authorize, a simulation run and the document completion. Then
every place Hawk keeps or sends anything is scanned for a full PAN (a Luhn-valid 13-19 digit number, plain, grouped,
base64-encoded or inside a Fernet-encrypted ``enc:v1:`` value): every table of the database, the log lines, the error
journal on disk, the troubleshooting report's recent errors, the Redis fake, the Celery task arguments, the sign-in
store, the auditor export (its files on disk and its downloads), the audit-log CSV / JSONL / CEF exports, the activity
export, the incident report, the diagnostics bundle, a SIEM export and a system email. It must find none.

The masking format is ``[card ending 1111]`` (app/services/pci_controls.py).
"""

from __future__ import annotations

import base64
import binascii
import io
import json
import logging
import os
import re
import sqlite3
import tarfile
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")

from app.core import log_config
from app.core.config import settings
from app.db.models.ai_system import AISystem
from app.db.models.enforcement import EnforcementEvent
from app.db.models.policy import PolicyVersion
from app.db.session import Base, get_db
from app.main import app
from app.services import pci_controls

from tests.ai_system_approval_helpers import approve_ai_system

PASSWORD = "Password123!"


# ---------------------------------------------------------------------------------------------------------------------
# Test card numbers (the networks' published test numbers; RuPay's check digit computed)
# ---------------------------------------------------------------------------------------------------------------------


def _luhn_complete(prefix: str) -> str:
    for check in "0123456789":
        if pci_controls.luhn_valid(prefix + check):
            return prefix + check
    raise AssertionError(prefix)


PANS: dict[str, str] = {
    "visa": "4111111111111111",
    "visa_2": "4012888888881881",
    "mastercard": "5555555555554444",
    "mastercard_2series": "2223003122003222",
    "amex": "378282246310005",
    "discover": "6011111111111117",
    "rupay": _luhn_complete("608032100000000"),
    "rupay_65": _luhn_complete("652150000000000"),
}
assert all(pci_controls.luhn_valid(number) for number in PANS.values())


def spaced(number: str) -> str:
    if len(number) == 15:  # Amex: 4-6-5
        return f"{number[:4]} {number[4:10]} {number[10:]}"
    return " ".join(number[i : i + 4] for i in range(0, len(number), 4))


def dashed(number: str) -> str:
    return spaced(number).replace(" ", "-")


# ---------------------------------------------------------------------------------------------------------------------
# The scanner: independent of the code under test
# ---------------------------------------------------------------------------------------------------------------------

_RUN_RE = re.compile(r"[0-9](?:[ \- ]?[0-9])*")
_B64_RE = re.compile(r"[A-Za-z0-9+/_-]{20,}={0,2}")
_FERNET_RE = re.compile(r"enc:v1:([A-Za-z0-9_\-]+=*)")


def _luhn(digits: str) -> bool:
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = int(char)
        if index % 2:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def _brand(digits: str) -> bool:
    from app.services.detection.structured import card_brand

    return card_brand(digits) is not None or digits[:2] in {"60", "65", "81", "82"} or digits[:3] in {"508", "353", "356"}


def _pan_hits(text: str) -> list[str]:
    """Every full card number in ``text``: one of ours anywhere in a digit run (separators ignored), or any Luhn-valid
    13-19 digit run with a card network's prefix."""

    hits: list[str] = []
    for run in _RUN_RE.finditer(text):
        digits = re.sub(r"[^0-9]", "", run.group(0))
        if len(digits) < 13:
            continue
        for name, number in PANS.items():
            if number in digits:
                hits.append(f"{name}:{run.group(0)[:40]}")
        if 13 <= len(digits) <= 19 and _luhn(digits) and _brand(digits) and len(set(digits)) > 1:
            hits.append(f"luhn:{run.group(0)[:40]}")
    return hits


def _decoded_segments(text: str) -> list[str]:
    out: list[str] = []
    for match in _B64_RE.finditer(text):
        segment = match.group(0)
        padded = segment.rstrip("=") + "=" * (-len(segment.rstrip("=")) % 4)
        for decode in (base64.b64decode, base64.urlsafe_b64decode):
            try:
                out.append(decode(padded).decode("latin-1"))
            except (binascii.Error, ValueError):
                continue
    return out


def _decrypted_segments(text: str) -> list[str]:
    from app.services.enforcement_payload_crypto_service import decrypt_enforcement_prompt

    out = []
    for match in _FERNET_RE.finditer(text):
        try:
            out.append(decrypt_enforcement_prompt(match.group(0)))
        except Exception:  # noqa: BLE001
            continue
    return out


_IDENTIFIER_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32,})(?![0-9A-Fa-f])"
)


def scan(text: str, *, where: str) -> list[str]:
    # Record ids (UUIDs) and hex digests are not card numbers (a digit run inside one is not either).
    text = _IDENTIFIER_RE.sub(" ", text)
    findings = [f"{where}: {hit}" for hit in _pan_hits(text)]
    for decoded in _decoded_segments(text):
        findings += [f"{where} (base64): {hit}" for hit in _pan_hits(decoded)]
    for plain in _decrypted_segments(text):
        findings += [f"{where} (encrypted enc:v1): {hit}" for hit in _pan_hits(plain)]
    return findings


def scan_sqlite(db_file: Path) -> list[str]:
    findings: list[str] = []
    con = sqlite3.connect(str(db_file))
    try:
        tables = [row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")]
        for table in tables:
            columns = [row[1] for row in con.execute(f'PRAGMA table_info("{table}")')]
            for row in con.execute(f'SELECT * FROM "{table}"'):  # noqa: S608 - table names from sqlite_master
                for column, value in zip(columns, row):
                    if value is None or isinstance(value, (int, float)) and not isinstance(value, bool):
                        if isinstance(value, int) and 13 <= len(str(value)) <= 19:
                            findings += scan(str(value), where=f"db:{table}.{column}")
                        continue
                    text = value.decode("latin-1") if isinstance(value, bytes) else str(value)
                    findings += scan(text, where=f"db:{table}.{column}")
    finally:
        con.close()
    return findings


def scan_tree(root: Path, *, where: str) -> list[str]:
    findings: list[str] = []
    if not root.exists():
        return findings
    for file in sorted(root.rglob("*")):
        if not file.is_file():
            continue
        data = file.read_bytes()
        findings += scan_bytes(data, where=f"{where}:{file.relative_to(root)}")
    return findings


def scan_bytes(data: bytes, *, where: str) -> list[str]:
    findings: list[str] = []
    if data[:2] == b"\x1f\x8b":
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
                for member in tar.getmembers():
                    handle = tar.extractfile(member)
                    if handle is not None:
                        findings += scan_bytes(handle.read(), where=f"{where}!{member.name}")
            return findings
        except tarfile.TarError:
            import gzip

            data = gzip.decompress(data)
    if data[:2] == b"PK":
        import zipfile

        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name in archive.namelist():
                findings += scan_bytes(archive.read(name), where=f"{where}!{name}")
        return findings
    if data[:5] == b"%PDF-":
        try:
            import fitz

            with fitz.open(stream=data, filetype="pdf") as pdf:
                text = "\n".join(page.get_text() for page in pdf)
            findings += scan(text, where=f"{where}(pdf text)")
        except Exception:  # noqa: BLE001 - fall back to the raw bytes
            pass
    return findings + scan(data.decode("utf-8", errors="replace"), where=where)


def test_scanner_finds_every_form_and_masking_hides_each() -> None:
    """The scanner sees every form the harness sends; scrub_pan turns each into [card ending NNNN]."""

    for number in PANS.values():
        for form in (number, spaced(number), dashed(number), json.dumps({"pan": number}), " ".join(number)):
            assert scan(form, where="t"), form
            masked = pci_controls.scrub_pan(form)
            assert not scan(masked, where="t"), (form, masked)
            assert f"[card ending {number[-4:]}]" in masked
        encoded = base64.b64encode(f"card {spaced(number)} exp 12/29".encode()).decode()
        assert scan(encoded, where="t")
        assert not scan(pci_controls.scrub_pan(f"file={encoded}"), where="t")
    # Ids and digests are never touched.
    ident = str(uuid4())
    digest = "4111111111111111" * 4
    assert pci_controls.scrub_pan(f"{ident} {digest}") == f"{ident} {digest}"


# ---------------------------------------------------------------------------------------------------------------------
# The environment: a file database, a data folder, captured logs, a Redis fake, recorded Celery calls
# ---------------------------------------------------------------------------------------------------------------------


class FakeRedis:
    """Records every key and value written; answers like an empty Redis."""

    def __init__(self) -> None:
        self.writes: list[str] = []
        self.data: dict[str, Any] = {}

    def _record(self, *parts: Any) -> None:
        self.writes.append(" ".join(str(p) for p in parts))

    def set(self, key, value, *args, **kwargs):  # noqa: ANN001
        self._record("set", key, value)
        self.data[str(key)] = value
        return True

    def setex(self, key, ttl, value):  # noqa: ANN001
        return self.set(key, value)

    def get(self, key):  # noqa: ANN001
        return self.data.get(str(key))

    def getdel(self, key):  # noqa: ANN001
        return self.data.pop(str(key), None)

    def delete(self, *keys):  # noqa: ANN001
        for key in keys:
            self.data.pop(str(key), None)
        return 1

    def incr(self, key, amount=1):  # noqa: ANN001
        self._record("incr", key)
        self.data[str(key)] = int(self.data.get(str(key)) or 0) + amount
        return self.data[str(key)]

    def expire(self, *args, **kwargs):  # noqa: ANN001
        return True

    def mget(self, keys):  # noqa: ANN001
        return [self.data.get(str(k)) for k in keys]

    def hset(self, key, *args, mapping=None, **kwargs):  # noqa: ANN001
        self._record("hset", key, args, mapping, kwargs)
        return 1

    def lpush(self, key, *values):  # noqa: ANN001
        self._record("lpush", key, values)
        return len(values)

    rpush = lpush

    def zadd(self, key, mapping, *args, **kwargs):  # noqa: ANN001
        self._record("zadd", key, mapping)
        return 1

    def ping(self):  # noqa: ANN201
        return True

    def pipeline(self, *args, **kwargs):  # noqa: ANN001, ANN201
        return self

    def execute(self):  # noqa: ANN201
        return []

    def eval(self, *args, **kwargs):  # noqa: ANN001, ANN201
        self._record("eval", args)
        return None

    def __getattr__(self, name: str):  # anything else: record it, answer nothing
        def call(*args: Any, **kwargs: Any) -> Any:
            self._record(name, args, kwargs)
            return None

        return call

    def __enter__(self):  # noqa: ANN204
        return self

    def __exit__(self, *exc: Any) -> None:
        return None

    def close(self) -> None:
        return None


class _TaskResult:
    id = "task-recorded"

    def get(self, *args: Any, **kwargs: Any) -> Any:
        raise TimeoutError("no worker in the tests")

    def forget(self) -> None:
        return None


@pytest.fixture()
def pci_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    artifacts = tmp_path / "artifacts"
    monkeypatch.setenv("ARTIFACT_DIR", str(artifacts))
    monkeypatch.setattr(settings, "hawk_data_dir", str(data_dir), raising=False)
    monkeypatch.setattr(settings, "native_control_framework", False)
    monkeypatch.setattr(settings, "trusted_control_selector", False)
    # A small file goes through the OCR task, so its arguments are recorded.
    monkeypatch.setattr(settings, "sensitive_detection_async_ocr_enabled", True, raising=False)
    monkeypatch.setattr(settings, "sensitive_detection_async_ocr_min_bytes", 16, raising=False)

    db_file = tmp_path / "pci.sqlite3"
    engine = create_engine(f"sqlite+pysqlite:///{db_file}", connect_args={"check_same_thread": False})
    session_local = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    Base.metadata.create_all(bind=engine)

    def override_get_db():
        db = session_local()
        try:
            yield db
        finally:
            db.close()

    # Logs: every line as it would be written (JSON), the error journal on disk, the recent errors.
    stream = io.StringIO()
    line_handler = logging.StreamHandler(stream)
    line_handler.setFormatter(log_config.JsonFormatter(service="api"))
    line_handler.setLevel(logging.DEBUG)
    journal = log_config.ErrorJournalHandler(service="api", data_dir=data_dir)
    recent = log_config.RecentErrorsHandler()
    root = logging.getLogger()
    previous_level = root.level
    root.setLevel(logging.DEBUG)
    for handler in (line_handler, journal, recent):
        root.addHandler(handler)

    # Redis: every client the code makes is the fake.
    fake_redis = FakeRedis()
    import redis

    monkeypatch.setattr(redis.Redis, "from_url", classmethod(lambda cls, *a, **k: fake_redis))
    from app.services import sign_in_store

    memory_store = sign_in_store.MemoryStore()
    sign_in_store.use(memory_store)

    # Celery: every task sent is recorded, none runs.
    celery_calls: list[str] = []
    from celery.app.task import Task

    from app.jobs.celery_app import celery_app

    def record_send(name, args=None, kwargs=None, **options):  # noqa: ANN001, ANN202
        celery_calls.append(json.dumps({"task": name, "args": args, "kwargs": kwargs}, default=str))
        return _TaskResult()

    def record_apply(self, args=None, kwargs=None, **options):  # noqa: ANN001, ANN202
        celery_calls.append(json.dumps({"task": self.name, "args": args, "kwargs": kwargs}, default=str))
        return _TaskResult()

    monkeypatch.setattr(celery_app, "send_task", record_send)
    monkeypatch.setattr(Task, "apply_async", record_apply)

    class CardProvider:
        """Answers with card numbers of its own; streams one split across chunks."""

        model = "gpt-mock"

        def generate_text(self, system_prompt: str, user_prompt: str) -> str:
            del system_prompt, user_prompt
            return f"Customer card on file: {spaced(PANS['mastercard'])}; backup {PANS['discover']}."

        def stream_text(self, system_prompt: str, user_prompt: str, usage_sink=None):  # noqa: ANN001, ANN201
            del system_prompt, user_prompt
            number = spaced(PANS["amex"])
            yield "Your card "
            yield number[:7]
            yield number[7:]
            yield f" and {dashed(PANS['rupay'])[:9]}"
            yield f"{dashed(PANS['rupay'])[9:]} are on file."

        def generate_json(self, system_prompt: str, user_prompt: str, json_schema: dict) -> dict:
            payload = json.loads(user_prompt.removeprefix("[user]\n"))
            if payload.get("mode") == "draft":
                return {"blocks": [{"kind": "paragraph", "text": f"Card {PANS['visa_2']} approved"}]}
            return {
                "edits": [
                    {"id": block["id"], "rows": block["rows"]} if block["kind"] == "table" else {"id": block["id"], "text": block["text"]}
                    for block in payload["blocks"]
                ]
            }

    monkeypatch.setattr(
        "app.services.llm_gateway_service._load_provider",
        lambda provider, model: (CardProvider(), {"azure-openai": "azure_openai"}.get(str(provider), str(provider)), model or "gpt-mock"),
    )

    pci_controls.reset_masked_counts()
    app.dependency_overrides[get_db] = override_get_db
    client = TestClient(app)
    try:
        yield {
            "client": client,
            "SessionLocal": session_local,
            "db_file": db_file,
            "data_dir": data_dir,
            "artifacts": artifacts,
            "log_stream": stream,
            "recent": recent,
            "redis": fake_redis,
            "sign_in_store": memory_store,
            "celery_calls": celery_calls,
        }
    finally:
        client.close()
        app.dependency_overrides.clear()
        for handler in (line_handler, journal, recent):
            root.removeHandler(handler)
        root.setLevel(previous_level)
        sign_in_store.use(None)
        Base.metadata.drop_all(bind=engine)
        engine.dispose()


# ---------------------------------------------------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------------------------------------------------


def _owner(client: TestClient) -> dict[str, str]:
    response = client.post("/auth/register", json={"email": "pci-owner@example.com", "password": PASSWORD, "full_name": "PCI Owner"})
    assert response.status_code == 200, response.text
    body = response.json()
    return {
        "access_token": body["access_token"],
        "token": body["access_token"],
        "tenant_id": body["tenants"][0]["id"],
        "user_id": body["user"]["id"],
    }


def _headers(owner: dict[str, str]) -> dict[str, str]:
    return {"Authorization": f"Bearer {owner['access_token']}", "X-Tenant-ID": owner["tenant_id"]}


def _ai_system(client: TestClient, headers: dict[str, str], session_local: sessionmaker) -> str:
    response = client.post("/ai-systems", headers=headers, json={"name": "Card Desk Assistant", "description": "", "risk_tier": "LOW"})
    assert response.status_code == 200, response.text
    ai_system_id = response.json()["id"]
    approve_ai_system(client, headers, ai_system_id)
    with session_local() as db:
        row = db.get(AISystem, ai_system_id)
        metadata = dict(row.metadata_json or {})
        metadata.update(
            {
                "governance_state": "APPROVED",
                "lifecycle_state": "ACTIVE",
                "ownership_state": "APPROVED",
                "status_classification": "approved",
                "business_owner": "PCI Owner",
                "technical_owner": "PCI Owner",
            }
        )
        row.status = "active"
        row.metadata_json = metadata
        db.commit()
    return ai_system_id


def _policy_version(client: TestClient, headers: dict[str, str], session_local: sessionmaker, *, masking: bool) -> str:
    response = client.post("/policies/packs", headers=headers, json={"name": f"Card Pack {uuid4().hex[:6]}", "description": "pci", "status": "active"})
    assert response.status_code == 200, response.text
    version_id = response.json()["default_version"]["id"]
    if masking:
        with session_local.begin() as db:
            policy = db.get(PolicyVersion, version_id)
            policy.scope = {
                **dict(policy.scope or {}),
                "llm_gateway_security": {"reversible_masking": {"enabled": True, "documents_enabled": True}},
            }
    return version_id


def _reapprove(session_local: sessionmaker, ai_system_id: str) -> None:
    """Card numbers in the traffic send the system back to review; each step starts from an approved system."""

    with session_local() as db:
        row = db.get(AISystem, ai_system_id)
        row.metadata_json = {**dict(row.metadata_json or {}), "governance_state": "APPROVED", "lifecycle_state": "ACTIVE"}
        row.status = "approved"
        db.commit()


def _not_server_error(response: Any, what: str) -> None:
    print(f"PCI-STEP {what}: {response.status_code} {response.text[:300] if response.status_code >= 300 else ''}")
    assert response.status_code < 500, f"{what}: {response.status_code} {response.text[:500]}"


def _card_prompt() -> str:
    return (
        f"Refund the customer: card {spaced(PANS['visa'])}, second card {dashed(PANS['mastercard_2series'])}, "
        f"amex {PANS['amex']}, and the JSON {json.dumps({'card_number': PANS['rupay_65']})}."
    )


# ---------------------------------------------------------------------------------------------------------------------
# The harness
# ---------------------------------------------------------------------------------------------------------------------


def test_no_full_pan_is_stored_logged_or_exported(pci_env, monkeypatch: pytest.MonkeyPatch) -> None:
    client: TestClient = pci_env["client"]
    session_local: sessionmaker = pci_env["SessionLocal"]
    owner = _owner(client)
    headers = _headers(owner)
    ai_system_id = _ai_system(client, headers, session_local)
    plain_policy = _policy_version(client, headers, session_local, masking=False)
    masking_policy = _policy_version(client, headers, session_local, masking=True)
    prompt = _card_prompt()
    encoded_file = base64.b64encode(f"Statement\nCard: {spaced(PANS['visa_2'])}\nExp 12/29\n".encode()).decode()

    # 1. The gateway's LLM intercept: a prompt, a response, tool output and attachments, all with card numbers.
    response = client.post(
        "/gateway/llm/intercept",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_type": "human",
            "actor_id": "agent-desk",
            "request_id": f"pci-intercept-{uuid4().hex[:8]}",
            "prompt": prompt,
            "context_summary": f"customer pasted {PANS['discover']}",
            "attachments_meta": [{"name": "statement.txt", "mime_type": "text/plain", "content_base64": encoded_file}],
            "tool_output": json.dumps({"lookup": {"pan": PANS["visa"]}}),
            "response_text": f"Card {spaced(PANS['mastercard'])} refunded",
            "provider": "openai",
            "model": "gpt-4.1",
            "tool_usage_meta": {"arguments": {"card": PANS["amex"]}, "note": f"card {PANS['rupay']}"},
        },
    )
    assert response.status_code == 200, response.text

    _reapprove(session_local, ai_system_id)
    # 2. The governed chat, buffered: plain, and with reversible masking.
    for policy_version_id in (plain_policy, masking_policy):
        response = client.post(
            "/llm-gateway/chat/complete",
            headers=headers,
            json={
                "tenant_id": owner["tenant_id"],
                "ai_system_id": ai_system_id,
                "policy_version_id": policy_version_id,
                "provider": "openai",
                "actor_type": "human",
                "actor_id": "agent-desk",
                "messages": [{"role": "system", "content": f"Known card {PANS['visa']}"}, {"role": "user", "content": prompt}],
                "context_summary": f"refund for {dashed(PANS['discover'])}",
                "attachments_meta": [],
                "tool_context": [f"crm lookup: card={PANS['mastercard']}"],
            },
        )
        _not_server_error(response, "chat/complete")

    _reapprove(session_local, ai_system_id)
    # 3. The governed chat, streamed: the provider splits card numbers across chunks.
    response = client.post(
        "/llm-gateway/chat/complete",
        headers=headers,
        json={
            "tenant_id": owner["tenant_id"],
            "ai_system_id": ai_system_id,
            "policy_version_id": plain_policy,
            "provider": "openai",
            "actor_id": "agent-desk",
            "stream": True,
            "messages": [{"role": "user", "content": prompt}],
        },
    )
    _not_server_error(response, "chat/complete stream")

    _reapprove(session_local, ai_system_id)
    # 4. The OpenAI-compatible chat, buffered and streamed.
    for stream in (False, True):
        response = client.post(
            "/openai-compatible/v1/chat/completions",
            headers=headers,
            json={
                "tenant_id": owner["tenant_id"],
                "ai_system_id": ai_system_id,
                "policy_version_id": plain_policy,
                "provider": "azure_openai",
                "model": "gpt-4.1",
                "stream": stream,
                "messages": [{"role": "user", "content": prompt}],
                "metadata": {"actor_type": "human", "actor_id": "foundry-user", "context_summary": f"card {PANS['visa_2']}"},
            },
        )
        _not_server_error(response, f"openai-compatible stream={stream}")

    _reapprove(session_local, ai_system_id)
    # 5. The browser interaction check: the raw prompt, the extension's own preview, a file (base64) and its text.
    for path in ("/telemetry/browser/interaction-eval", "/telemetry/desktop/interaction-eval"):
        response = client.post(
            path,
            headers=headers,
            json={
                "correlation_id": f"pci-{uuid4().hex[:8]}",
                "domain": "chat.openai.com",
                "url": f"https://chat.openai.com/c/1?card={PANS['visa']}",
                "raw_prompt": prompt,
                "prompt_preview_redacted": f"Refund card {spaced(PANS['visa'])}",
                "input_signal_types": ["sensitive_data_pattern"],
                "file_meta": [
                    {"name": f"card-{PANS['discover']}.txt", "mime_type": "text/plain", "content_base64": encoded_file},
                    {"name": "notes.txt", "mime_type": "text/plain", "extracted_text": f"PAN {dashed(PANS['mastercard'])}"},
                ],
                "browser": "chrome",
                "browser_profile": "work",
                "endpoint_id": "endpoint-pci-a",
            },
        )
        _not_server_error(response, path)

    # 6. Browser telemetry.
    response = client.post(
        "/telemetry/browser",
        headers=headers,
        json={
            "event_type": "prompt_blocked",
            "ai_system_id": ai_system_id,
            "domain": "chatgpt.com",
            "url": "https://chatgpt.com",
            "action_taken": "block",
            "severity": "high",
            "prompt_preview_redacted": f"card {PANS['amex']} pasted",
            "input_signal_types": ["sensitive_data_pattern"],
            "metadata": {"clipboard": f"{spaced(PANS['rupay'])}", "nested": {"pan": int(PANS["visa_2"])}},
        },
    )
    _not_server_error(response, "telemetry/browser")

    # 7. Endpoint telemetry, from an enrolled device.
    from tests.test_endpoint_agent import _endpoint_headers, _enroll_endpoint

    key, token = _enroll_endpoint(client, owner)
    path = "/endpoint-agent/telemetry"
    response = client.post(
        path,
        headers=_endpoint_headers(key, token, owner, method="POST", path=path, jti=f"pci-{uuid4().hex[:8]}"),
        json={
            "event_type": "prompt_submitted",
            "domain": "claude.ai",
            "url": "https://claude.ai",
            "action_taken": "warn",
            "severity": "medium",
            "prompt_preview_redacted": f"card {dashed(PANS['visa'])}",
            "input_signal_types": ["sensitive_data_pattern"],
            "metadata": {"window_title": f"Invoice {PANS['mastercard']}"},
        },
    )
    _not_server_error(response, "endpoint-agent/telemetry")

    _reapprove(session_local, ai_system_id)
    # 8. MCP authorize: the resource and the tool's arguments carry a card number (refused: no capability token).
    response = client.post(
        "/gateway/mcp/authorize",
        headers=headers,
        json={
            "ai_system_id": ai_system_id,
            "actor_id": "agent-mcp",
            "capability_token": "not-a-token",
            "action": "tool.write",
            "resource": f"payments://cards/{PANS['visa']}",
            "tool_name": "payments",
            "tool_usage_meta": {"arguments": {"pan": PANS["discover"]}, "summary": f"charge {spaced(PANS['amex'])}"},
            "session_context": {"note": f"card {PANS['rupay']}"},
        },
    )
    _not_server_error(response, "mcp/authorize")

    _reapprove(session_local, ai_system_id)
    # 9. A simulation whose step and inputs carry card numbers.
    control_id = f"CTRL-PCI-{uuid4().hex[:6]}"
    response = client.post(
        "/simulations/controls",
        headers=headers,
        json={"id": control_id, "name": "PCI control", "category": "monitoring", "description": "pci", "mapped_framework_refs": [], "is_global": False},
    )
    _not_server_error(response, "simulations/controls")
    dsl = {
        "id": f"dsl-pci-{uuid4()}",
        "tenant_id": owner["tenant_id"],
        "name": "Card leak simulation",
        "category": "injection",
        "target_module": "interaction_security",
        "version": "1.0.0",
        "safety": {"requires_sandbox": True, "max_runtime_seconds": 60, "no_external_network": True},
        "inputs_schema": {"fields": []},
        "steps": [
            {
                "step_id": "s1",
                "kind": "llm_intercept",
                "payload_template": {
                    "actor_type": "system",
                    "actor_id": "simulator",
                    "request_id": f"pci-sim-{uuid4().hex[:8]}",
                    "prompt": f"Charge card {spaced(PANS['mastercard'])}",
                    "context_summary": f"simulation card {PANS['visa']}",
                    "attachments_meta": [],
                },
                "variable_bindings": {},
            }
        ],
        "assertions": [
            {
                "assertion_id": "a1",
                "check": {"field": "s1.final_decision", "operator": "equals", "value": "allow"},
                "on_fail": {"result": "fail", "evidence_signal_type": "simulation.fail", "severity": "high"},
            }
        ],
        "maps_to_controls": [control_id],
        "expected_outcomes": {"pass_conditions": ["assertion passes"], "fail_conditions": ["assertion fails"]},
    }
    response = client.post(
        "/simulations/definitions",
        headers=headers,
        json={"name": dsl["name"], "category": dsl["category"], "target_module": dsl["target_module"], "version": dsl["version"], "dsl_json": dsl},
    )
    _not_server_error(response, "simulations/definitions")
    if response.status_code == 200:
        simulation_id = response.json()["id"]
        response = client.post(
            f"/simulations/definitions/{simulation_id}/run",
            headers=headers,
            json={"ai_system_id": ai_system_id, "mode": "deterministic", "inputs_used": {"card": PANS["amex"], "note": dashed(PANS["discover"])}},
        )
        _not_server_error(response, "simulation run")

    _reapprove(session_local, ai_system_id)
    # 10. Document completion: a draft, and a transform of an uploaded DOCX holding card numbers.
    from docx import Document

    fields = {
        "tenant_id": owner["tenant_id"],
        "ai_system_id": ai_system_id,
        "policy_version_id": masking_policy,
        "provider": "openai",
        "output_format": "docx",
    }
    response = client.post("/llm-gateway/documents/complete", headers=headers, data={**fields, "mode": "draft", "instruction": f"Letter about card {spaced(PANS['visa'])}"})
    _not_server_error(response, "documents draft")
    _reapprove(session_local, ai_system_id)
    source = Document()
    source.add_paragraph(f"Card on file: {spaced(PANS['mastercard'])}")
    table = source.add_table(rows=1, cols=2)
    table.cell(0, 0).text = "PAN"
    table.cell(0, 1).text = PANS["discover"]
    out = io.BytesIO()
    source.save(out)
    response = client.post(
        "/llm-gateway/documents/complete",
        headers=headers,
        data={**fields, "mode": "transform", "instruction": "Keep all cells"},
        files={"file": ("cards.docx", out.getvalue(), "application/vnd.openxmlformats-officedocument.wordprocessingml.document")},
    )
    _not_server_error(response, "documents transform")

    # 11. An error with a card number in its text, as a failing provider or parser would log it.
    logger = logging.getLogger("app.services.pci_harness")
    try:
        raise ValueError(f"could not parse card {spaced(PANS['visa'])}")
    except ValueError:
        logger.exception("provider call failed for %s", PANS["mastercard"], extra={"card": PANS["amex"], "pan_number": int(PANS["visa_2"])})
    logger.error("refund failed: %s", json.dumps({"pan": PANS["discover"]}))

    # 12. Exports: the auditor export (files on disk and downloads), the audit-log exports, the activity export, the
    # incident report, the diagnostics bundle, a SIEM export and a system email.
    exported: list[tuple[str, bytes]] = []
    _reapprove(session_local, ai_system_id)
    response = client.post("/auditor/export", headers=headers, json={"ai_system_id": ai_system_id})
    _not_server_error(response, "auditor/export")
    if response.status_code == 200:
        body = response.json()
        exported.append(("auditor/export response", response.content))
        for name, url in dict(body.get("download_urls") or {}).items():
            downloaded = client.get(url, headers=headers)
            if downloaded.status_code == 200:
                exported.append((f"auditor artifact {name}", downloaded.content))
    for url in (
        "/audit/log/export.csv",
        "/audit/log/export.jsonl",
        "/audit/log/export.cef",
        "/activity/log/export.csv",
        "/compliance/incident-report",
        "/diagnostics/bundle",
        "/llm-gateway/logs",
    ):
        downloaded = client.get(url, headers=headers)
        _not_server_error(downloaded, url)
        if downloaded.status_code == 200:
            exported.append((url, downloaded.content))

    monkeypatch.setattr(settings, "siem_export_enabled", True)
    monkeypatch.setattr(settings, "siem_pseudonymization_key", "vJ3nHh4K_r9Q2pLm7Xs5cTa8Wz1Dg6FyB0uE")
    from app.services.siem_export_service import build_siem_export

    with session_local() as db:
        rows = db.scalars(select(EnforcementEvent).where(EnforcementEvent.tenant_id == owner["tenant_id"])).all()
        events = [
            {
                "tenant_id": owner["tenant_id"],
                "event_id": row.id,
                "event_type": "policy.violation",
                "created_at": "2026-11-27T10:00:00Z",
                "summary": f"card {spaced(PANS['visa'])} seen",
                "details": {"final_actions": row.final_actions, "pan": PANS["amex"]},
            }
            for row in rows
        ] or [{"tenant_id": owner["tenant_id"], "event_id": "evt-1", "summary": f"card {PANS['visa']}"}]
    for adapter in ("generic", "sentinel"):
        batch = build_siem_export(tenant_id=owner["tenant_id"], events=events, adapter=adapter)
        exported.append((f"siem export {adapter}", batch.ndjson.encode()))

    from app.services import mailer

    message = mailer.system_email(
        subject=f"Hawk AI: refund for card {PANS['visa']} failed",
        lines=[f"The provider said: card {spaced(PANS['mastercard'])} declined."],
        facts=[("Card", dashed(PANS["discover"]))],
        footer=f"reference {PANS['amex']}",
    )
    exported.append(("system email", message.as_bytes()))

    # ---- The scan -------------------------------------------------------------------------------------------------
    findings: list[str] = []
    findings += scan_sqlite(pci_env["db_file"])
    findings += scan(pci_env["log_stream"].getvalue(), where="log lines")
    findings += scan(json.dumps(pci_env["recent"].lines(50)), where="recent errors")
    findings += scan_tree(pci_env["data_dir"], where="data folder")
    findings += scan_tree(pci_env["artifacts"], where="auditor artifacts on disk")
    findings += scan("\n".join(pci_env["redis"].writes) + json.dumps(pci_env["redis"].data, default=str), where="redis")
    findings += scan(json.dumps({k: str(v) for k, v in pci_env["sign_in_store"]._values.items()}), where="sign-in store")
    findings += scan("\n".join(pci_env["celery_calls"]), where="celery task arguments")
    for where, data in exported:
        findings += scan_bytes(data, where=where)

    assert not findings, "full card numbers found:\n" + "\n".join(sorted(set(findings))[:200])

    # Something was actually there to mask, and the journal and log lines were written.
    assert pci_controls.masked_counts(), "no card number reached a boundary: the harness tested nothing"
    assert "[card ending " in pci_env["log_stream"].getvalue()
    assert (pci_env["data_dir"] / "logs" / "errors-api.jsonl").exists()

    # The audit chain still verifies over the masked rows (its MAC is computed after the mask).
    from app.services import audit_chain

    with session_local() as db:
        for chain in audit_chain.chains(db):
            result = audit_chain.verify(db, chain)
            assert result["ok"] is True and result["entries"] > 0, (chain, result)


def test_pan_protection_status_reports_enforced_boundaries() -> None:
    status = pci_controls.pan_protection_status()
    assert status["enforced"] is True
    assert status["masking_format"] == "[card ending NNNN]"
    assert status["boundaries"]["database"] is True
    assert status["boundaries"]["logs"] is True
    assert "3.4.1" in status["pci_dss"]["supported"]


def test_hashes_of_what_was_seen_are_kept_from_the_original(pci_env) -> None:
    """The gateway's prompt hash is the SHA-256 of the original prompt (with the card number), so it still proves what
    was seen; the stored rows hold that hash and only the masked text."""

    import hashlib

    client: TestClient = pci_env["client"]
    session_local: sessionmaker = pci_env["SessionLocal"]
    owner = _owner(client)
    headers = _headers(owner)
    ai_system_id = _ai_system(client, headers, session_local)
    policy_version_id = _policy_version(client, headers, session_local, masking=False)
    prompt = f"Refund card {spaced(PANS['visa'])} today"
    response = client.post(
        "/llm-gateway/request",
        headers=headers,
        json={
            "tenant_id": owner["tenant_id"],
            "ai_system_id": ai_system_id,
            "policy_version_id": policy_version_id,
            "provider": "openai",
            "actor_type": "human",
            "actor_id": "desk",
            "prompt": prompt,
            "context_summary": "",
            "attachments_meta": [],
            "tool_context": [],
        },
    )
    assert response.status_code == 200, response.text
    body = response.json()
    original_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()
    assert body["prompt_hash"] == original_hash
    with session_local() as db:
        event = db.get(EnforcementEvent, body["event_id"])
        assert event is not None
        assert ((event.final_actions or {}).get("_trace") or {}).get("prompt_hash") == original_hash
    assert not scan_sqlite(pci_env["db_file"])


def test_signed_receipts_and_evidence_bundles_still_verify_over_masked_rows(pci_env, monkeypatch: pytest.MonkeyPatch) -> None:
    """Decision / execution receipts and canonical evidence bundles are signed by the gateway; with card numbers in the
    call (even in the caller's request id) they are stored masked and still verify."""

    from app.db.models.evidence import DecisionReceipt, EvidenceNode, ExecutionReceipt
    from app.db.models.user import User
    from app.services import receipt_service
    from app.services.canonical_evidence_bundle_service import BUNDLE_ROOT_TYPE, verify_evidence_bundle

    client: TestClient = pci_env["client"]
    session_local: sessionmaker = pci_env["SessionLocal"]
    owner = _owner(client)
    headers = _headers(owner)
    ai_system_id = _ai_system(client, headers, session_local)
    policy_version_id = _policy_version(client, headers, session_local, masking=False)
    with session_local() as db:
        actor_id = db.scalar(select(User.id).where(User.email == "pci-owner@example.com"))
    monkeypatch.setattr(settings, "authorization_kernel_v2_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_shadow_compare_enabled", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce", True)
    monkeypatch.setattr(settings, "authorization_kernel_v2_enforce_rollout", f'{{"{owner["tenant_id"]}":["llm_gateway"]}}')
    monkeypatch.setattr(settings, "canonical_ai_action_dual_write_enabled", False)
    monkeypatch.setattr(settings, "canonical_action_binding_key", "pci-receipt-binding-key-0000000001")
    monkeypatch.setattr(settings, "decision_execution_receipts_enabled", True)
    monkeypatch.setattr(settings, "receipt_signing_active_key_id", "pci-receipt-key")
    monkeypatch.setattr(settings, "receipt_signing_keys_json", '{"pci-receipt-key":"pci-receipt-signing-material-0000000001"}')

    for request_id in (f"refund-{PANS['visa']}", f"refund {spaced(PANS['mastercard'])}"):
        _reapprove(session_local, ai_system_id)
        response = client.post(
            "/llm-gateway/chat/complete",
            headers=headers,
            json={
                "tenant_id": owner["tenant_id"],
                "ai_system_id": ai_system_id,
                "policy_version_id": policy_version_id,
                "provider": "openai",
                "actor_type": "human",
                "actor_id": actor_id,
                "request_id": request_id,
                "messages": [{"role": "user", "content": _card_prompt()}],
                "context_summary": f"refund {PANS['discover']}",
                "attachments_meta": [],
                "tool_context": [],
            },
        )
        _not_server_error(response, "chat/complete with receipts")

    assert not scan_sqlite(pci_env["db_file"])
    with session_local() as db:
        decisions = db.scalars(select(DecisionReceipt).where(DecisionReceipt.tenant_id == owner["tenant_id"])).all()
        for receipt in decisions:
            assert receipt_service.verify_decision_receipt(receipt, tenant_id=owner["tenant_id"], settings_obj=settings, db=db), receipt.receipt_id
            assert receipt_service.verify_receipt_evidence(db, tenant_id=owner["tenant_id"], receipt=receipt)
        for receipt in db.scalars(select(ExecutionReceipt).where(ExecutionReceipt.tenant_id == owner["tenant_id"])).all():
            assert receipt_service.verify_execution_receipt(receipt, tenant_id=owner["tenant_id"], settings_obj=settings)
            assert receipt_service.verify_receipt_evidence(db, tenant_id=owner["tenant_id"], receipt=receipt)
        bundles = db.scalars(
            select(EvidenceNode).where(EvidenceNode.tenant_id == owner["tenant_id"], EvidenceNode.node_type == BUNDLE_ROOT_TYPE)
        ).all()
        for bundle in bundles:
            result = verify_evidence_bundle(db, tenant_id=owner["tenant_id"], bundle=bundle, settings_obj=settings)
            assert result["signature_valid"], result
        # The audit entries that quoted the request id hold it masked, and their chain still verifies.
        from app.services import audit_chain

        for chain in audit_chain.chains(db):
            verified = audit_chain.verify(db, chain)
            assert verified["ok"] is True, (chain, verified)
    assert decisions, "no receipt was issued: the test checked nothing"
