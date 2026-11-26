"""Per-tenant detection profile: which DLP categories are on, custom dictionaries, exact-data-match sets and the
prompt-injection thresholds; plus the context variable through which the decision paths hand it to the detectors.

A tenant with no saved settings gets ``DEFAULT_PROFILE``, which is what every tenant had before settings existed.
"""

from __future__ import annotations

import contextvars
import functools
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, TypeVar

from app.services.detection.categories import DOCUMENT_CATEGORIES, CustomDictionary
from app.services.detection.fingerprints import FingerprintSet

# Every toggle the console and API know about. Entity types cover both the validated detectors and the long-standing
# pattern detectors (``person``, ``address``, ``organization``, ``bank_account``).
ENTITY_TYPES: tuple[str, ...] = (
    "credit_card", "iban", "bank_account", "emirates_id", "us_ssn", "uk_nino", "passport", "email", "phone",
    "ip_address", "date_of_birth", "api_key", "private_key", "credential", "person", "address", "organization",
)
TOGGLE_KEYS: tuple[str, ...] = (*ENTITY_TYPES, *DOCUMENT_CATEGORIES, "exact_data_match", "custom_dictionary")

# Entity types that make a payload "sensitive" (protected data). ``ip_address`` is reported but not sensitive unless a
# tenant says so.
DEFAULT_SENSITIVE_TYPES: frozenset[str] = frozenset(
    {
        "email", "phone", "credit_card", "api_key", "emirates_id", "bank_account", "person", "address", "organization",
        "iban", "us_ssn", "uk_nino", "passport", "private_key", "credential", "date_of_birth", "exact_data_match",
    }
)

INJECTION_ACTIONS = ("block", "hold", "redact", "log")
DEFAULT_INJECTION_THRESHOLDS: dict[str, float | None] = {"block": 0.85, "hold": None, "redact": None, "log": 0.5}
DEFAULT_DOCUMENT_MIN_SCORE = 0.6
REPORT_MIN_CONFIDENCE = 0.7

MAX_DICTIONARIES = 50
MAX_TERMS_PER_DICTIONARY = 500
MAX_TERM_CHARS = 120

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_\-]{0,47}$")


@dataclass(frozen=True)
class DetectionProfile:
    tenant_id: str | None = None
    revision: int = 0
    disabled: frozenset[str] = frozenset()
    sensitive_types: frozenset[str] = DEFAULT_SENSITIVE_TYPES
    document_min_score: float = DEFAULT_DOCUMENT_MIN_SCORE
    sensitive_categories: frozenset[str] = frozenset(DOCUMENT_CATEGORIES)
    ner_enabled: bool = True
    custom_dictionaries: tuple[CustomDictionary, ...] = ()
    fingerprint_salt: str = ""
    fingerprint_sets: tuple[FingerprintSet, ...] = ()
    injection_enabled: bool = True
    injection_thresholds: dict[str, float | None] = field(default_factory=lambda: dict(DEFAULT_INJECTION_THRESHOLDS))

    def enabled(self, key: str) -> bool:
        return key not in self.disabled

    def injection_decision(self, risk: float) -> str:
        """block | hold | redact | log | allow for a risk score, highest action first."""
        if not self.injection_enabled:
            return "allow"
        for action in INJECTION_ACTIONS:
            threshold = self.injection_thresholds.get(action)
            if threshold is not None and risk >= threshold:
                return action
        return "allow"


DEFAULT_PROFILE = DetectionProfile()


def default_config() -> dict[str, Any]:
    return {
        "dlp": {
            "categories": {key: True for key in TOGGLE_KEYS},
            "sensitive_categories": list(DOCUMENT_CATEGORIES),
            "document_min_score": DEFAULT_DOCUMENT_MIN_SCORE,
            "ner_enabled": True,
            "ip_address_sensitive": False,
            "custom_dictionaries": [],
        },
        "prompt_injection": {"enabled": True, "thresholds": dict(DEFAULT_INJECTION_THRESHOLDS)},
    }


class ConfigError(ValueError):
    pass


def _float(value: Any, name: str, *, allow_none: bool = False) -> float | None:
    if value is None and allow_none:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ConfigError(f"{name} must be a number between 0 and 1") from None
    if not 0.0 <= number <= 1.0:
        raise ConfigError(f"{name} must be between 0 and 1")
    return round(number, 4)


def sanitize_config(raw: Any) -> dict[str, Any]:
    """Validate a settings body and return the full, normalised config (missing parts take the defaults)."""
    if raw is None:
        raw = {}
    if not isinstance(raw, dict):
        raise ConfigError("settings must be an object")
    config = default_config()
    dlp_in = raw.get("dlp") or {}
    if not isinstance(dlp_in, dict):
        raise ConfigError("dlp must be an object")
    categories_in = dlp_in.get("categories") or {}
    if not isinstance(categories_in, dict):
        raise ConfigError("dlp.categories must be an object of booleans")
    for key, value in categories_in.items():
        if key not in TOGGLE_KEYS:
            raise ConfigError(f"unknown category {key!r}")
        if not isinstance(value, bool):
            raise ConfigError(f"dlp.categories.{key} must be true or false")
        config["dlp"]["categories"][key] = value
    if "sensitive_categories" in dlp_in:
        values = dlp_in.get("sensitive_categories")
        if not isinstance(values, list) or any(v not in DOCUMENT_CATEGORIES for v in values):
            raise ConfigError(f"dlp.sensitive_categories must list some of {', '.join(DOCUMENT_CATEGORIES)}")
        config["dlp"]["sensitive_categories"] = sorted(set(values), key=DOCUMENT_CATEGORIES.index)
    if "document_min_score" in dlp_in:
        config["dlp"]["document_min_score"] = _float(dlp_in.get("document_min_score"), "dlp.document_min_score")
    for flag in ("ner_enabled", "ip_address_sensitive"):
        if flag in dlp_in:
            if not isinstance(dlp_in[flag], bool):
                raise ConfigError(f"dlp.{flag} must be true or false")
            config["dlp"][flag] = dlp_in[flag]
    dictionaries_in = dlp_in.get("custom_dictionaries") or []
    if not isinstance(dictionaries_in, list) or len(dictionaries_in) > MAX_DICTIONARIES:
        raise ConfigError(f"dlp.custom_dictionaries must be a list of at most {MAX_DICTIONARIES}")
    seen_ids: set[str] = set()
    dictionaries: list[dict[str, Any]] = []
    for index, item in enumerate(dictionaries_in):
        if not isinstance(item, dict):
            raise ConfigError(f"dlp.custom_dictionaries[{index}] must be an object")
        name = str(item.get("name") or "").strip()[:80]
        if not name:
            raise ConfigError(f"dlp.custom_dictionaries[{index}].name is required")
        dictionary_id = str(item.get("id") or re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-") or f"d{index}")[:48]
        if not _ID_RE.match(dictionary_id) or dictionary_id in seen_ids:
            raise ConfigError(f"dlp.custom_dictionaries[{index}].id must be unique (a-z, 0-9, - and _)")
        seen_ids.add(dictionary_id)
        terms_in = item.get("terms")
        if isinstance(terms_in, str):
            terms_in = [line for line in re.split(r"[\n,]", terms_in)]
        if not isinstance(terms_in, list):
            raise ConfigError(f"dlp.custom_dictionaries[{index}].terms must be a list")
        terms = sorted({str(t).strip() for t in terms_in if str(t).strip()}, key=str.lower)
        if not terms or len(terms) > MAX_TERMS_PER_DICTIONARY or any(len(t) > MAX_TERM_CHARS or len(t) < 2 for t in terms):
            raise ConfigError(
                f"dlp.custom_dictionaries[{index}].terms: 1 to {MAX_TERMS_PER_DICTIONARY} terms of 2 to {MAX_TERM_CHARS} characters"
            )
        category = str(item.get("category") or "custom").strip()
        if category != "custom" and category not in DOCUMENT_CATEGORIES:
            raise ConfigError(f"dlp.custom_dictionaries[{index}].category must be custom or one of {', '.join(DOCUMENT_CATEGORIES)}")
        min_matches = item.get("min_matches", 1)
        if not isinstance(min_matches, int) or not 1 <= min_matches <= 50:
            raise ConfigError(f"dlp.custom_dictionaries[{index}].min_matches must be 1 to 50")
        dictionaries.append(
            {
                "id": dictionary_id,
                "name": name,
                "category": category,
                "terms": terms,
                "confidence": _float(item.get("confidence", 0.9), f"dlp.custom_dictionaries[{index}].confidence"),
                "min_matches": min_matches,
                "enabled": bool(item.get("enabled", True)),
            }
        )
    config["dlp"]["custom_dictionaries"] = dictionaries

    pi_in = raw.get("prompt_injection") or {}
    if not isinstance(pi_in, dict):
        raise ConfigError("prompt_injection must be an object")
    if "enabled" in pi_in:
        if not isinstance(pi_in["enabled"], bool):
            raise ConfigError("prompt_injection.enabled must be true or false")
        config["prompt_injection"]["enabled"] = pi_in["enabled"]
    thresholds_in = pi_in.get("thresholds") or {}
    if not isinstance(thresholds_in, dict):
        raise ConfigError("prompt_injection.thresholds must be an object")
    for key, value in thresholds_in.items():
        if key not in INJECTION_ACTIONS:
            raise ConfigError(f"unknown threshold {key!r}: use {', '.join(INJECTION_ACTIONS)}")
        config["prompt_injection"]["thresholds"][key] = _float(value, f"prompt_injection.thresholds.{key}", allow_none=True)
    thresholds = config["prompt_injection"]["thresholds"]
    ordered = [thresholds[a] for a in INJECTION_ACTIONS if thresholds[a] is not None]
    if any(a < b for a, b in zip(ordered, ordered[1:])):
        raise ConfigError("prompt_injection.thresholds must not increase from block to hold to redact to log")
    return config


def profile_from_config(
    config: dict[str, Any] | None,
    *,
    tenant_id: str | None = None,
    revision: int = 0,
    fingerprint_salt: str = "",
    fingerprints: list[dict[str, Any]] | None = None,
) -> DetectionProfile:
    try:
        config = sanitize_config(config or {})
    except ConfigError:
        config = default_config()
    dlp = config["dlp"]
    disabled = frozenset(key for key, on in dlp["categories"].items() if not on)
    sensitive = set(DEFAULT_SENSITIVE_TYPES)
    if dlp.get("ip_address_sensitive"):
        sensitive.add("ip_address")
    dictionaries = tuple(
        CustomDictionary(
            id=item["id"], name=item["name"], terms=tuple(item["terms"]), category=item["category"],
            confidence=float(item["confidence"]), min_matches=int(item["min_matches"]), enabled=bool(item["enabled"]),
        )
        for item in dlp["custom_dictionaries"]
    )
    sets = tuple(
        FingerprintSet(
            id=str(item.get("id")), name=str(item.get("name") or ""), category=str(item.get("category") or "custom"),
            digests=frozenset(str(d) for d in (item.get("digests") or [])),
        )
        for item in (fingerprints or [])
        if isinstance(item, dict) and item.get("enabled", True)
    )
    return DetectionProfile(
        tenant_id=tenant_id,
        revision=revision,
        disabled=disabled,
        sensitive_types=frozenset(sensitive),
        document_min_score=float(dlp["document_min_score"]),
        sensitive_categories=frozenset(dlp["sensitive_categories"]),
        ner_enabled=bool(dlp["ner_enabled"]),
        custom_dictionaries=dictionaries,
        fingerprint_salt=fingerprint_salt,
        fingerprint_sets=sets,
        injection_enabled=bool(config["prompt_injection"]["enabled"]),
        injection_thresholds=dict(config["prompt_injection"]["thresholds"]),
    )


# ---------------------------------------------------------------------------------------------------------------------
# Loading (cached briefly per process; saving clears the tenant's entry) and the active profile
# ---------------------------------------------------------------------------------------------------------------------

_CACHE_TTL_SECONDS = 15.0
_cache: dict[str, tuple[float, DetectionProfile]] = {}
_cache_lock = threading.Lock()


def invalidate(tenant_id: str | None = None) -> None:
    with _cache_lock:
        if tenant_id is None:
            _cache.clear()
        else:
            _cache.pop(str(tenant_id), None)


def load_profile(db: Any, tenant_id: str | None) -> DetectionProfile:
    if not tenant_id or db is None:
        return DEFAULT_PROFILE
    key = str(tenant_id)
    now = time.monotonic()
    with _cache_lock:
        cached = _cache.get(key)
        if cached and now - cached[0] < _CACHE_TTL_SECONDS:
            return cached[1]
    try:
        from app.db.models.detection import DetectionSettings

        no_autoflush = getattr(db, "no_autoflush", None)
        if no_autoflush is not None:
            with no_autoflush:  # reading settings must not flush the caller's pending work early
                row = db.get(DetectionSettings, key)
        else:
            row = db.get(DetectionSettings, key)
    except Exception:  # noqa: BLE001 - detection settings must never break a decision path
        return DEFAULT_PROFILE
    if not isinstance(row, DetectionSettings):
        profile = DetectionProfile(tenant_id=key)
    else:
        profile = profile_from_config(
            row.config,
            tenant_id=key,
            revision=int(row.revision or 0),
            fingerprint_salt=str(row.fingerprint_salt or ""),
            fingerprints=list(row.fingerprints or []),
        )
    with _cache_lock:
        _cache[key] = (now, profile)
    return profile


_ACTIVE: contextvars.ContextVar[DetectionProfile | None] = contextvars.ContextVar("hawk_detection_profile", default=None)


def current_profile() -> DetectionProfile:
    return _ACTIVE.get() or DEFAULT_PROFILE


@contextmanager
def active_profile(profile: DetectionProfile | None) -> Iterator[DetectionProfile]:
    token = _ACTIVE.set(profile or DEFAULT_PROFILE)
    try:
        yield profile or DEFAULT_PROFILE
    finally:
        _ACTIVE.reset(token)


F = TypeVar("F", bound=Callable[..., Any])


def with_tenant_profile(func: F) -> F:
    """Decorate a decision path taking ``db`` (first argument or keyword) and ``tenant_id`` (keyword): the tenant's
    detection profile is active while it runs, so the DLP and injection detectors it calls use the tenant's settings."""

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        db = kwargs.get("db", args[0] if args else None)
        tenant_id = kwargs.get("tenant_id")
        with active_profile(load_profile(db, tenant_id)):
            return func(*args, **kwargs)

    return wrapper  # type: ignore[return-value]


def utcnow() -> datetime:
    return datetime.now(timezone.utc)
