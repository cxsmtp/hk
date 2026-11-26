"""Exact data match (EDM): a tenant uploads values it knows are sensitive (customer IDs, account numbers, names) and
only salted keyed hashes are kept. Prompts are then checked by hashing their candidate tokens with the same salt.

The values are never stored, logged or returned: ``hash_values`` turns them into HMAC-SHA256 digests (truncated to
128 bits) under the tenant's own random salt, and matching compares digests only.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import re
import secrets
import unicodedata
from dataclasses import dataclass
from typing import Iterable

MIN_VALUE_CHARS = 4
MAX_VALUES_PER_SET = 100_000
MAX_VALUES_PER_TENANT = 250_000
MAX_SETS_PER_TENANT = 20
_DIGEST_HEX = 32  # 128 bits

_TOKEN_RE = re.compile(r"[^\s,;:\"'()<>\[\]{}|]+")
_DIGIT_RUN_RE = re.compile(r"(?<![\w])\d(?:[\d \-./]{2,40}\d)?(?![\w])")
_WORD_RE = re.compile(r"[^\W_][\w.'\-]*", re.UNICODE)
_STRIP = ".,!?;:'\"`()[]{}<>"


@dataclass(frozen=True)
class FingerprintSet:
    id: str
    name: str
    category: str
    digests: frozenset[str]

    @property
    def size(self) -> int:
        return len(self.digests)


def new_salt() -> str:
    return secrets.token_hex(32)


def normalize_value(value: str) -> str:
    text = unicodedata.normalize("NFKC", str(value or "")).strip().casefold()
    text = "".join(str(unicodedata.decimal(ch)) if unicodedata.category(ch) == "Nd" else ch for ch in text)
    compact = re.sub(r"[\s\-./]", "", text)
    if compact and sum(ch.isdigit() for ch in compact) >= len(compact) * 0.6:
        return compact  # identifiers: "CUST-001 234" == "cust001234"
    return re.sub(r"\s+", " ", text.strip(_STRIP))


def digest(salt: str, normalized: str) -> str:
    return hmac.new(bytes.fromhex(salt), normalized.encode("utf-8"), hashlib.sha256).hexdigest()[:_DIGEST_HEX]


def hash_values(salt: str, values: Iterable[str]) -> tuple[list[str], int]:
    """Digest each usable value; returns (sorted unique digests, values skipped as too short)."""
    out: set[str] = set()
    skipped = 0
    for value in values:
        normalized = normalize_value(value)
        if len(normalized) < MIN_VALUE_CHARS:
            skipped += 1
            continue
        out.add(digest(salt, normalized))
        if len(out) > MAX_VALUES_PER_SET:
            raise ValueError(f"too many values: at most {MAX_VALUES_PER_SET} per set")
    return sorted(out), skipped


def values_from_csv(text: str, *, column: str | int | None = None, has_header: bool | None = None) -> list[str]:
    """Read one column (by header name or 0-based index; the first by default) of CSV text."""
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|") if sample.strip() else csv.excel
    except csv.Error:
        dialect = csv.excel
    rows = list(csv.reader(io.StringIO(text), dialect))
    if not rows:
        return []
    if has_header is None:
        has_header = isinstance(column, str)
        if not has_header:
            try:
                has_header = csv.Sniffer().has_header(sample)
            except csv.Error:
                has_header = False
    index = 0
    if isinstance(column, int):
        index = column
    elif isinstance(column, str) and rows:
        header = [cell.strip().lower() for cell in rows[0]]
        if column.strip().lower() not in header:
            raise ValueError(f"column {column!r} is not in the header")
        index = header.index(column.strip().lower())
    body = rows[1:] if has_header else rows
    return [row[index] for row in body if len(row) > index and str(row[index]).strip()]


def candidates(text: str, *, max_ngram: int = 3, limit: int = 20_000) -> set[str]:
    """Normalised candidate values in a text: tokens, digit runs with separators, and word n-grams (names)."""
    out: set[str] = set()
    for match in _TOKEN_RE.finditer(text):
        token = normalize_value(match.group(0))
        if len(token) >= MIN_VALUE_CHARS:
            out.add(token)
    for match in _DIGIT_RUN_RE.finditer(text):
        token = normalize_value(match.group(0))
        if len(token) >= MIN_VALUE_CHARS:
            out.add(token)
    words = [w.strip(_STRIP) for w in _WORD_RE.findall(text)]
    words = [w for w in words if w]
    for size in range(2, max_ngram + 1):
        for i in range(0, max(0, len(words) - size + 1)):
            out.add(normalize_value(" ".join(words[i : i + size])))
            if len(out) >= limit:
                return out
    return out


def match(text: str, *, salt: str, sets: Iterable[FingerprintSet], candidate_set: set[str] | None = None) -> list[dict[str, object]]:
    sets = [s for s in sets if s.digests]
    if not sets or not salt or not text:
        return []
    pool = candidate_set if candidate_set is not None else candidates(text)
    digests = {digest(salt, value) for value in pool}
    hits: list[dict[str, object]] = []
    for fingerprint_set in sets:
        count = len(digests & fingerprint_set.digests)
        if count:
            hits.append({"set_id": fingerprint_set.id, "name": fingerprint_set.name, "category": fingerprint_set.category, "matches": count})
    return hits
