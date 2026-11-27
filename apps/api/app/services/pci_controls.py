"""Card numbers (PAN) never stored, logged or exported in full: PCI DSS v4.0.1 requirements 3.3, 3.4, 3.5 and 10.

Hawk sees prompts, responses, files and browser / endpoint telemetry, and any of them can carry a payment card number.
The detectors (app/services/detection, app/services/sensitive_data_detection_service.py) see the full number, because
they have to; nothing that leaves the request does:

* **One masking format.** A card number is written as ``[card ending 1111]``: the last four digits only, never the BIN,
  never the rest (PCI DSS 3.4.1 allows at most the first six and last four; Hawk keeps less). A base64 segment that
  decodes to text holding a card number is replaced as a whole by ``[omitted:encoded card number]``.
* **What counts as a card number** (``find_pans``). All of:

  - 13 to 16 digits written together (17 to 19 only when labelled as a card: longer runs are record ids), or grouped
    in a card layout with one kind of separator (space, dash, no-break or thin space): 4-4-4-4, 4-4-4-4-3, 4-6-5,
    4-6-4, 4-4-4-1 to 4-4-4-3, or every digit on its own (``CARD_LAYOUTS``);
  - a card network's prefix (IIN) and a length valid for that network (``CARD_NETWORKS``: Visa, Mastercard, Amex,
    Discover, Diners, JCB, UnionPay, RuPay, Maestro);
  - the Luhn check.

  Not a card number: digits that are part of an IBAN (``AE07 0331 2345 6789 0123 456``), a date or time
  (``2024-11-15``, ``15/11/2024``, ISO timestamps, ``20241115093045``), a record id (UUID) or hex digest
  (``IDENTIFIER_RE``, the same rule as app/services/privacy_sanitizer.py, so an id always matches its record and a
  digest still verifies), an international phone number written with ``+`` (at most 15 digits), the digits after a
  decimal point, or a number labelled as something else just before it (``Order #``, ``Invoice No.``, ``ref:``,
  ``Tel:``, ``"order_id": ``). Labelled as a card (``card``, ``PAN``, ``CC``, ``Visa``, ``"card_number": ``), it is one
  in any grouping. tests/test_pci_masking_precision.py measures this on generated corpora (recall 100% for card
  numbers in every layout, under 0.5% false positives for IBANs, dates, timestamps, ids, phone numbers and labelled
  order numbers).

  Detection (app/services/detection/structured.py, the DLP that decides what may reach an AI provider) keeps a wider
  net on purpose: there a missed card number is a disclosure and a false alarm a finding someone reviews, while
  masking here changes stored data for good. Its networks cover these (``card_brand``), so every number masked here
  is also reported there; the test above checks it.
* **Where it is enforced.** ``scrub_pan`` runs at every boundary where text leaves the request:

  - the database: every string and JSON column (and a JSON number that is a card number) of every row the ORM
    writes, and the parameters and inline values of ORM-session inserts / updates (``install_persistence_guard``: a
    ``before_flush`` hook,
    so the audit chain's MAC - computed in ``before_insert`` - covers what is stored, and ``do_orm_execute``);
  - the gateway's encrypted copy of a prompt (``encrypt_enforcement_prompt``): masked before it is encrypted;
  - the logs: every line, message and field (app/core/log_config.py ``redact_text`` / ``redact_value``), and so the
    error journal on disk, the troubleshooting report and the diagnostics bundle that read them;
  - exports: built from the masked rows; the SIEM export masks whatever it is given; system emails (app/services/
    mailer.py) mask their subject, lines, facts and footer;
  - Celery: the OCR task (the only task whose arguments or result carry content) travels encrypted both ways and its
    result is forgotten as soon as it is read;
  - simulations: a definition names ``{{hawk.test_card}}``; the test number is filled in only when a step runs.

  Not stored anywhere: the gateway's reversible-masking map (app/services/llm_gateway_secure/data_minimizer.py) lives
  in memory for at most 300 seconds and is destroyed after the call. Redis holds sign-in tickets, rate-limit counters
  and error counts, never content.

* **Evidence hashes.** Hashes Hawk keeps of what it saw (``prompt_hash``, ``response_hash``, receipt bindings) are
  computed by the services from the original text before it is stored, so they still prove what was seen; the row
  itself only ever holds the masked text. The audit chain, receipts and canonical evidence bundles verify over the
  masked rows (tests/test_pci_pan_leak_scan.py). Those content hashes are unkeyed SHA-256 of the whole text: where
  the text held a card number, database access must stay restricted so a hash and the masked text cannot be
  correlated (PCI DSS 3.5.1.1 / 7.2, the customer's).

``pan_protection_status()`` says what is enforced, for Settings and the compliance packs.
"""

from __future__ import annotations

import base64
import bisect
import binascii
import re
import threading
from collections import Counter
from typing import Any

PAN_MASK_FORMAT = "[card ending NNNN]"
ENCODED_PAN_PLACEHOLDER = "[omitted:encoded card number]"
#: The card number Hawk AI's own simulations send (the networks' published Visa test number). Filled into a step only
#: when it runs (``{{hawk.test_card}}``, app/services/simulation_catalog_runners.py): never stored with a definition.
TEST_CARD_NUMBER = "4111 1111 1111 1111"
PAN_MIN_DIGITS = 13
PAN_MAX_DIGITS = 19
#: A contiguous run this long (17 to 19 digits) is far more often a record id (a 64-bit id, a snowflake) than a card
#: number: it counts as one only when it is labelled as a card (``card: …``, ``"pan": …``). Grouped, it always counts.
UNLABELLED_CONTIGUOUS_MAX = 16

#: The card networks: (name, issuer prefixes as inclusive ranges over the first digits, valid lengths). A number is a
#: card number only when its prefix (IIN) is in one of these ranges and its length is valid for that network.
CARD_NETWORKS: tuple[tuple[str, tuple[tuple[int, int], ...], frozenset[int]], ...] = (
    ("visa", ((4, 4),), frozenset({13, 16, 19})),
    ("mastercard", ((51, 55), (2221, 2720)), frozenset({16})),
    ("amex", ((34, 34), (37, 37)), frozenset({15})),
    ("discover", ((6011, 6011), (644, 649), (65, 65), (622126, 622925)), frozenset(range(16, 20))),
    ("diners", ((300, 305), (36, 36), (38, 39)), frozenset({14, 16})),
    ("jcb", ((3528, 3589),), frozenset(range(16, 20))),
    ("unionpay", ((62, 62),), frozenset(range(16, 20))),
    ("rupay", ((60, 60), (65, 65), (81, 82), (508, 508), (353, 353), (356, 356)), frozenset({16})),
    ("maestro", ((50, 50), (56, 69)), frozenset(range(12, 20))),
)
#: How card numbers are printed and typed, as the lengths of their groups: 4-4-4-4 (16), 4-4-4-4-3 (19), Amex 4-6-5,
#: Diners 4-6-4, and 4-4-4-1 to 4-4-4-3 (13 to 15). Written together (13 to 19 digits) or every digit on its own is a
#: card layout too. Anything else (4-2-2, 2-2-4, 8-8, …: dates, IBAN groups, ids) is not.
CARD_LAYOUTS = frozenset({(4, 4, 4, 4), (4, 4, 4, 4, 3), (4, 6, 5), (4, 6, 4), (4, 4, 4, 1), (4, 4, 4, 2), (4, 4, 4, 3)})
_LAYOUT_SIZES = sorted({len(layout) for layout in CARD_LAYOUTS}, reverse=True)
#: The separators between groups: one kind in a card number (space, dash, no-break, thin or narrow no-break space).
PAN_SEPARATORS = " -   "

# A run of ASCII digits, optionally grouped by one separator between groups (space, dash, no-break or thin space).
# Standing on its own: digits inside a word or an identifier (``ep_36d477d8344175220107336d75fb``) belong to that token,
# not a card number; masking them would make the identifier stop matching its record.
_DIGIT_RUN_RE = re.compile(r"(?<![0-9A-Za-z_])[0-9]+(?:[ \-   ][0-9]+)*(?![0-9A-Za-z_])")
_GROUP_RE = re.compile(r"[0-9]+")
# Record ids (UUIDs) and hex digests (32 hex characters or more): never a card number (privacy_sanitizer.IDENTIFIER_RE).
IDENTIFIER_RE = re.compile(
    r"(?<![0-9A-Fa-f])(?:[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|[0-9a-fA-F]{32,})(?![0-9A-Fa-f])"
)
# An IBAN: a country code and two check digits, then its account number in one token run (``AE07 0331 2345 6789 0123
# 456``, ``GB82WEST12345698765432``). Its digit groups are never a card number.
_IBAN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2})[0-9]{2}(?:[ \- ]?[A-Za-z0-9]){8,32}(?![A-Za-z0-9])")
# Dates and times: 2024-11-15, 15/11/2024, 15.11.2024, with a time and a zone after them (ISO 8601).
_DATE_RE = re.compile(
    r"(?<![0-9])(?:(?:19|20)[0-9]{2}[-/.](?:0?[1-9]|1[0-2])[-/.](?:0?[1-9]|[12][0-9]|3[01])"
    r"|(?:0?[1-9]|[12][0-9]|3[01])[-/.](?:0?[1-9]|1[0-2])[-/.](?:19|20)[0-9]{2})"
    r"(?:[T ](?:[01][0-9]|2[0-3]):[0-5][0-9](?::[0-5][0-9](?:[.,][0-9]{1,9})?)?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?(?![0-9])"
)
# A label just before a number that says it is a card number: it is masked even where the rules below would say it
# is not (a 19-digit number written together, an unusual grouping, a date-like run).
_CARD_LABEL_RE = re.compile(
    r"(?<![a-z])(?:card|pan|ccn?|visa|mastercard|amex|rupay|maestro|discover|unionpay|jcb|diners|credit|debit)"
    r"(?:[ _\-]?(?:no|nr|num|number|id|holder))?(?![a-z])"
)
# A label that says a number is something else (a phone, an order, an invoice, a reference, an account, an IBAN, an
# id), written as a label: followed by "#", ":", "=", "no", "number" or "id", or as a key (``"order_id": …``). A bare
# word ("Invoice 4111 …") is not enough: a card number after it is still masked.
_NOT_CARD_LABEL_RE = re.compile(
    r"(?<![a-z0-9])(?:phone|telephone|tel|mobile|mob|cell|fax|whatsapp|order|invoice|inv|ref|reference|account|acct|"
    r"iban|id|txn|transaction|tracking|booking|ticket|awb|msisdn)"
    r"(?P<suffix>[ _.\-]?(?:no|nr|num|number|id|ref|code)\.?)?"
    r"(?P<marker>[ \t]*[\"']?[ \t]*(?:[#:=]|-)[ \t]*[\"']?)?"
    r"[ \t]*$"
)
_LABEL_WINDOW = 32
# A base64 (or base64url) segment long enough to hold a card number once decoded.
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/_-])[A-Za-z0-9+/_-]{20,}={0,2}(?![A-Za-z0-9+/_=-])")
_MAX_DECODE_CHARS = 2_000_000


def luhn_valid(digits: str) -> bool:
    if not digits or not digits.isdigit():
        return False
    total = 0
    for index, char in enumerate(reversed(digits)):
        digit = ord(char) - 48
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def card_network(digits: str) -> str | None:
    """The network whose prefix (IIN) and length ``digits`` has, or None."""

    if not digits.isdigit():
        return None
    for name, ranges, lengths in CARD_NETWORKS:
        if len(digits) not in lengths:
            continue
        for low, high in ranges:
            width = len(str(low))
            if len(digits) >= width and low <= int(digits[:width]) <= high:
                return name
    return None


def _looks_like_datetime(digits: str) -> bool:
    """YYYYmmddHHMMSS (and with milliseconds) with a real month, day, hour, minute and second."""

    if len(digits) not in (14, 17):
        return False
    year, month, day = int(digits[:4]), int(digits[4:6]), int(digits[6:8])
    hour, minute, second = int(digits[8:10]), int(digits[10:12]), int(digits[12:14])
    return 1900 <= year <= 2099 and 1 <= month <= 12 and 1 <= day <= 31 and hour <= 23 and minute <= 59 and second <= 60


def _card_digits(digits: str) -> bool:
    """13-19 digits, not one digit repeated, a card network's prefix and a length valid for it, Luhn-valid."""

    return PAN_MIN_DIGITS <= len(digits) <= PAN_MAX_DIGITS and len(set(digits)) > 1 and card_network(digits) is not None and luhn_valid(digits)


def is_pan(digits: str, *, labelled: bool = False) -> bool:
    """``digits`` (digits only, written together: a JSON number, a field) is a card number: ``_card_digits``, and,
    unless ``labelled`` as a card, at most 16 digits and not a date and time (YYYYmmddHHMMSS)."""

    if not _card_digits(digits):
        return False
    return labelled or (len(digits) <= UNLABELLED_CONTIGUOUS_MAX and not _looks_like_datetime(digits))


def _plausible_grouping(groups: list[str]) -> bool:
    """Any grouping a person might type, for a number labelled as a card: one group, every digit on its own, or
    groups of 2 to 6 digits (the last may be 1 to 6)."""

    if len(groups) == 1:
        return True
    if all(len(group) == 1 for group in groups):
        return True
    return all(2 <= len(group) <= 6 for group in groups[:-1]) and 1 <= len(groups[-1]) <= 6


def _identifier_spans(text: str) -> list[tuple[int, int]]:
    return [match.span() for match in IDENTIFIER_RE.finditer(text)]


def _iban_spans(text: str) -> list[tuple[int, int]]:
    """Each IBAN, as long as its country's IBANs are (a number written after it is not taken in)."""

    from app.services.detection.structured import IBAN_LENGTHS

    spans: list[tuple[int, int]] = []
    for match in _IBAN_RE.finditer(text):
        expected = IBAN_LENGTHS.get(match.group(1).upper())
        if not expected:
            continue
        count, end = 0, match.end()
        for pos in range(match.start(), match.end()):
            if text[pos].isalnum():
                count += 1
                if count == expected:
                    end = pos + 1
                    break
        spans.append((match.start(), end))
    return spans


def _date_spans(text: str) -> list[tuple[int, int]]:
    return [match.span() for match in _DATE_RE.finditer(text)]


def _inside(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    # ``spans`` come from one finditer: sorted and never overlapping, so only the last one starting at or before
    # ``start`` can hold [start, end) (a scan of every span made many numbers among many ids quadratic).
    index = bisect.bisect_right(spans, (start, float("inf"))) - 1
    return index >= 0 and spans[index][0] <= start and end <= spans[index][1]


def _overlaps(spans: list[tuple[int, int]], start: int, end: int) -> bool:
    # The last span starting before ``end`` is the only one that can reach into [start, end) (sorted, not overlapping).
    index = bisect.bisect_left(spans, (end, -1)) - 1
    return index >= 0 and spans[index][1] > start


def card_label(before: str) -> bool:
    """The text just before a number labels it as a card number (``card``, ``PAN:``, ``"card_number": ``)."""

    return bool(_CARD_LABEL_RE.search(before[-_LABEL_WINDOW:].lower()))


def other_label(before: str, *, key: bool = False) -> bool:
    """The text just before a number labels it as something else (``Order #``, ``Invoice No.``, ``ref=``, ``"id": ``).
    ``key``: ``before`` is a whole JSON key, which is a label by itself."""

    text = before[-_LABEL_WINDOW:].lower()
    if key:
        text += ":"
    match = _NOT_CARD_LABEL_RE.search(text)
    return bool(match and (match.group("suffix") or match.group("marker")))


def _not_a_card_run(text: str, start: int, digits: int) -> bool:
    """The digit run at ``start`` (``digits`` digits) is an international phone number (``+86 139 1067 6024``: a ``+``
    at the start of a value or a word, at most 15 digits, E.164) or the fraction of a decimal (``0.5044215558096435``,
    how Python writes a float). About one in ten of those passed as a card number and was masked, changing the number.
    A ``+`` after a letter, a digit or ``=`` / ``&`` may be a URL-encoded space (``note=hello+4111111111111111``), and a
    16 to 19 digit number after ``+`` is no phone number: both are still masked."""

    if start == 0:
        return False
    before = text[start - 1]
    if before == "+":
        return digits <= 15 and (start == 1 or text[start - 2] in " \t\r\n([{\"':,;")
    return before == "." and start >= 2 and "0" <= text[start - 2] <= "9"


def _candidates(groups: list[tuple[int, int, str]], seps: list[str], index: int) -> list[tuple[int, bool]]:
    """The card layouts that start at group ``index``: (the last group's index, written together), longest first. At
    most a handful for each group, so a run is looked at in time linear in its length."""

    out: list[tuple[int, int, bool]] = []
    first = groups[index][2]
    if PAN_MIN_DIGITS <= len(first) <= PAN_MAX_DIGITS:
        out.append((len(first), index, True))
    for size in _LAYOUT_SIZES:
        last = index + size - 1
        if last >= len(groups):
            continue
        if tuple(len(g[2]) for g in groups[index : last + 1]) in CARD_LAYOUTS and len(set(seps[index:last])) == 1:
            out.append((sum(len(g[2]) for g in groups[index : last + 1]), last, False))
    if len(first) == 1:
        # Every digit on its own (``4 1 1 1 …``), with one kind of separator.
        last = index
        while last + 1 < len(groups) and last - index + 1 < PAN_MAX_DIGITS and len(groups[last + 1][2]) == 1 and seps[last] == seps[index]:
            last += 1
        for end in range(last, index + PAN_MIN_DIGITS - 2, -1):
            out.append((end - index + 1, end, False))
    out.sort(key=lambda row: -row[0])
    return [(last, together) for _, last, together in out]


def find_pans(text: str) -> list[tuple[int, int, str]]:
    """Every card number in ``text``: (start, end, digits), in order, never overlapping.

    A card number is 13 to 19 digits written together (at most 16 unless labelled as a card) or grouped in a card
    layout (``CARD_LAYOUTS``) with one kind of separator, with a card network's prefix and a length valid for it, that
    passes the Luhn check. It is not a card number when it is part of an IBAN, a date or time, a record id or digest, an
    international phone number or a decimal, or labelled as something else (``Order #``, ``Invoice No.``, ``ref:``);
    labelled as a card (``card``, ``PAN``, ``CC``, ``Visa``, …), it is, in any grouping."""

    if not text or not any("0" <= ch <= "9" for ch in text):
        return []
    identifiers = _identifier_spans(text)
    ibans: list[tuple[int, int]] | None = None
    dates: list[tuple[int, int]] | None = None
    found: list[tuple[int, int, str]] = []
    for run in _DIGIT_RUN_RE.finditer(text):
        offset = run.start()
        groups = [(m.start() + offset, m.end() + offset, m.group(0)) for m in _GROUP_RE.finditer(run.group(0))]
        total_digits = sum(len(g[2]) for g in groups)
        if total_digits < PAN_MIN_DIGITS or _not_a_card_run(text, run.start(), total_digits):
            continue
        seps = [text[groups[i][1] : groups[i + 1][0]] for i in range(len(groups) - 1)]
        index = 0
        while index < len(groups):
            start = groups[index][0]
            labelled = card_label(text[max(0, start - _LABEL_WINDOW) : start])
            choices = _candidates(groups, seps, index)
            if labelled:
                # Labelled as a card: any grouping a person might type, as before (at most PAN_MAX_DIGITS groups).
                for last in range(min(len(groups) - 1, index + PAN_MAX_DIGITS - 1), index - 1, -1):
                    if (last, False) not in choices and _plausible_grouping([g[2] for g in groups[index : last + 1]]):
                        choices.append((last, False))
            matched = False
            for last, together in choices:
                digits = "".join(g[2] for g in groups[index : last + 1])
                end = groups[last][1]
                if not _card_digits(digits):
                    continue
                if not labelled:
                    if (together and len(digits) > UNLABELLED_CONTIGUOUS_MAX) or _looks_like_datetime(digits):
                        continue
                    if other_label(text[max(0, start - _LABEL_WINDOW) : start]):
                        continue
                    if ibans is None:
                        ibans = _iban_spans(text)
                    if _overlaps(ibans, start, end):
                        continue
                    if dates is None:
                        dates = _date_spans(text)
                    if _overlaps(dates, start, end):
                        continue
                if _inside(identifiers, start, end):
                    continue
                found.append((start, end, digits))
                index = last + 1
                matched = True
                break
            if not matched:
                index += 1
    return found


def mask_pan(digits: str) -> str:
    """The one masked form of a card number: ``[card ending 1111]`` (the last four digits, nothing else)."""

    return f"[card ending {digits[-4:]}]"


def _decoded_text(segment: str) -> str | None:
    raw = segment.rstrip("=")
    if len(raw) > _MAX_DECODE_CHARS:
        return None
    padded = raw + "=" * (-len(raw) % 4)
    try:
        if "-" in raw or "_" in raw:
            data = base64.urlsafe_b64decode(padded)
        else:
            data = base64.b64decode(padded, validate=True)
    except (binascii.Error, ValueError):
        return None
    if not data:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1")
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\r\n\t")
    return text if printable >= 0.85 * len(text) else None


def _encoded_pan_spans(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    if len(text) < 20:
        return spans
    identifiers = None
    for match in _BASE64_RE.finditer(text):
        segment = match.group(0)
        # Pure-digit or pure-hex segments are numbers and digests, handled as text.
        if segment.isdigit():
            continue
        decoded = _decoded_text(segment)
        if decoded is None or not find_pans(decoded):
            continue
        if identifiers is None:
            identifiers = _identifier_spans(text)
        if _inside(identifiers, *match.span()):
            continue
        spans.append(match.span())
    return spans


# ---------------------------------------------------------------------------------------------------------------------
# Counters: how often a card number was masked, and where (no number, no digits: the kind of boundary only)
# ---------------------------------------------------------------------------------------------------------------------

_counts: Counter[str] = Counter()
_counts_lock = threading.Lock()


def _count(boundary: str, n: int = 1) -> None:
    if n <= 0:
        return
    with _counts_lock:
        _counts[boundary] += n


def masked_counts() -> dict[str, int]:
    with _counts_lock:
        return dict(_counts)


def reset_masked_counts() -> None:
    with _counts_lock:
        _counts.clear()


def contains_pan(value: Any) -> bool:
    """``value`` (a string, or a dict / list holding strings) holds a card number, plain or base64-encoded."""

    if isinstance(value, str):
        return bool(find_pans(value)) or bool(_encoded_pan_spans(value))
    if isinstance(value, dict):
        return any(contains_pan(k) or contains_pan(v) for k, v in value.items())
    if isinstance(value, (list, tuple, set, frozenset)):
        return any(contains_pan(item) for item in value)
    return False


def scrub_pan(text: Any, *, boundary: str | None = None) -> Any:
    """``text`` with every card number masked (``[card ending 1111]``) and every base64 segment holding one omitted.
    Anything that is not a string is returned as it is. Ids and digests are never changed."""

    if not isinstance(text, str) or len(text) < PAN_MIN_DIGITS:
        return text
    changed = 0
    encoded = _encoded_pan_spans(text)
    if encoded:
        parts: list[str] = []
        cursor = 0
        for start, end in encoded:
            parts.extend((text[cursor:start], ENCODED_PAN_PLACEHOLDER))
            cursor = end
        parts.append(text[cursor:])
        text = "".join(parts)
        changed += len(encoded)
    pans = find_pans(text)
    if pans:
        parts = []
        cursor = 0
        for start, end, digits in pans:
            parts.extend((text[cursor:start], mask_pan(digits)))
            cursor = end
        parts.append(text[cursor:])
        text = "".join(parts)
        changed += len(pans)
    if changed and boundary:
        _count(boundary, changed)
    return text


def _scrub_number(value: int, *, boundary: str | None, key: str | None = None) -> Any:
    """A card number sent as a JSON number, by the same rules as in text: its key is its label (``"pan": …`` is one at
    any length; ``"order_id": …`` is not one)."""

    if value <= 0:
        return value
    digits = str(value)
    labelled = bool(key) and card_label(key or "")
    if key and not labelled and other_label(key, key=True):
        return value
    if not is_pan(digits, labelled=labelled):
        return value
    if boundary:
        _count(boundary)
    return mask_pan(digits)


def scrub_pan_value(value: Any, *, boundary: str | None = None, _depth: int = 0) -> Any:
    """``value`` (a string, dict, list) with every card number in its strings (and its keys) masked. Returns the same
    object when nothing changed, so a caller can tell by identity."""

    if isinstance(value, str):
        return scrub_pan(value, boundary=boundary)
    if isinstance(value, int) and not isinstance(value, bool):
        return _scrub_number(value, boundary=boundary)
    if _depth > 64:
        return value
    if isinstance(value, dict):
        out: dict[Any, Any] = {}
        changed = False
        for key, item in value.items():
            new_key = scrub_pan(key, boundary=boundary) if isinstance(key, str) else key
            if isinstance(item, int) and not isinstance(item, bool) and isinstance(key, str):
                new_item = _scrub_number(item, boundary=boundary, key=key)
            else:
                new_item = scrub_pan_value(item, boundary=boundary, _depth=_depth + 1)
            changed = changed or new_key is not key or new_item is not item
            out[new_key] = new_item
        return out if changed else value
    if isinstance(value, (list, tuple)):
        items = [scrub_pan_value(item, boundary=boundary, _depth=_depth + 1) for item in value]
        if all(new is old for new, old in zip(items, value)):
            return value
        return type(value)(items) if isinstance(value, tuple) else items
    return value


# ---------------------------------------------------------------------------------------------------------------------
# The database boundary
# ---------------------------------------------------------------------------------------------------------------------

_guard_installed = False


def _scrub_instance(obj: Any) -> None:
    from sqlalchemy import inspect as sa_inspect
    from sqlalchemy.orm import ColumnProperty

    try:
        mapper = sa_inspect(obj).mapper
    except Exception:  # noqa: BLE001 - not a mapped object
        return
    table = getattr(mapper, "local_table", None)
    boundary = f"db:{getattr(table, 'name', mapper.class_.__name__)}"
    for prop in mapper.iterate_properties:
        if not isinstance(prop, ColumnProperty):
            continue
        key = prop.key
        try:
            current = obj.__dict__.get(key)
        except Exception:  # noqa: BLE001
            continue
        if current is None or isinstance(current, (bool, int, float, bytes)):
            continue
        if not isinstance(current, (str, dict, list, tuple)):
            continue
        scrubbed = scrub_pan_value(current, boundary=boundary)
        if scrubbed is not current:
            setattr(obj, key, scrubbed)


def _before_flush(session: Any, flush_context: Any, instances: Any) -> None:
    for obj in list(session.new) + list(session.dirty):
        _scrub_instance(obj)


def _scrub_inline_values(statement: Any) -> Any:
    """``statement`` with card numbers masked in the values written inline (``update(Model).values(reason=text)``, an
    ``insert(Model).values(...)``): those are part of the statement, not of the execute parameters."""

    from sqlalchemy.sql.elements import BindParameter

    values = getattr(statement, "_values", None)
    if not values:
        return statement
    changes: dict[Any, Any] = {}
    for key, bound in values.items():
        if not isinstance(bound, BindParameter) or bound.callable is not None:
            continue
        scrubbed = scrub_pan_value(bound.value, boundary="db:bulk")
        if scrubbed is not bound.value:
            changes[key] = scrubbed
    return statement.values(changes) if changes else statement


def _before_orm_execute(orm_execute_state: Any) -> Any:
    """Bulk ORM inserts and updates (``db.execute(insert(Model), rows)``) and conditional updates
    (``db.execute(update(Model).where(...).values(...))``) never pass through a flush: their parameters and inline
    values are masked here and the statement run with them."""

    if not (orm_execute_state.is_insert or orm_execute_state.is_update):
        return None
    statement = _scrub_inline_values(orm_execute_state.statement)
    params = orm_execute_state.parameters
    scrubbed = scrub_pan_value(params, boundary="db:bulk") if params else params
    if statement is orm_execute_state.statement and scrubbed is params:
        return None
    return orm_execute_state.invoke_statement(statement=statement, params=scrubbed)


def install_persistence_guard() -> None:
    """Mask card numbers in every row the ORM writes. Registered once, after every model's own ``before_flush`` hook
    (app/db/models/__init__.py), so rows those hooks add are masked too; it runs before ``before_insert``, where the
    audit chain computes its MAC."""

    global _guard_installed
    if _guard_installed:
        return
    from sqlalchemy import event
    from sqlalchemy.orm import Session

    event.listen(Session, "before_flush", _before_flush)
    event.listen(Session, "do_orm_execute", _before_orm_execute)
    _guard_installed = True


def persistence_guard_installed() -> bool:
    return _guard_installed


# ---------------------------------------------------------------------------------------------------------------------
# Status, for Settings and the compliance packs
# ---------------------------------------------------------------------------------------------------------------------


def pan_protection_status() -> dict[str, Any]:
    """What Hawk enforces for card numbers, as a plain dict other code can show or check."""

    from app.core import log_config

    logs_masked = log_config.redact_text("4111 1111 1111 1111") != "4111 1111 1111 1111"
    database_guard = persistence_guard_installed()
    return {
        "enforced": bool(database_guard and logs_masked),
        "masking_format": PAN_MASK_FORMAT,
        "masking_rule": "last four digits only (PCI DSS 3.4.1 allows at most first six and last four)",
        "encoded_placeholder": ENCODED_PAN_PLACEHOLDER,
        "detection": {
            "digits": [PAN_MIN_DIGITS, PAN_MAX_DIGITS],
            "luhn": True,
            "networks": [name for name, _, _ in CARD_NETWORKS],
            "layouts": ["together", "every digit apart", *sorted("-".join(map(str, layout)) for layout in CARD_LAYOUTS)],
            "separators": ["space", "dash", "no-break space", "thin space"],
            "not_cards": ["IBAN", "date and time", "phone number", "decimal", "labelled as an order, invoice, reference, account, phone or id"],
            "base64": True,
            "identifiers_preserved": True,
        },
        "boundaries": {
            "database": database_guard,
            "logs": logs_masked,
            "error_journal": logs_masked,
            "exports": database_guard and logs_masked,
            "celery_results": True,
        },
        "evidence_hashes": "computed over the original text before it is masked; stored rows hold the masked text",
        "backups": "encrypted (app/services/backup_archive.py); they hold the masked database",
        "masked_since_start": masked_counts(),
        "simulations": "definitions hold {{hawk.test_card}}; the test number is filled in only when a step runs",
        "pci_dss": {
            # What Hawk AI itself does for the card numbers it sees.
            "supported": {
                "3.3": "a PAN inside track data or a prompt is never kept in full (CVV / PIN are not recognised as such)",
                "3.4.1": "PAN shown and kept as the last four digits only",
                "3.5.1": "PAN unreadable wherever Hawk AI stores it: truncated in rows, logs, exports and backups",
                "10.2 / 10.3": "audit and log lines never hold a full PAN; the audit log stays chained and verifiable",
                "12.5.2": "this status and the guide describe where card data flows through Hawk AI",
            },
            # What stays with the customer.
            "customer": {
                "3.2.1": "retention of the card data in the customer's own systems and AI providers",
                "3.3.1": "keeping card verification codes and PINs out of AI tools by policy and training",
                "3.5.1.1": "prompt hashes are unkeyed SHA-256 of the whole text: restrict database access (7.2) so a "
                "hash and the masked text are not correlated",
                "3.6 / 3.7": "management of the keys protecting backups and encrypted fields",
                "10.5.1": "keeping log history for at least 12 months in the SIEM",
                "12.5.2": "scoping the systems outside Hawk AI that store, process or transmit card data",
            },
        },
    }
