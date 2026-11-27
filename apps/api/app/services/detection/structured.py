"""Validated structured detectors: values with a checksum, a fixed grammar or a known prefix.

Each detector matches on the folded text (see ``normalize``), validates the candidate (Luhn, IBAN mod-97, MRZ 7-3-1
check digits, SSN/NINO allocation rules, entropy for tokens) and scores it, raising the score when a context word is
near ("card", "iban", "passport", "ssn", ...). Only offsets and a redacted preview leave this module: the value itself
is never returned to callers outside the masking path.
"""

from __future__ import annotations

import ipaddress
import math
import re
from collections import Counter
from dataclasses import dataclass, field

from app.services.detection.normalize import Normalized

STRUCTURED_RULESET_VERSION = "2026.11.1"


@dataclass(frozen=True)
class Finding:
    entity_type: str
    start: int  # offsets in the folded text
    end: int
    confidence: float
    detector: str
    subtype: str | None = None
    context_hit: bool = False
    encoded: str | None = None  # set when found inside a decoded base64/hex segment
    reasons: tuple[str, ...] = field(default_factory=tuple)


# ---------------------------------------------------------------------------------------------------------------------
# Validators
# ---------------------------------------------------------------------------------------------------------------------


def digits_of(value: str) -> str:
    return "".join(ch for ch in value if "0" <= ch <= "9")


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


def card_brand(digits: str) -> str | None:
    n = len(digits)
    if digits.startswith("4") and n in (13, 16, 19):
        return "visa"
    two, three, four, six = int(digits[:2]), int(digits[:3]), int(digits[:4]), int(digits[:6])
    if n == 16 and (51 <= two <= 55 or 222100 <= six <= 272099):
        return "mastercard"
    if n == 15 and two in (34, 37):
        return "amex"
    if n in (16, 19) and (four == 6011 or two == 65 or 644 <= three <= 649):
        return "discover"
    if 16 <= n <= 19 and 3528 <= four <= 3589:
        return "jcb"
    if n in (14, 16) and (300 <= three <= 305 or two in (36, 38, 39)):
        return "diners"
    if 16 <= n <= 19 and two == 62:
        return "unionpay"
    if 12 <= n <= 19 and (two == 50 or 56 <= two <= 69):
        return "maestro"
    # RuPay's other ranges (60 and 65 are read above as Maestro and Discover), so that every number at-rest masking
    # treats as a card (app/services/pci_controls.py CARD_NETWORKS) is also one here.
    if n == 16 and (two in (81, 82) or three in (353, 356, 508)):
        return "rupay"
    return None


IBAN_LENGTHS: dict[str, int] = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "BY": 28,
    "CH": 21, "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18,
    "FO": 18, "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22,
    "IL": 23, "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20,
    "LU": 20, "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15,
    "PK": 24, "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19,
    "SK": 24, "SM": 27, "ST": 25, "SV": 28, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
    "OM": 23, "LY": 25, "SD": 18,
}


def iban_valid(value: str) -> bool:
    iban = re.sub(r"[\s\-]", "", value).upper()
    country = iban[:2]
    if IBAN_LENGTHS.get(country) != len(iban) or not iban[2:4].isdigit() or not iban.isalnum():
        return False
    rearranged = iban[4:] + iban[:4]
    numeric = "".join(str(int(ch, 36)) for ch in rearranged)
    return int(numeric) % 97 == 1


def emirates_id_valid(digits: str) -> bool:
    if len(digits) != 15 or not digits.startswith("784"):
        return False
    year = int(digits[3:7])
    return 1900 <= year <= 2099 and luhn_valid(digits)


_SSN_INVALID = {"078051120", "219099999", "123456789", "111111111", "333333333", "666666666", "999999999"}


def ssn_valid(digits: str) -> bool:
    if len(digits) != 9 or digits in _SSN_INVALID:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area in ("000", "666") or area[0] == "9":
        return False
    return group != "00" and serial != "0000"


_NINO_BAD_PREFIX = {"BG", "GB", "KN", "NK", "NT", "TN", "ZZ"}


def nino_valid(value: str) -> bool:
    nino = re.sub(r"\s", "", value).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{6}[A-D]", nino):
        return False
    first, second = nino[0], nino[1]
    if first in "DFIQUV" or second in "DFIOQUV" or nino[:2] in _NINO_BAD_PREFIX:
        return False
    return True


def _mrz_value(ch: str) -> int:
    if ch.isdigit():
        return int(ch)
    if ch == "<":
        return 0
    return ord(ch) - 55


def mrz_check(field_value: str, check: str) -> bool:
    weights = (7, 3, 1)
    total = sum(_mrz_value(ch) * weights[i % 3] for i, ch in enumerate(field_value))
    return check.isdigit() and total % 10 == int(check)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def char_classes(value: str) -> int:
    return sum(
        (
            any(ch.islower() for ch in value),
            any(ch.isupper() for ch in value),
            any(ch.isdigit() for ch in value),
            any(not ch.isalnum() for ch in value),
        )
    )


# ---------------------------------------------------------------------------------------------------------------------
# Context words (searched in a window around the match, lower-case)
# ---------------------------------------------------------------------------------------------------------------------

CONTEXT_WORDS: dict[str, tuple[str, ...]] = {
    "credit_card": ("card", "credit", "debit", "visa", "mastercard", "amex", "cc", "pan", "payment", "cvv", "expiry", "exp"),
    "iban": ("iban", "bank", "account", "transfer", "swift", "bic", "wire", "beneficiary"),
    "emirates_id": ("emirates id", "eid", "uae id", "national id", "identity card", "هوية"),
    "us_ssn": ("ssn", "social security", "social sec", "taxpayer", "tin"),
    "uk_nino": ("national insurance", "nino", "ni number", "ni no", "nin"),
    "passport": ("passport", "travel document", "passport no", "passport number"),
    "phone": ("phone", "mobile", "tel", "call", "cell", "whatsapp", "contact", "fax", "number"),
    "ip_address": ("ip", "host", "server", "address", "addr", "endpoint", "subnet"),
    "api_key": ("key", "token", "secret", "api", "bearer", "auth", "credential", "password", "access"),
    "date_of_birth": ("dob", "date of birth", "birth date", "birthdate", "born on", "born"),
}


def _context_hit(lowered_folded: str, start: int, end: int, entity_type: str, *, window: int = 48) -> bool:
    words = CONTEXT_WORDS.get(entity_type)
    if not words:
        return False
    left = lowered_folded[max(0, start - window) : start]
    right = lowered_folded[end : end + 24]
    around = f"{left} {right}"
    for word in words:
        if len(word) <= 3:
            if re.search(rf"(?<![a-z]){re.escape(word)}(?![a-z])", around):
                return True
        elif word in around:
            return True
    return False


# ---------------------------------------------------------------------------------------------------------------------
# Patterns
# ---------------------------------------------------------------------------------------------------------------------

_CARD_RE = re.compile(r"(?<![\d\-.])(?:\d[ \-.]{0,2}){12,18}\d(?![\d])")
_IBAN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2}\d{2}(?:[ \-]?[A-Za-z0-9]){11,30})(?![A-Za-z0-9])")
_EID_RE = re.compile(r"(?<!\d)7[ \-.]?8[ \-.]?4(?:[ \-.]{0,2}\d){12}(?!\d)")
_SSN_RE = re.compile(r"(?<![\d\-])(\d{3})([ \-.])(\d{2})\2(\d{4})(?![\d\-])")
_SSN_BARE_RE = re.compile(r"(?<![\d\-])\d{9}(?![\d\-])")
_NINO_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z]{2})[ ]?(\d{2})[ ]?(\d{2})[ ]?(\d{2})[ ]?([A-Da-d])(?![A-Za-z0-9])")
_MRZ_LINE1_RE = re.compile(r"P[A-Z<][A-Z<]{3}[A-Z<]{39}")
_MRZ_LINE2_RE = re.compile(r"([A-Z0-9<]{9})(\d)([A-Z<]{3})(\d{6})(\d)([MFX<])(\d{6})(\d)([A-Z0-9<]{14})([\d<])(\d)")
_PASSPORT_CONTEXT_RE = re.compile(
    r"(?i)\bpassport(?:\s*(?:number|no\.?|num|#|id))?\s*(?:is|:|#|=|-)?\s*([A-Z]{1,2}[ ]?\d{6,8}|\d{8,9}|[A-Z]\d{7,8}[A-Z]?)\b"
)
_EMAIL_RE = re.compile(r"(?<![\w.+-])([A-Za-z0-9][A-Za-z0-9._%+-]{0,63})@((?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,24})(?![\w-])")
_EMAIL_OBFUSCATED_RE = re.compile(
    r"(?i)(?<![\w.])([a-z0-9][a-z0-9._+-]{0,63})\s*[\[\(\{<]\s*at\s*[\]\)\}>]\s*([a-z0-9-]{1,63})\s*[\[\(\{<]\s*dot\s*[\]\)\}>]\s*([a-z]{2,24})\b"
)
_PHONE_INTL_RE = re.compile(r"(?<![\w+])\+(\d{1,3})[ \-.]?(?:\(\d{1,4}\)[ \-.]?)?\d{1,4}(?:[ \-.]?\d{2,5}){1,4}(?![\d])")
_PHONE_NATIONAL_RE = re.compile(r"(?<![\w.\-])(?:\(\d{2,4}\)[ \-.]?|0\d{1,3}[ \-.])\d{3,4}[ \-.]?\d{3,4}(?![\d\-.])")
_PHONE_US_RE = re.compile(r"(?<![\w.\-])\(?[2-9]\d{2}\)?[ \-.][2-9]\d{2}[ \-.]\d{4}(?![\d\-.])")
_IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.]|\.\d)")
_IPV6_RE = re.compile(r"(?<![\w:.])[0-9A-Fa-f:]{2,39}(?:/\d{1,3})?(?![\w:])")
_DOB_RE = re.compile(
    r"(?i)\b(?:d\.?o\.?b\.?|date\s+of\s+birth|birth\s*date|born(?:\s+on)?)\s*[:\-]?\s*"
    r"((?:\d{1,2}[/\-. ]\d{1,2}[/\-. ](?:19|20)\d{2})|(?:(?:19|20)\d{2}[/\-.]\d{1,2}[/\-.]\d{1,2})|"
    r"(?:\d{1,2}\s+(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?,?\s+(?:19|20)\d{2})|"
    r"(?:(?:jan|feb|mar|apr|may|jun|jul|aug|sep|sept|oct|nov|dec)[a-z]*\.?\s+\d{1,2},?\s+(?:19|20)\d{2}))"
)

# Secrets with a recognisable prefix or shape: (detector id, regex, entity type, confidence).
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str], str, float], ...] = (
    ("private_key_block", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----"), "private_key", 0.99),
    ("aws_access_key_id", re.compile(r"(?<![A-Z0-9])(?:AKIA|ASIA|ABIA|ACCA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}(?![A-Z0-9])"), "api_key", 0.97),
    ("aws_secret_access_key", re.compile(r"(?i)aws.{0,24}(?:secret|private).{0,24}[:=]\s*[\"']?([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"), "api_key", 0.95),
    ("github_token", re.compile(r"(?<![A-Za-z0-9_])gh[pousr]_[A-Za-z0-9]{36,255}(?![A-Za-z0-9_])"), "api_key", 0.98),
    ("github_fine_grained_pat", re.compile(r"(?<![A-Za-z0-9_])github_pat_[A-Za-z0-9_]{40,255}"), "api_key", 0.98),
    ("gitlab_token", re.compile(r"(?<![A-Za-z0-9_])glpat-[A-Za-z0-9_\-]{20,}"), "api_key", 0.97),
    ("slack_token", re.compile(r"(?<![A-Za-z0-9])xox[abposr]-(?:\d+-)?[A-Za-z0-9\-]{10,}"), "api_key", 0.97),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+"), "api_key", 0.97),
    ("stripe_key", re.compile(r"(?<![A-Za-z0-9_])(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}"), "api_key", 0.97),
    ("anthropic_key", re.compile(r"(?<![A-Za-z0-9_\-])sk-ant-(?:api\d{2}-|admin\d{2}-)?[A-Za-z0-9_\-]{20,}"), "api_key", 0.98),
    ("openai_key", re.compile(r"(?<![A-Za-z0-9_\-])sk-(?:proj-|svcacct-|None-)?[A-Za-z0-9_\-]{20,}"), "api_key", 0.94),
    ("google_api_key", re.compile(r"(?<![A-Za-z0-9_\-])AIza[0-9A-Za-z\-_]{35}(?![0-9A-Za-z\-_])"), "api_key", 0.97),
    ("sendgrid_key", re.compile(r"SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}"), "api_key", 0.98),
    ("npm_token", re.compile(r"(?<![A-Za-z0-9_])npm_[A-Za-z0-9]{36}(?![A-Za-z0-9])"), "api_key", 0.97),
    ("pypi_token", re.compile(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}"), "api_key", 0.98),
    ("huggingface_token", re.compile(r"(?<![A-Za-z0-9_])hf_[A-Za-z]{34,}(?![A-Za-z0-9])"), "api_key", 0.95),
    ("azure_storage_key", re.compile(r"(?i)AccountKey=[A-Za-z0-9+/=]{60,}"), "api_key", 0.96),
    ("twilio_key", re.compile(r"(?<![A-Za-z0-9])SK[0-9a-f]{32}(?![A-Za-z0-9])"), "api_key", 0.85),
    ("jwt", re.compile(r"(?<![A-Za-z0-9_\-])eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}"), "api_key", 0.9),
    ("connection_string_password", re.compile(r"(?i)\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver|ftp|sftp|ldaps?)://[^\s:@/]{1,64}:[^\s@/]{3,128}@[^\s/]+"), "credential", 0.96),
)

_ASSIGNMENT_RE = re.compile(
    r"(?i)(?<![a-z0-9])(?P<key>password|passwd|pwd|pass|passphrase|secret|client[_\- ]?secret|api[_\- ]?key|apikey|access[_\- ]?key|"
    r"auth[_\- ]?token|access[_\- ]?token|refresh[_\- ]?token|bearer|private[_\- ]?key|token)"
    r"(?:\s+(?:for|of|to|on|at|in)\s+(?:the\s+|my\s+|our\s+|this\s+|a\s+)?[\w.\-]+(?:\s+[\w.\-]+)?)?"
    r"[\"']?(?P<sep>\s*(?:[:=]|=>|\bis\b)\s*|\s+)[\"']?(?P<value>[^\s\"',;]{6,200})"
)
_PLACEHOLDER_RE = re.compile(
    r"(?i)^(?:x+|\*+|\.+|<[^>]*>|\{\{?[^}]*\}?\}|\$\{[^}]*\}|\$[A-Z_]+|%[A-Z_]+%|changeme|change_me|password|secret|"
    r"your[_\-]?\w*|example\w*|placeholder|redacted|\[redacted\]|none|null|undefined|true|false|required|optional|string|"
    r"env\(.*\)|os\.environ.*|process\.env.*|getenv.*|settings\.\w+|config\.\w+|\w+\(\)?)$"
)
_GENERIC_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_\-+/=])[A-Za-z0-9_\-+/=]{24,200}(?![A-Za-z0-9_\-+/=])")
_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_DATEISH_RE = re.compile(r"\b(?:19|20)\d{2}[-/.]\d{1,2}[-/.]\d{1,2}\b|\b\d{1,2}[-/.]\d{1,2}[-/.](?:19|20)\d{2}\b")


def _clamp(value: float) -> float:
    return round(max(0.0, min(0.999, value)), 4)


def _detect_cards(norm: Normalized, low: str, out: list[Finding]) -> None:
    for match in _CARD_RE.finditer(norm.folded):
        raw = match.group(0)
        digits = digits_of(raw)
        if not 13 <= len(digits) <= 19 or len(set(digits)) == 1 or not luhn_valid(digits):
            continue
        # Groups must be consistent: "4111 1111 1111 1111", "4111-1111-...", "4111111111111111", or every digit spaced.
        separators = re.findall(r"[ \-.]+", raw)
        if separators and len({s for s in separators}) > 1 and not all(len(s) == 1 for s in separators):
            continue
        brand = card_brand(digits)
        ctx = _context_hit(low, match.start(), match.end(), "credit_card")
        if brand:
            conf = 0.93 + (0.05 if ctx else 0.0)
        else:
            conf = 0.72 if ctx else 0.5
        out.append(Finding("credit_card", match.start(), match.end(), _clamp(conf), "luhn_card", brand, ctx, reasons=("luhn",)))


def _detect_ibans(norm: Normalized, low: str, out: list[Finding]) -> None:
    for match in _IBAN_RE.finditer(norm.folded):
        value = match.group(1)
        expected = IBAN_LENGTHS.get(value[:2].upper())
        if not expected:
            continue
        # The pattern is greedy ("... 189 by Friday" takes "by" too): cut it at the country's length.
        start, end, count = match.start(1), match.start(1), 0
        for pos in range(match.start(1), match.end(1)):
            if norm.folded[pos].isalnum():
                count += 1
                if count == expected:
                    end = pos + 1
                    break
        if count != expected or not iban_valid(norm.folded[start:end]):
            continue
        ctx = _context_hit(low, start, end, "iban")
        conf = 0.97 + (0.02 if ctx else 0.0)
        out.append(Finding("iban", start, end, _clamp(conf), "iban_mod97", value[:2].upper(), ctx, reasons=("mod97",)))


def _detect_emirates_ids(norm: Normalized, low: str, out: list[Finding]) -> None:
    for match in _EID_RE.finditer(norm.folded):
        digits = digits_of(match.group(0))
        if len(digits) != 15:
            continue
        ctx = _context_hit(low, match.start(), match.end(), "emirates_id")
        if emirates_id_valid(digits):
            conf = 0.97 + (0.02 if ctx else 0.0)
            reasons: tuple[str, ...] = ("luhn", "year")
        elif ctx:
            conf, reasons = 0.8, ("context",)
        else:
            continue
        out.append(Finding("emirates_id", match.start(), match.end(), _clamp(conf), "emirates_id", None, ctx, reasons=reasons))


def _detect_ssn(norm: Normalized, low: str, out: list[Finding]) -> None:
    for match in _SSN_RE.finditer(norm.folded):
        digits = match.group(1) + match.group(3) + match.group(4)
        if not ssn_valid(digits):
            continue
        ctx = _context_hit(low, match.start(), match.end(), "us_ssn")
        # "123-45-6789"-shaped values are also part numbers and phone fragments: the separator must be a dash or
        # space and, without a context word, the score stays just above the reporting line.
        if _DATEISH_RE.search(norm.folded[max(0, match.start() - 2) : match.end() + 2]):
            continue
        if not ctx and re.search(r"\b(?:ext(?:ension)?|call|phone|tel|fax|part|order|invoice|ticket|ref(?:erence)?|sku|model|serial|case|po)\b[^\n]{0,24}$", low[max(0, match.start() - 32) : match.start()]):
            continue
        conf = 0.95 if ctx else (0.75 if match.group(2) == "-" else 0.6)
        out.append(Finding("us_ssn", match.start(), match.end(), _clamp(conf), "ssn_rules", None, ctx, reasons=("allocation_rules",)))
    for match in _SSN_BARE_RE.finditer(norm.folded):
        digits = match.group(0)
        if not ssn_valid(digits):
            continue
        if _context_hit(low, match.start(), match.end(), "us_ssn", window=32):
            out.append(Finding("us_ssn", match.start(), match.end(), 0.85, "ssn_rules", "unformatted", True, reasons=("allocation_rules", "context")))


def _detect_nino(norm: Normalized, low: str, out: list[Finding]) -> None:
    for match in _NINO_RE.finditer(norm.folded):
        value = "".join(match.groups())
        upper = value.isupper() or match.group(0).upper() == match.group(0)
        if not nino_valid(value):
            continue
        ctx = _context_hit(low, match.start(), match.end(), "uk_nino")
        if not upper and not ctx:
            continue
        conf = 0.96 if ctx else 0.8
        out.append(Finding("uk_nino", match.start(), match.end(), _clamp(conf), "nino_rules", None, ctx, reasons=("prefix_rules",)))


def _detect_passports(norm: Normalized, low: str, out: list[Finding]) -> None:
    text = norm.folded
    for match in _MRZ_LINE2_RE.finditer(text):
        number, c1, _nat, dob, c2, _sex, expiry, c3, personal, c4, final = match.groups()
        checks = [mrz_check(number, c1), mrz_check(dob, c2), mrz_check(expiry, c3)]
        if personal.strip("<") and c4 != "<":
            checks.append(mrz_check(personal, c4))
        composite = number + c1 + dob + c2 + expiry + c3 + personal + c4
        checks.append(mrz_check(composite, final))
        if all(checks):
            out.append(Finding("passport", match.start(), match.end(), 0.99, "mrz_td3", "mrz", True, reasons=("mrz_check_digits",)))
    for match in _MRZ_LINE1_RE.finditer(text):
        if match.group(0).count("<") >= 4:
            out.append(Finding("passport", match.start(), match.end(), 0.9, "mrz_td3", "mrz_line1", True, reasons=("mrz_header",)))
    for match in _PASSPORT_CONTEXT_RE.finditer(text):
        value = match.group(1)
        if not any(ch.isdigit() for ch in value):
            continue
        out.append(Finding("passport", match.start(1), match.end(1), 0.9, "passport_context", None, True, reasons=("context",)))


def _detect_emails(norm: Normalized, low: str, out: list[Finding]) -> None:
    for match in _EMAIL_RE.finditer(norm.folded):
        local, domain = match.group(1), match.group(2)
        if ".." in local or local.endswith(".") or domain.lower().endswith((".png", ".jpg", ".gif", ".svg", ".webp")):
            continue
        out.append(Finding("email", match.start(), match.end(), 0.97, "email", None, False, reasons=("rfc5322_shape",)))
    for match in _EMAIL_OBFUSCATED_RE.finditer(norm.folded):
        out.append(Finding("email", match.start(), match.end(), 0.85, "email_obfuscated", "obfuscated", False, reasons=("at_dot_spelled",)))


def _detect_phones(norm: Normalized, low: str, out: list[Finding]) -> None:
    text = norm.folded
    for match in _PHONE_INTL_RE.finditer(text):
        digits = digits_of(match.group(0))
        if not 8 <= len(digits) <= 15:
            continue
        ctx = _context_hit(low, match.start(), match.end(), "phone")
        out.append(Finding("phone", match.start(), match.end(), _clamp(0.88 + (0.08 if ctx else 0.0)), "phone_e164", "international", ctx, reasons=("e164",)))
    for regex, subtype in ((_PHONE_US_RE, "nanp"), (_PHONE_NATIONAL_RE, "national")):
        for match in regex.finditer(text):
            digits = digits_of(match.group(0))
            if not 9 <= len(digits) <= 12 or _DATEISH_RE.search(match.group(0)):
                continue
            ctx = _context_hit(low, match.start(), match.end(), "phone")
            if not ctx and subtype == "national":
                continue
            conf = 0.9 if ctx else 0.72
            out.append(Finding("phone", match.start(), match.end(), conf, f"phone_{subtype}", subtype, ctx, reasons=("national_format",)))


def _detect_ips(norm: Normalized, low: str, out: list[Finding]) -> None:
    text = norm.folded
    for match in _IPV4_RE.finditer(text):
        value = match.group(0)
        try:
            address = ipaddress.IPv4Address(value)
        except ValueError:
            continue
        before = low[max(0, match.start() - 16) : match.start()]
        if re.search(r"(?:\b(?:version|ver\.?|v|release|build|oid|section|sec\.?|clause|chapter|figure|fig\.?|table|step|rule|article|art\.?|item|paragraph|para\.?|no\.?)|[#§])\s*$", before):
            continue
        if all(len(octet) == 1 for octet in value.split(".")) and not _context_hit(low, match.start(), match.end(), "ip_address"):
            continue  # "3.1.4.1" is a section or version far more often than an address
        ctx = _context_hit(low, match.start(), match.end(), "ip_address")
        if address.is_unspecified or address.is_loopback or str(address).startswith("255."):
            continue
        subtype = "private" if address.is_private else "public"
        conf = (0.75 if subtype == "public" else 0.6) + (0.15 if ctx else 0.0)
        out.append(Finding("ip_address", match.start(), match.end(), _clamp(conf), "ipv4", subtype, ctx, reasons=("octets_valid",)))
    for match in _IPV6_RE.finditer(text):
        value = match.group(0).split("/")[0]
        if value.count(":") < 2 or re.fullmatch(r"[\d:]+", value) and value.count(":") < 4:
            continue  # times such as 12:30:45
        try:
            address = ipaddress.IPv6Address(value)
        except ValueError:
            continue
        if address.is_loopback or address.is_unspecified:
            continue
        ctx = _context_hit(low, match.start(), match.end(), "ip_address")
        out.append(Finding("ip_address", match.start(), match.end(), _clamp(0.75 + (0.15 if ctx else 0.0)), "ipv6", "ipv6", ctx, reasons=("ipv6_valid",)))


def _detect_dob(norm: Normalized, low: str, out: list[Finding]) -> None:
    for match in _DOB_RE.finditer(norm.folded):
        out.append(Finding("date_of_birth", match.start(1), match.end(1), 0.9, "dob_context", None, True, reasons=("context",)))


def _detect_secrets(norm: Normalized, low: str, out: list[Finding]) -> None:
    text = norm.folded
    covered: list[tuple[int, int]] = []
    for detector, regex, entity_type, conf in _SECRET_PATTERNS:
        for match in regex.finditer(text):
            span = match.span(1) if match.groups() else match.span()
            covered.append(span)
            out.append(Finding(entity_type, span[0], span[1], conf, detector, detector, True, reasons=("known_prefix",)))
    for match in _ASSIGNMENT_RE.finditer(text):
        value = match.group("value").strip("\"'`").rstrip(".!?)")
        start = match.start("value")
        end = start + len(match.group("value").rstrip(".!?)\"'`"))
        bare = not match.group("sep").strip()
        if any(s <= start < e for s, e in covered) or _PLACEHOLDER_RE.match(value) or len(value) < 6:
            continue
        key = match.group("key").lower()
        entropy = shannon_entropy(value)
        classes = char_classes(value)
        is_password_key = key.startswith("pass") or key == "pwd"
        if bare and (classes < 3 and not (classes >= 2 and any(ch.isdigit() for ch in value) and len(value) >= 8)):
            continue  # "password reset", "token expired": prose, not a value
        if is_password_key:
            # A password needs only to look like one: not a plain dictionary word, not prose.
            if value.isalpha() and value.islower() and len(value) < 10:
                continue
            conf = 0.86 if classes >= 2 else 0.7
            entity_type = "credential"
        else:
            if entropy < 3.0 or classes < 2:
                continue
            conf = 0.9 if entropy >= 3.5 and len(value) >= 16 else 0.78
            entity_type = "api_key"
        covered.append((start, end))
        out.append(Finding(entity_type, start, end, conf, "secret_assignment", key, True, reasons=("assignment", f"entropy_{entropy:.1f}")))
    for match in _GENERIC_TOKEN_RE.finditer(text):
        value = match.group(0)
        start, end = match.span()
        if any(s <= start < e or start <= s < end for s, e in covered) or _UUID_RE.match(value):
            continue
        entropy = shannon_entropy(value)
        classes = char_classes(value)
        if value.isdigit() or value.isalpha() or classes < 2 or entropy < 3.6:
            continue
        if re.fullmatch(r"[0-9a-f]+", value) and len(value) in (32, 40, 64) and not _context_hit(low, start, end, "api_key", window=24):
            continue  # commit SHAs and content hashes
        if "/" in value and value.count("/") >= 2 and not any(ch.isdigit() for ch in value.split("/")[-1]):
            continue  # a path
        ctx = _context_hit(low, start, end, "api_key", window=32)
        if ctx:
            conf = 0.85 if entropy >= 4.0 else 0.75
        elif entropy >= 4.5 and classes >= 3 and len(value) >= 32:
            conf = 0.62
        else:
            continue
        out.append(Finding("api_key", start, end, conf, "high_entropy_token", None, ctx, reasons=(f"entropy_{entropy:.1f}",)))


_DETECTORS = (
    ("credit_card", _detect_cards),
    ("iban", _detect_ibans),
    ("emirates_id", _detect_emirates_ids),
    ("us_ssn", _detect_ssn),
    ("uk_nino", _detect_nino),
    ("passport", _detect_passports),
    ("email", _detect_emails),
    ("phone", _detect_phones),
    ("ip_address", _detect_ips),
    ("date_of_birth", _detect_dob),
    ("secrets", _detect_secrets),
)

STRUCTURED_ENTITY_TYPES = (
    "credit_card", "iban", "emirates_id", "us_ssn", "uk_nino", "passport", "email", "phone", "ip_address",
    "date_of_birth", "api_key", "private_key", "credential",
)


def _overlaps(a: Finding, b: Finding) -> bool:
    return a.start < b.end and b.start < a.end


# When two findings overlap, the more specific type wins (an IBAN's digits are not also a phone number).
_TYPE_PRIORITY = {
    "private_key": 0, "credential": 1, "api_key": 2, "passport": 3, "iban": 4, "emirates_id": 5, "credit_card": 6,
    "us_ssn": 7, "uk_nino": 8, "email": 9, "date_of_birth": 10, "ip_address": 11, "phone": 12,
}


def resolve_overlaps(findings: list[Finding]) -> list[Finding]:
    ordered = sorted(findings, key=lambda f: (_TYPE_PRIORITY.get(f.entity_type, 50), -f.confidence, f.start))
    kept: list[Finding] = []
    for finding in ordered:
        if any(_overlaps(finding, other) and other.entity_type != finding.entity_type for other in kept):
            continue
        if any(_overlaps(finding, other) and other.entity_type == finding.entity_type for other in kept):
            continue
        kept.append(finding)
    return sorted(kept, key=lambda f: f.start)


def detect_structured(norm: Normalized, *, enabled: frozenset[str] | None = None) -> list[Finding]:
    low = norm.folded.lower()
    findings: list[Finding] = []
    for group, detector in _DETECTORS:
        if enabled is not None and group not in enabled and not (group == "secrets" and enabled & {"api_key", "private_key", "credential"}):
            continue
        detector(norm, low, findings)
    if enabled is not None:
        findings = [f for f in findings if f.entity_type in enabled]
    return resolve_overlaps(findings)
