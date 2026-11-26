"""Offline text normalisation shared by the DLP and prompt-injection detectors.

Attackers (and ordinary copy/paste) hide sensitive values and instructions behind Unicode tricks: full-width or
Arabic-Indic digits, zero-width characters, Cyrillic/Greek look-alike letters, leetspeak, letters or digits spaced out
one by one, or a base64/hex/percent-encoded segment. Everything here is deterministic, standard library only, and keeps
an offset map back to the original text so a value found in the normalised text can still be masked in the original.
"""

from __future__ import annotations

import base64
import binascii
import functools
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

# Escaped, never literal (a "Trojan Source" risk in source files): zero-width, joiners, bidi controls, soft hyphen,
# word joiner and invisible operators, Mongolian vowel separator, combining grapheme joiner, BOM.
_INVISIBLE = frozenset(
    [
        "\u00ad", "\u034f", "\u061c", "\u115f", "\u1160", "\u17b4", "\u17b5", "\u180e",
        "\u200b", "\u200c", "\u200d", "\u200e", "\u200f",
        "\u202a", "\u202b", "\u202c", "\u202d", "\u202e",
        "\u2060", "\u2061", "\u2062", "\u2063", "\u2064",
        "\u2066", "\u2067", "\u2068", "\u2069", "\u3164", "\ufeff", "\uffa0",
    ]
)

# Cyrillic, Greek and other letters that render like Latin ones. Folded only inside words that also carry Latin
# letters, or when the text is mostly Latin, so genuine Russian or Greek text is left alone.
HOMOGLYPHS: dict[str, str] = {
    # Cyrillic lower case
    "\u0430": "a", "\u0432": "b", "\u0435": "e", "\u0451": "e", "\u043a": "k", "\u043c": "m", "\u043d": "h",
    "\u043e": "o", "\u0440": "p", "\u0441": "c", "\u0442": "t", "\u0443": "y", "\u0445": "x", "\u0455": "s",
    "\u0456": "i", "\u0457": "i", "\u0458": "j", "\u0501": "d", "\u04cf": "l", "\u0461": "w", "\u051b": "q",
    "\u0475": "v", "\u0491": "r",
    # Cyrillic upper case
    "\u0410": "A", "\u0412": "B", "\u0415": "E", "\u041a": "K", "\u041c": "M", "\u041d": "H", "\u041e": "O",
    "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X", "\u0423": "Y", "\u0405": "S", "\u0406": "I",
    "\u0408": "J", "\u04c0": "I", "\u0417": "3",
    # Greek
    "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b9": "i", "\u03ba": "k", "\u03bd": "v", "\u03bf": "o",
    "\u03c1": "p", "\u03c4": "t", "\u03c5": "u", "\u03c7": "x", "\u03c9": "w",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z", "\u0397": "H", "\u0399": "I", "\u039a": "K",
    "\u039c": "M", "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a5": "Y", "\u03a7": "X",
    # Latin look-alikes outside ASCII that NFKC leaves alone
    "\u0131": "i", "\u0261": "g", "\u01c0": "l", "\u0251": "a", "\u0269": "i", "\u028f": "y", "\u1d00": "a",
    "\u0280": "r", "\u026a": "i", "\u1d0f": "o", "\u0274": "n", "\u1d1b": "t",
}

_LEET: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", "9": "g",
    "@": "a", "$": "s", "!": "i", "|": "l", "+": "t", "€": "e", "£": "l",
}

_WORD_RE = re.compile(r"[^\W_]+", re.UNICODE)
# Only words that mix letters with digits or symbols ("1gn0re", "p@ss"): plain words and plain numbers are skipped.
_LEET_TOKEN_RE = re.compile(r"[a-z0-9@$!|+€£]*(?:[a-z][0-9@$!|+€£]|[0-9@$!|+€£][a-z])[a-z0-9@$!|+€£]*")
_LEET_SYMBOLS = frozenset("@$!|+€£")
# Three or more single letters or digits, each followed by one separator: "i g n o r e", "4.1.1.1", "p-a-s-s".
_SPACED_RUN_RE = re.compile(r"(?<![^\W_])(?:[^\W_][ .\-_*·/]){2,}[^\W_](?![^\W_])")
_MULTI_SPACE_RE = re.compile(r"\s+")

_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])(?:[A-Za-z0-9+/]{4}){4,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?(?![A-Za-z0-9+/=])")
_BASE64URL_RE = re.compile(r"(?<![A-Za-z0-9_\-])[A-Za-z0-9_\-]{24,}(?![A-Za-z0-9_\-])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:(?:0x)?[0-9A-Fa-f]{2}[\s:]?){12,}(?![0-9A-Fa-f])")
_PERCENT_RE = re.compile(r"(?:%[0-9A-Fa-f]{2}[^\s%]{0,3}){4,}")
_UNICODE_ESCAPE_RE = re.compile(r"(?:\\u[0-9A-Fa-f]{4}|\\x[0-9A-Fa-f]{2}){4,}")

MAX_DECODED_SEGMENTS = 8
MAX_SEGMENT_CHARS = 4096


@dataclass
class Normalized:
    """The views of one text. ``folded`` keeps an offset map to the original; the other views are for matching only."""

    original: str
    folded: str  # NFKC, invisible characters removed, homoglyphs folded, every digit ASCII
    offsets: list[int]  # offsets[i] = index in ``original`` of folded[i]
    lowered: str  # folded, casefolded, whitespace collapsed
    deleeted: str  # lowered with leetspeak undone inside words ("1" read as "i")
    deleeted_l: str  # the same with "1" read as "l" ("a11" -> "all"); empty when there is no "1" to read
    despaced: str  # lowered with spaced-out letters/digits joined
    decoded: list[tuple[str, str]] = field(default_factory=list)  # (encoding, decoded text)
    signals: list[str] = field(default_factory=list)  # obfuscation observed, e.g. "zero_width", "homoglyph"

    def original_span(self, start: int, end: int) -> tuple[int, int]:
        """Map a [start, end) span of ``folded`` back to the original text."""
        if not self.offsets or start >= len(self.offsets):
            return (len(self.original), len(self.original))
        o_start = self.offsets[max(0, start)]
        o_end = self.offsets[max(start, min(end, len(self.offsets)) - 1)] + 1
        return (o_start, o_end)

    def matching_views(self) -> list[tuple[str, str]]:
        """Distinct lower-case views to run phrase and rule matching on, the plain one first."""
        out: list[tuple[str, str]] = [("plain", self.lowered)]
        seen = {self.lowered}
        for name, view in (("deleet", self.deleeted), ("deleet_l", self.deleeted_l), ("despaced", self.despaced)):
            if view and view not in seen:
                seen.add(view)
                out.append((name, view))
        return out


def _fold_char(ch: str) -> str:
    if ch in _INVISIBLE:
        return ""
    category = unicodedata.category(ch)
    if category == "Cf":  # any other format control is invisible too
        return ""
    if category == "Nd" and not ("0" <= ch <= "9"):
        try:
            return str(unicodedata.decimal(ch))
        except (TypeError, ValueError):
            return ch
    if ord(ch) < 128:
        return ch
    norm = unicodedata.normalize("NFKC", ch)
    # Strip combining marks used to disguise letters ("i" + U+0307 + "gnore"), but keep letters of scripts that need them.
    if category == "Mn":
        return ""
    return norm


def _is_mostly_latin(text: str) -> bool:
    latin = other = 0
    for ch in text:
        if ch.isalpha():
            if ord(ch) < 0x250:
                latin += 1
            else:
                other += 1
    return latin > 0 and latin >= 3 * other


def fold(text: str) -> tuple[str, list[int], list[str]]:
    """NFKC per character, invisible characters removed, digits to ASCII, homoglyphs folded; with offsets."""
    if text.isascii():
        return text, list(range(len(text))), []
    out_chars: list[str] = []
    offsets: list[int] = []
    signals: set[str] = set()
    for index, ch in enumerate(text):
        if ch in _INVISIBLE or (ord(ch) >= 128 and unicodedata.category(ch) == "Cf"):
            signals.add("zero_width")
            continue
        folded = _fold_char(ch)
        if folded != ch and ord(ch) >= 128 and folded:
            if unicodedata.category(ch) == "Nd":
                signals.add("non_ascii_digits")
            elif unicodedata.normalize("NFKC", ch) != ch:
                signals.add("compatibility_forms")
        for out_ch in folded:
            out_chars.append(out_ch)
            offsets.append(index)
    folded_text = "".join(out_chars)

    if any(ch in HOMOGLYPHS for ch in folded_text):
        mostly_latin = _is_mostly_latin(folded_text)
        chars = list(folded_text)
        for match in _WORD_RE.finditer(folded_text):
            word = match.group(0)
            if not any(ch in HOMOGLYPHS for ch in word):
                continue
            has_latin = any("a" <= ch.lower() <= "z" for ch in word)
            if has_latin or mostly_latin:
                signals.add("homoglyph")
                for pos in range(match.start(), match.end()):
                    replacement = HOMOGLYPHS.get(chars[pos])
                    if replacement:
                        chars[pos] = replacement
        folded_text = "".join(chars)
    return folded_text, offsets, sorted(signals)


def _deleet(lowered: str, *, one: str = "i") -> tuple[str, bool]:
    changed = False
    table = dict(_LEET, **{"1": one})

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        token = match.group(0)
        letters = sum(1 for ch in token if ch.isalpha())
        # Only undo leetspeak inside words that are mostly letters: "1gn0re" yes, "2024" or "v1.2" no.
        if letters < 1 or letters * 2 < len(token) - 1:
            return token
        last = len(token) - 1
        new = "".join(
            ch if (ch in _LEET_SYMBOLS and (pos == 0 or pos == last)) else table.get(ch, ch)
            for pos, ch in enumerate(token)
        )
        if new != token:
            changed = True
        return new

    return _LEET_TOKEN_RE.sub(repl, lowered), changed


def _despace(lowered: str) -> tuple[str, bool]:
    changed = False

    def repl(match: re.Match[str]) -> str:
        nonlocal changed
        changed = True
        return re.sub(r"[ .\-_*·/]", "", match.group(0))

    # Words spaced letter by letter are usually separated by two or more spaces or a slash: keep that as one space.
    staged = re.sub(r"(?<=\S) {2,}(?=\S)|\s*/\s*(?=\S)", "  ", lowered)
    joined = _SPACED_RUN_RE.sub(repl, staged)
    if not changed:
        return lowered, False
    return _MULTI_SPACE_RE.sub(" ", joined), True


def _printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    good = sum(1 for ch in text if ch.isprintable() or ch in "\n\r\t")
    return good / len(text)


def _try_text(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    letters = sum(1 for ch in text if ch.isalnum())
    if len(text) < 6 or _printable_ratio(text) < 0.95 or letters < len(text) * 0.4:
        return None
    return text


def decode_segments(text: str, *, depth: int = 2) -> list[tuple[str, str]]:
    """Decode base64, base64url, hex, percent and \\u-escaped segments that hold readable text (bounded)."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(kind: str, decoded: str | None) -> None:
        if not decoded or decoded in seen or len(found) >= MAX_DECODED_SEGMENTS:
            return
        decoded = decoded[:MAX_SEGMENT_CHARS]
        seen.add(decoded)
        found.append((kind, decoded))

    if not text:
        return found
    for match in _BASE64_RE.finditer(text):
        blob = match.group(0)
        if blob.isdigit() or blob.isalpha() and blob.islower():
            continue
        try:
            add("base64", _try_text(base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)))
        except (binascii.Error, ValueError):
            continue
    for match in _BASE64URL_RE.finditer(text):
        blob = match.group(0)
        if not any(ch in "-_" for ch in blob):
            continue
        try:
            add("base64url", _try_text(base64.urlsafe_b64decode(blob + "=" * (-len(blob) % 4))))
        except (binascii.Error, ValueError):
            continue
    for match in _HEX_RE.finditer(text):
        blob = re.sub(r"0x|[\s:]", "", match.group(0))
        if len(blob) % 2:
            blob = blob[:-1]
        try:
            add("hex", _try_text(bytes.fromhex(blob)))
        except ValueError:
            continue
    for match in _PERCENT_RE.finditer(text):
        decoded = unquote(match.group(0))
        if decoded != match.group(0):
            add("percent", decoded)
    for match in _UNICODE_ESCAPE_RE.finditer(text):
        try:
            add("unicode_escape", match.group(0).encode("ascii").decode("unicode_escape"))
        except (UnicodeDecodeError, UnicodeEncodeError, ValueError):
            continue
    if depth > 1:
        for kind, decoded in list(found):
            for inner_kind, inner in decode_segments(decoded, depth=depth - 1):
                add(f"{kind}+{inner_kind}", inner)
    return found


def normalize(text: str, *, decode: bool = True) -> Normalized:
    """The views of a text. The result is shared (a small cache, as the DLP and injection detectors both normalise
    the same prompt): treat it as read-only."""
    return _normalize_cached(text or "", decode)


@functools.lru_cache(maxsize=64)
def _normalize_cached(text: str, decode: bool) -> Normalized:
    original = text
    folded, offsets, signals = fold(original)
    lowered = _MULTI_SPACE_RE.sub(" ", folded.casefold())
    deleeted, leet_changed = _deleet(lowered)
    deleeted_l = _deleet(lowered, one="l")[0] if leet_changed and "1" in lowered else ""
    spaced_source = folded.casefold()
    if leet_changed:
        spaced_source = _deleet(spaced_source)[0]
    despaced, spaced_changed = _despace(spaced_source)
    if not spaced_changed:
        despaced = deleeted
    if leet_changed:
        signals.append("leetspeak")
    if spaced_changed:
        signals.append("spaced_out")
    decoded = decode_segments(folded) if decode else []
    if decoded:
        signals.append("encoded_segment")
    return Normalized(
        original=original,
        folded=folded,
        offsets=offsets,
        lowered=lowered,
        deleeted=deleeted,
        deleeted_l=deleeted_l,
        despaced=despaced,
        decoded=decoded,
        signals=sorted(set(signals)),
    )
