"""Document / semantic classification: weighted phrase dictionaries per category, a structural source-code score, and
customer-defined dictionaries.

A category's score is ``1 - prod(1 - w)`` over the distinct phrases found (strong 0.5, medium 0.3, weak 0.15), so one
phrase never decides alone; categories that describe documents full of figures or code also need that structure.
Short questions about a topic ("what is a balance sheet?") are damped, so asking about a subject is not the same as
pasting a document about it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

CATEGORY_RULESET_VERSION = "2026.11.1"

STRONG, MEDIUM, WEAK = 0.5, 0.3, 0.15

DOCUMENT_CATEGORIES = ("source_code", "financial_statements", "mna", "hr_medical", "legal_privilege", "credentials")

_DICTIONARIES: dict[str, dict[float, tuple[str, ...]]] = {
    "financial_statements": {
        STRONG: (
            "balance sheet", "income statement", "cash flow statement", "statement of cash flows", "profit and loss statement",
            "p&l statement", "consolidated financial statements", "unaudited financial results", "unaudited results",
            "earnings per share", "general ledger", "trial balance", "statement of financial position", "10-k filing",
            "quarterly earnings report", "management accounts", "board financial pack", "annual report and accounts",
            "statement of comprehensive income", "audited accounts",
        ),
        MEDIUM: (
            "ebitda", "net income", "gross margin", "operating income", "total revenue", "accounts receivable",
            "accounts payable", "retained earnings", "operating expenses", "free cash flow", "fiscal year",
            "year-over-year", "year over year", "revenue forecast", "budget variance", "depreciation", "amortization",
            "shareholders' equity", "shareholders equity", "net profit", "cost of goods sold", "cogs", "gross profit",
            "operating margin", "total liabilities", "total assets", "current liabilities", "working capital",
            "q1 revenue", "q2 revenue", "q3 revenue", "q4 revenue", "full-year guidance", "earnings guidance",
        ),
        WEAK: ("revenue", "profit", "forecast", "quarterly", "audit", "budget", "assets", "liabilities", "opex", "capex"),
    },
    "mna": {
        STRONG: (
            "letter of intent", "term sheet", "due diligence", "definitive agreement", "merger agreement",
            "acquisition target", "target company", "purchase price", "share purchase agreement", "asset purchase agreement",
            "tender offer", "non-binding offer", "indicative offer", "virtual data room", "data room", "break fee",
            "earn-out", "earnout", "deal team", "material non-public information", "mnpi", "insider list",
            "exclusivity period", "enterprise value", "synergy case", "fairness opinion", "project codename",
            "pre-announcement", "heads of terms",
        ),
        MEDIUM: (
            "merger", "acquisition", "acquire", "valuation", "transaction", "bidder", "buyer", "seller", "board approval",
            "closing date", "investment bank", "multiple of ebitda", "takeover", "divestiture", "carve-out", "joint venture",
            "deal value", "offer price", "per share", "announcement date", "signing date",
        ),
        WEAK: ("deal", "bid", "premium", "shareholders", "strategic", "negotiation", "announcement"),
    },
    "hr_medical": {
        STRONG: (
            "performance improvement plan", "disciplinary hearing", "disciplinary action", "termination letter",
            "grievance", "medical leave", "sick note", "diagnosis", "diagnosed with", "prescription", "medical record",
            "patient record", "health record", "treatment plan", "icd-10", "medical history", "mental health",
            "fmla", "workers' compensation claim", "background check results", "salary review", "compensation package",
            "pay slip", "payslip", "employee relations case", "redundancy", "occupational health", "hiv positive",
            "disability accommodation", "medical record number", "maternity leave", "fit note", "psychiatric",
        ),
        MEDIUM: (
            "salary", "bonus", "performance review", "termination", "dismissal", "patient", "clinic", "hospital",
            "medication", "symptoms", "blood test", "lab results", "therapy", "employee id", "date of birth",
            "home address", "next of kin", "sick leave", "hr case", "investigation", "allergies", "dosage", "pregnant",
            "pregnancy", "chronic", "underperformance", "final written warning", "written warning", "garnishment",
        ),
        WEAK: ("employee", "health", "leave", "doctor", "manager", "absence", "condition"),
    },
    "legal_privilege": {
        STRONG: (
            "attorney-client privilege", "attorney client privilege", "attorney-client privileged", "privileged and confidential",
            "privileged & confidential", "legally privileged", "attorney work product", "work product doctrine",
            "litigation hold", "legal hold", "without prejudice", "subject to legal privilege",
            "prepared at the request of counsel", "settlement agreement", "under seal", "cease and desist", "subpoena",
            "privileged communication", "legal professional privilege", "common interest privilege",
        ),
        MEDIUM: (
            "outside counsel", "general counsel", "litigation", "lawsuit", "plaintiff", "defendant", "deposition",
            "settlement", "legal advice", "law firm", "indemnity", "breach of contract", "regulator inquiry", "court filing",
            "claimant", "arbitration", "damages", "liability exposure",
        ),
        WEAK: ("counsel", "legal", "contract", "agreement", "dispute", "lawyer", "court", "claim"),
    },
    "credentials": {
        STRONG: (
            "here is my password", "my password is", "the password is", "password is", "root password", "admin password",
            "login credentials", "vpn credentials", "ssh private key", "private key", "client secret", "secret key",
            "connection string", "service account key", "backup codes", "recovery codes", "seed phrase",
            "mnemonic phrase", "aws_secret_access_key", "access key id", "api token", "bearer token",
        ),
        MEDIUM: (
            "password", "passwd", "username", "login", "credentials", "access token", "api key", "secret", "keystore",
            "kubeconfig", ".env file", "pin code", "passcode", "one-time code", "otp",
        ),
        WEAK: ("account", "auth", "sign in", "token"),
    },
    "source_code": {
        MEDIUM: ("all rights reserved", "proprietary and confidential", "proprietary", "internal use only", "do not distribute"),
        WEAK: ("copyright", "license", "confidential", "repository", "commit"),
    },
}

# Categories whose genuine documents are full of figures or code: without that structure the phrase score is capped
# below the reporting line, so talking about the subject is not treated as the document itself.
_NUMERIC_TOKEN_RE = re.compile(r"(?:[$€£¥]|aed|usd|eur|gbp)?\s?\(?-?\d[\d,]*(?:\.\d+)?\)?\s?(?:%|[kmb]n?\b|million|billion|thousand)?", re.I)
_QUESTION_RE = re.compile(
    r"^\s*(?:what|what's|whats|how|why|when|where|which|who|can|could|should|would|is|are|do|does|explain|define|describe|"
    r"tell me|give me an example|help me understand|what is the difference)\b",
    re.I,
)
_EDUCATIONAL_RE = re.compile(r"\b(?:example|template|explain|definition|meaning|difference between|in general|tutorial|course|homework|exam)\b", re.I)

_CODE_LINE_RES = (
    re.compile(r"^\s*(?:def|class|async def)\s+\w+.*:\s*$"),
    re.compile(r"^\s*(?:import\s+[\w.]+|from\s+[\w.]+\s+import\s+)"),
    re.compile(r"^\s*(?:public|private|protected|internal|static|final|abstract|override)\s+[\w<>\[\], ]+\s*\(?"),
    re.compile(r"^\s*(?:function\s+\w+|const\s+\w+\s*=|let\s+\w+\s*=|var\s+\w+\s*=|export\s+(?:default\s+)?(?:function|class|const))"),
    re.compile(r"^\s*(?:#include\s*[<\"]|using\s+namespace\s|package\s+[\w.]+;?|namespace\s+\w+)"),
    re.compile(r"^\s*(?:fn|func|impl|struct|enum|trait|interface|type)\s+\w+"),
    re.compile(r"^\s*(?:if|for|while|switch|catch|elif|else if)\s*\(?.*[\{:]\s*$"),
    re.compile(r"^\s*(?:return\b.*;?|\}\s*(?:else\s*\{)?|\{|\);?|\];?)\s*$"),
    re.compile(r"[;{]\s*$"),
    re.compile(r"^\s*(?:@\w+(?:\(.*\))?|#!\s*/)"),
    re.compile(r"(?i)^\s*(?:select\s+.+\s+from\s+\w+|insert\s+into\s+\w+|update\s+\w+\s+set\s|create\s+(?:table|index|view)\s|alter\s+table\s)"),
    re.compile(r"(?i)^\s*(?:select|from|(?:left\s+|right\s+|inner\s+|outer\s+|full\s+)?join|where|group\s+by|order\s+by|having|limit|union(?:\s+all)?|values|delete\s+from|with\s+\w+\s+as)\s+[\w*(\'\"]"),
    re.compile(r"^\s*\w+(?:\.\w+)*\s*(?:=|\+=|-=|:=)\s*[\w\"'\[{(].*$"),
    re.compile(r"^\s*(?:self|this)\.\w+"),
    re.compile(r"^\s*//|^\s*/\*|^\s*\*\s|^\s*#\s*(?:TODO|FIXME|noqa)"),
)


@dataclass(frozen=True)
class CustomDictionary:
    id: str
    name: str
    terms: tuple[str, ...]
    category: str = "custom"
    confidence: float = 0.9
    min_matches: int = 1
    enabled: bool = True


@dataclass
class CategoryResult:
    category: str
    score: float
    terms_matched: int
    reasons: list[str] = field(default_factory=list)
    source: str = "dictionary"  # dictionary | structure | custom_dictionary | exact_data_match

    def to_dict(self) -> dict[str, object]:
        return {
            "category": self.category,
            "score": round(self.score, 4),
            "terms_matched": self.terms_matched,
            "reasons": list(self.reasons),
            "source": self.source,
        }


_TOKEN_RE = re.compile(r"[^\s\-_/]+")
_EDGE = "\"'`.,;:!?()[]{}<>*"


def _tokens(text: str) -> list[str]:
    """Words of a lower-case text for phrase matching: split on spaces, hyphens, underscores and slashes, with
    surrounding punctuation dropped ("year-over-year" and "year over year" read alike; ".env" keeps its dot)."""
    out = []
    for raw in _TOKEN_RE.findall(text):
        token = raw.rstrip(_EDGE).lstrip(_EDGE.replace(".", ""))
        if token:
            out.append(token)
    return out


class PhraseIndex:
    """Phrases (several words) looked up by their first word: one pass over a text's words, however many phrases."""

    def __init__(self, phrases: Iterable[str]) -> None:
        self.by_first: dict[str, list[tuple[tuple[str, ...], str]]] = {}
        for phrase in phrases:
            words = tuple(_tokens(phrase.lower()))
            if words:
                self.by_first.setdefault(words[0], []).append((words, " ".join(words)))
        for entries in self.by_first.values():
            entries.sort(key=lambda entry: -len(entry[0]))

    def find(self, text: str) -> set[str]:
        words = _tokens(text)
        found: set[str] = set()
        for i, word in enumerate(words):
            entries = self.by_first.get(word)
            if not entries:
                continue
            for phrase_words, key in entries:
                n = len(phrase_words)
                if tuple(words[i : i + n]) == phrase_words:
                    found.add(key)
                    break
        return found


_PHRASE_INDEX: dict[str, list[tuple[str, float]]] = {}
for _category, _levels in _DICTIONARIES.items():
    for _weight, _phrases in _levels.items():
        for _phrase in _phrases:
            _PHRASE_INDEX.setdefault(" ".join(_tokens(_phrase.lower())), []).append((_category, _weight))
_ALL_PHRASES = PhraseIndex(_PHRASE_INDEX.keys())


def source_code_score(text: str) -> tuple[float, int]:
    lines = [line for line in text.splitlines() if line.strip()]
    if len(lines) < 3:
        return 0.0, 0
    code_lines = 0
    for line in lines[:400]:
        if any(regex.search(line) for regex in _CODE_LINE_RES):
            code_lines += 1
    ratio = code_lines / min(len(lines), 400)
    indented = sum(1 for line in lines[:400] if line.startswith(("    ", "\t")))
    symbol_density = sum(text.count(ch) for ch in "{}();=[]<>") / max(1, len(text))
    if code_lines < 3 or ratio < 0.35:
        return 0.0, code_lines
    score = 0.45 + 0.4 * min(1.0, (ratio - 0.35) / 0.4) + min(0.1, indented / max(1, len(lines)) * 0.2)
    if symbol_density > 0.03:
        score += 0.05
    if code_lines >= 8:
        score += 0.05
    return min(0.97, score), code_lines


def classify_document(
    views: list[tuple[str, str]],
    *,
    raw_text: str,
    custom: Iterable[CustomDictionary] = (),
    structured_types: Iterable[str] = (),
) -> dict[str, CategoryResult]:
    """Score each category over the matching views of one text (plain, de-leeted, de-spaced, decoded)."""
    matched: dict[str, dict[str, float]] = {}
    for _name, view in views:
        for key in _ALL_PHRASES.find(view):
            for category, weight in _PHRASE_INDEX.get(key, ()):
                bucket = matched.setdefault(category, {})
                bucket[key] = max(bucket.get(key, 0.0), weight)

    results: dict[str, CategoryResult] = {}
    plain = views[0][1] if views else ""
    numeric_tokens = sum(1 for m in _NUMERIC_TOKEN_RE.finditer(plain) if any(ch.isdigit() for ch in m.group(0)))
    is_short_question = len(plain) < 280 and (bool(_QUESTION_RE.search(plain)) or plain.rstrip().endswith("?"))
    educational = bool(_EDUCATIONAL_RE.search(plain)) and len(plain) < 600

    for category, terms in matched.items():
        remaining = 1.0
        for weight in terms.values():
            remaining *= 1.0 - weight
        score = 1.0 - remaining
        reasons = [f"terms:{len(terms)}"]
        if category == "financial_statements" and numeric_tokens < 4:
            score = min(score, 0.55)
            reasons.append("few_figures")
        if is_short_question or educational:
            score *= 0.6
            reasons.append("question_damped")
        results[category] = CategoryResult(category, score, len(terms), reasons)

    code_score, code_lines = source_code_score(raw_text)
    if code_score > 0:
        existing = results.get("source_code")
        combined = code_score if existing is None else 1.0 - (1.0 - code_score) * (1.0 - existing.score)
        results["source_code"] = CategoryResult(
            "source_code", min(0.99, combined), (existing.terms_matched if existing else 0), [f"code_lines:{code_lines}"], "structure"
        )
    elif "source_code" in results:
        # Licence words alone are not code.
        results["source_code"].score = min(results["source_code"].score, 0.4)

    structured = set(structured_types)
    if structured & {"api_key", "private_key", "credential"}:
        existing = results.get("credentials")
        base = 0.9
        combined = base if existing is None else 1.0 - (1.0 - base) * (1.0 - existing.score)
        results["credentials"] = CategoryResult("credentials", min(0.99, combined), (existing.terms_matched if existing else 0), ["validated_secret"], "structure")

    for dictionary in custom:
        if not dictionary.enabled or not dictionary.terms:
            continue
        index = _custom_index(dictionary)
        hits: set[str] = set()
        for _name, view in views:
            hits.update(index.find(view))
        if len(hits) < max(1, dictionary.min_matches):
            continue
        key = f"custom:{dictionary.id}"
        results[key] = CategoryResult(key, dictionary.confidence, len(hits), [f"dictionary:{dictionary.name}"], "custom_dictionary")
        if dictionary.category in DOCUMENT_CATEGORIES:
            existing = results.get(dictionary.category)
            combined = dictionary.confidence if existing is None else 1.0 - (1.0 - dictionary.confidence) * (1.0 - existing.score)
            results[dictionary.category] = CategoryResult(
                dictionary.category, min(0.99, combined), len(hits) + (existing.terms_matched if existing else 0),
                [*(existing.reasons if existing else []), f"custom_dictionary:{dictionary.id}"], "custom_dictionary",
            )
    return results


_CUSTOM_CACHE: dict[tuple[str, ...], PhraseIndex] = {}


def _custom_index(dictionary: CustomDictionary) -> PhraseIndex:
    key = tuple(sorted(term.lower() for term in dictionary.terms))
    if key not in _CUSTOM_CACHE:
        if len(_CUSTOM_CACHE) > 256:
            _CUSTOM_CACHE.clear()
        _CUSTOM_CACHE[key] = PhraseIndex(dictionary.terms)
    return _CUSTOM_CACHE[key]


def dictionary_terms(category: str) -> dict[str, list[str]]:
    """The built-in phrases of one category, by strength (for the coverage endpoint)."""
    levels = _DICTIONARIES.get(category, {})
    names = {STRONG: "strong", MEDIUM: "medium", WEAK: "weak"}
    return {names[w]: list(p) for w, p in levels.items()}
