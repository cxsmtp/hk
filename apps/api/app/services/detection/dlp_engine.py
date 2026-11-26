"""Layered, offline DLP scan of one text.

1. Normalise (NFKC, invisible characters, homoglyphs, leetspeak, spaced-out characters) and decode embedded base64 /
   hex / percent / \\u-escaped segments, which are scanned again.
2. Validated structured detectors (structured.py): checksums, allocation rules, known prefixes, entropy, context words.
3. Named entities (people, places, organisations) from Presidio/spaCy when a model is installed; see
   sensitive_data_detection_service.ner_status() — without one this layer reports itself unavailable.
4. Document classification (categories.py): weighted dictionaries per category, a source-code score, the tenant's own
   dictionaries, and exact data match against the tenant's salted fingerprints (fingerprints.py).

Only types, scores, reasons and offsets come out; values are never logged or returned except as a redacted preview.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.services.detection import fingerprints as edm
from app.services.detection.categories import CATEGORY_RULESET_VERSION, CategoryResult, classify_document
from app.services.detection.normalize import Normalized, normalize
from app.services.detection.profile import REPORT_MIN_CONFIDENCE, DetectionProfile, current_profile
from app.services.detection.structured import STRUCTURED_RULESET_VERSION, Finding, detect_structured

DLP_ENGINE_VERSION = "1"
MAX_SCAN_CHARS = 60_000


@dataclass
class DLPScan:
    findings: list[Finding]  # offsets in ``normalized.folded`` (encoded findings carry ``encoded`` and no usable span)
    categories: dict[str, CategoryResult]
    edm_matches: list[dict[str, Any]]
    normalized: Normalized
    obfuscation: list[str] = field(default_factory=list)

    def reportable(self, min_confidence: float = REPORT_MIN_CONFIDENCE) -> list[Finding]:
        return [f for f in self.findings if f.confidence >= min_confidence]

    def detected_categories(self, profile: DetectionProfile) -> dict[str, CategoryResult]:
        out: dict[str, CategoryResult] = {}
        for name, result in self.categories.items():
            base = name.split(":", 1)[0]
            if name.startswith("custom:"):
                if profile.enabled("custom_dictionary"):
                    out[name] = result
                continue
            if not profile.enabled(base):
                continue
            if result.score >= profile.document_min_score:
                out[name] = result
        return out

    def original_span(self, finding: Finding) -> tuple[int, int] | None:
        if finding.encoded:
            return None
        return self.normalized.original_span(finding.start, finding.end)


def scan(text: str, *, profile: DetectionProfile | None = None) -> DLPScan:
    profile = profile or current_profile()
    raw = (text or "")[:MAX_SCAN_CHARS]
    norm = normalize(raw)
    enabled = frozenset(t for t in _ALL_TYPES if profile.enabled(t))
    findings = detect_structured(norm, enabled=enabled)
    decoded_views: list[tuple[str, str]] = []
    for kind, segment in norm.decoded:
        inner = normalize(segment, decode=False)
        decoded_views.append((f"decoded:{kind}", inner.lowered))
        for finding in detect_structured(inner, enabled=enabled):
            findings.append(
                Finding(
                    finding.entity_type, finding.start, finding.end, finding.confidence, finding.detector, finding.subtype,
                    finding.context_hit, encoded=kind, reasons=(*finding.reasons, f"decoded_{kind}"),
                )
            )
    views = [*norm.matching_views(), *decoded_views]
    categories = classify_document(
        views,
        raw_text=norm.folded,
        custom=profile.custom_dictionaries if profile.enabled("custom_dictionary") else (),
        structured_types=[f.entity_type for f in findings if f.confidence >= REPORT_MIN_CONFIDENCE],
    )
    edm_matches: list[dict[str, Any]] = []
    if profile.fingerprint_sets and profile.enabled("exact_data_match"):
        pool = edm.candidates(norm.folded)
        for _kind, segment in norm.decoded:
            pool |= edm.candidates(segment)
        edm_matches = edm.match(norm.folded, salt=profile.fingerprint_salt, sets=profile.fingerprint_sets, candidate_set=pool)
        for hit in edm_matches:
            category = str(hit.get("category") or "custom")
            key = f"edm:{hit['set_id']}"
            categories[key] = CategoryResult(key, 0.99, int(hit["matches"]), [f"fingerprint_set:{hit['name']}"], "exact_data_match")
            if category in categories and not category.startswith(("custom:", "edm:")):
                categories[category].score = max(categories[category].score, 0.95)
    # Only the tricks that hide content: compatibility forms, leetspeak and non-ASCII digits are common in ordinary text.
    obfuscation = [s for s in norm.signals if s in ("zero_width", "homoglyph")]
    if any(f.encoded for f in findings):
        obfuscation.append("encoded_segment")
    return DLPScan(findings=findings, categories=categories, edm_matches=edm_matches, normalized=norm, obfuscation=obfuscation)


_ALL_TYPES = (
    "credit_card", "iban", "emirates_id", "us_ssn", "uk_nino", "passport", "email", "phone", "ip_address",
    "date_of_birth", "api_key", "private_key", "credential",
)


def versions() -> dict[str, str]:
    return {
        "dlp_engine": DLP_ENGINE_VERSION,
        "structured_rules": STRUCTURED_RULESET_VERSION,
        "category_dictionaries": CATEGORY_RULESET_VERSION,
    }
