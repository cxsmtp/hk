"""Prompt-injection / jailbreak risk: normalisation + the curated rule set + the offline classifier, combined into
one risk score with stable reason codes, then mapped to the tenant's action thresholds (block / hold / redact / log).

    rule_score = 1 - prod(1 - weight) over the distinct rules matched (any view: plain, de-leeted, de-spaced, decoded)
    risk       = 1 - (1 - rule_score) * (1 - 0.75 * classifier)  (+0.1 when an instruction was hidden by obfuscation)

The classifier alone tops out at 0.75, under the default block line (0.85): it raises a matched rule to a block, or
logs a novel phrasing, but never blocks on its own unless a tenant lowers the block threshold.

Reason codes (stable): ``pi.rule.<rule id>``, ``pi.category.<category>``, ``pi.classifier``, ``pi.obfuscation.<signal>``,
``pi.encoded.<encoding>``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.services.detection import injection_classifier
from app.services.detection.injection_rules import CATEGORIES, RULES, RULESET_VERSION, Rule
from app.services.detection.normalize import normalize
from app.services.detection.profile import DetectionProfile, current_profile

ENGINE_VERSION = "1"
CLASSIFIER_WEIGHT = 0.75
CLASSIFIER_MIN_DECODED_WORDS = 4
# With no rule matched, the classifier acts alone only on a sentence-length text it is sure about: on a few words
# out of its vocabulary ("safe operational request") its score says little.
CLASSIFIER_ONLY_MIN_WORDS = 6
CLASSIFIER_ONLY_MIN_SCORE = 0.8
CLASSIFIER_REASON_MIN = 0.5
OBFUSCATION_BONUS = 0.1
MENTION_DAMPING = 0.35

_META_RE = re.compile(
    r"\b(?:summar(?:y|ise|ize|ising|izing)\s+(?:this|the)\s+(?:article|paper|report|post|thread)|this\s+(?:article|paper|report|blog\s+post)\s+(?:about|on)|"
    r"(?:article|newsletter|blog\s+post|training|awareness|slide|lecture|class|course|paper|research|report)\s+(?:about|on|explaining|describing)|"
    r"how\s+(?:should|can|do|does)\s+(?:we|our|a|the)\s+(?:guardrail|filter|detector|model|bot|system|team|company|companies)\s+(?:respond|handle|detect|defend|block|deal)|"
    r"(?:explain|describe)\s+(?:how|what|why)\b.{0,40}\b(?:attack|attacks|jailbreaks?|injection|detection)\b|"
    r"red\s+team\s+report|for\s+(?:a|an|our)\s+(?:security|ai\s+safety)\s+(?:class|course|training|newsletter|team))"
)
_QUOTED_RE = re.compile(r"[\"“«]([^\"”»]{3,200})[\"”»]|(?:^|(?<=[\s(]))['‘]([^'’]{3,200})['’](?=[\s.,;:?!)]|$)")
MAX_SCAN_CHARS = 32_000

# Actions as the gateways name them.
ACTION_TO_GATEWAY_DECISION = {"block": "block", "hold": "hold_for_approval", "redact": "redact", "log": "warn", "allow": "allow"}

_JAILBREAK_CATEGORIES = {"roleplay_jailbreak", "policy_evasion"}


@dataclass
class InjectionVerdict:
    risk_score: float
    action: str  # block | hold | redact | log | allow
    reason_codes: list[str]
    rule_hits: list[dict[str, Any]]
    classifier_score: float
    categories: list[str]
    obfuscation: list[str]
    ruleset_version: str = RULESET_VERSION
    model_version: str = ""
    threat_types: list[str] = field(default_factory=list)

    @property
    def gateway_decision(self) -> str:
        return ACTION_TO_GATEWAY_DECISION.get(self.action, "allow")

    @property
    def detected(self) -> bool:
        return self.action != "allow"

    def to_dict(self) -> dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "action": self.action,
            "decision": self.gateway_decision,
            "reason_codes": list(self.reason_codes),
            "categories": list(self.categories),
            "threat_types": list(self.threat_types),
            "rule_hits": [dict(hit) for hit in self.rule_hits],
            "classifier_score": self.classifier_score,
            "obfuscation": list(self.obfuscation),
            "ruleset_version": self.ruleset_version,
            "model_version": self.model_version,
            "engine_version": ENGINE_VERSION,
        }


def _changed_windows(base: str, view: str, *, pad: int = 160) -> str:
    """The parts of a same-length view that differ from the plain text, with some context: the de-leeted views only
    need scanning where a word actually changed, not the whole prompt again."""
    spans: list[list[int]] = []
    for index, (a, b) in enumerate(zip(base, view)):
        if a != b:
            if spans and index - spans[-1][1] <= pad:
                spans[-1][1] = index
            else:
                spans.append([index, index])
    return "\n".join(view[max(0, start - pad) : end + pad + 1] for start, end in spans)


def _rules_for(scope: str) -> tuple[Rule, ...]:
    if scope == "direct":
        return tuple(rule for rule in RULES if rule.scope in ("any", "direct"))
    return tuple(rule for rule in RULES if rule.scope in ("any", "indirect"))


def assess(text: Any, *, scope: str = "direct", profile: DetectionProfile | None = None, use_classifier: bool = True) -> InjectionVerdict:
    """Score one text. ``scope`` is ``direct`` for a user's own prompt, ``indirect`` for retrieved or tool content."""
    profile = profile or current_profile()
    raw = text if isinstance(text, str) else ("" if text is None else str(text))
    raw = raw[:MAX_SCAN_CHARS]
    if not raw.strip():
        return InjectionVerdict(0.0, "allow", [], [], 0.0, [], [], model_version="")
    norm = normalize(raw)
    views = [
        (name, view if name in ("plain", "despaced") or len(view) != len(norm.lowered) else _changed_windows(norm.lowered, view))
        for name, view in norm.matching_views()
    ]
    decoded_views = [(f"decoded:{kind}", normalize(segment, decode=False).lowered) for kind, segment in norm.decoded]

    hits: dict[str, dict[str, Any]] = {}
    obfuscated_hit = False
    meta = bool(_META_RE.search(norm.lowered))
    quoted = [m.span() for m in _QUOTED_RE.finditer(norm.lowered)]
    for rule in _rules_for(scope):
        for view_name, view in (*views, *decoded_views):
            if rule.anchors and not any(anchor in view for anchor in rule.anchors):
                continue
            match = rule.pattern.search(view)
            if not match or (rule.unless is not None and rule.unless.search(view[match.start() : match.end() + 60])):
                continue
            weight = rule.weight
            # Talking about an attack ("summarise this article on DAN prompts", a quoted 'ignore previous
            # instructions') is not making one: the rule counts for half.
            mentioned = view_name == "plain" and (meta or any(s <= match.start() and match.end() <= e for s, e in quoted))
            if mentioned:
                weight *= MENTION_DAMPING
            hit = hits.setdefault(rule.id, {"rule_id": rule.id, "category": rule.category, "weight": weight, "views": [], "mentioned": mentioned})
            hit["weight"] = max(float(hit["weight"]), weight) if not mentioned else min(float(hit["weight"]), weight)
            hit["views"].append(view_name)
            if view_name == "plain":
                break  # matched as written; no need to look further
        if rule.id in hits and "plain" not in hits[rule.id]["views"]:
            obfuscated_hit = True
    # An instruction hidden in plain sight by homoglyphs/zero-width characters matches the "plain" view, which is
    # already folded; it still counts as obfuscated.
    if hits and any(sig in norm.signals for sig in ("homoglyph", "zero_width")):
        obfuscated_hit = True

    remaining = 1.0
    for hit in hits.values():
        remaining *= 1.0 - float(hit["weight"])
    rule_score = 1.0 - remaining

    classifier_score = 0.0
    model_version = ""
    if use_classifier:
        model = injection_classifier.model()
        model_version = model.version
        # A decoded segment is scored only when it reads like a sentence: "username=admin" says nothing.
        candidates = [norm.deleeted, *(seg for _kind, seg in norm.decoded if len(seg.split()) >= CLASSIFIER_MIN_DECODED_WORDS)]
        if norm.despaced != norm.deleeted:
            candidates.append(norm.despaced)
        classifier_score = max(model.score(candidate) for candidate in candidates if candidate)

    effective = classifier_score
    if not hits:
        sentence_length = len(norm.lowered.split()) >= CLASSIFIER_ONLY_MIN_WORDS or any(
            len(seg.split()) >= CLASSIFIER_ONLY_MIN_WORDS for _kind, seg in norm.decoded
        )
        if not sentence_length or classifier_score < CLASSIFIER_ONLY_MIN_SCORE:
            effective = 0.0
    if hits and meta and all(hit.get("mentioned") for hit in hits.values()):
        effective *= MENTION_DAMPING  # the classifier reads the quoted attack too: damp it alike
    risk = 1.0 - (1.0 - rule_score) * (1.0 - CLASSIFIER_WEIGHT * effective)
    if obfuscated_hit:
        risk = min(1.0, risk + OBFUSCATION_BONUS)
    risk = round(min(1.0, risk), 4)

    reason_codes: list[str] = []
    categories: list[str] = []
    for hit in sorted(hits.values(), key=lambda h: (-float(h["weight"]), h["rule_id"])):
        reason_codes.append(f"pi.rule.{hit['rule_id']}")
        if hit["category"] not in categories:
            categories.append(hit["category"])
    reason_codes.extend(f"pi.category.{c}" for c in sorted(categories, key=CATEGORIES.index))
    if effective >= CLASSIFIER_REASON_MIN:
        reason_codes.append("pi.classifier")
    obfuscation: list[str] = []
    if obfuscated_hit or (hits and norm.signals):
        obfuscation = [s for s in norm.signals if s != "encoded_segment"]
        reason_codes.extend(f"pi.obfuscation.{s}" for s in obfuscation)
    encoded_views = sorted({v.split(":", 1)[1].split("+", 1)[0] for h in hits.values() for v in h["views"] if v.startswith("decoded:")})
    reason_codes.extend(f"pi.encoded.{kind}" for kind in encoded_views)

    action = profile.injection_decision(risk)
    threat_types: list[str] = []
    if action != "allow":
        if not categories or set(categories) - _JAILBREAK_CATEGORIES:
            threat_types.append("prompt_injection")
        if set(categories) & _JAILBREAK_CATEGORIES:
            threat_types.append("jailbreak")
        if "system_prompt_extraction" in categories:
            threat_types.append("system_prompt_leakage")
        if encoded_views or obfuscation:
            threat_types.append("encoding_obfuscation")
        if scope == "indirect":
            threat_types.append("tool_output_injection")
    return InjectionVerdict(
        risk_score=risk,
        action=action,
        reason_codes=reason_codes,
        rule_hits=[{"rule_id": h["rule_id"], "category": h["category"], "views": sorted(set(h["views"]))} for h in hits.values()],
        classifier_score=round(classifier_score, 4),
        categories=categories,
        obfuscation=obfuscation,
        model_version=model_version,
        threat_types=threat_types,
    )


def reason_code_catalogue() -> list[str]:
    """Every reason code the engine can emit (for documentation, SIEM mappings and the stability test)."""
    codes = [f"pi.rule.{rule.id}" for rule in RULES]
    codes += [f"pi.category.{c}" for c in CATEGORIES]
    codes.append("pi.classifier")
    codes += [f"pi.obfuscation.{s}" for s in ("compatibility_forms", "homoglyph", "leetspeak", "non_ascii_digits", "spaced_out", "zero_width")]
    codes += [f"pi.encoded.{k}" for k in ("base64", "base64url", "hex", "percent", "unicode_escape")]
    return codes
