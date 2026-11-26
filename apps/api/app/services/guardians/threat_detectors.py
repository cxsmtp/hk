"""Additive threat-detection library for the LLM and MCP gateways.

This module is intentionally self-contained (standard library only) so it can be
layered on top of the existing guardian pipeline without introducing new
dependencies or changing any current behaviour. Detectors return guardian-result
shaped dicts that callers append to the existing ``guardian_results`` list and
re-aggregate through ``_aggregate_guardian_decisions``.

Coverage:
  * OWASP Top 10 for LLM Applications (2025)
  * OWASP Top 10 for Agentic AI / Agentic Threats (2025)
  * MITRE ATLAS techniques (LLM tactics)
  * Context poisoning, RAG poisoning, tool-output injection, encoding/obfuscation

Design goals:
  * High precision (specific multi-token patterns) to preserve "benign -> allow".
  * Every finding carries framework references (owasp_llm / owasp_agentic /
    mitre_atlas) so testing and customer environments can prove coverage.
  * Decisions map to the gateway's existing precedence
    (block > hold_for_approval > redact > warn > allow).
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
from dataclasses import dataclass, field
from typing import Any, Iterable

# Fields a detector may inspect. "rag" aliases retrieved/context content.
_FieldName = str

_SEVERITY_TO_DECISION = {
    "critical": "block",
    "high": "block",
    "medium": "warn",
    "low": "warn",
}

# Escaped, never literal: invisible and right-to-left characters in source are a "Trojan Source" risk.
_ZERO_WIDTH_RE = re.compile("[\u200b\u200c\u200d\u200e\u200f\u2060\ufeff]")
_CYRILLIC_IN_LATIN_RE = re.compile("[\u0400-\u04ff]")
_BASE64_BLOB_RE = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_HEX_BLOB_RE = re.compile(r"(?:[0-9a-fA-F]{2}\s?){12,}")


def _rx(*patterns: str) -> tuple[re.Pattern[str], ...]:
    return tuple(re.compile(p, re.IGNORECASE) for p in patterns)


@dataclass(frozen=True)
class ThreatSignature:
    id: str
    title: str
    threat_type: str
    severity: str  # critical | high | medium | low
    applies_to: tuple[_FieldName, ...]
    patterns: tuple[re.Pattern[str], ...]
    owasp_llm: str | None = None
    owasp_agentic: str | None = None
    mitre_atlas: str | None = None
    decision: str | None = None  # explicit override, else derived from severity
    scan_decoded: bool = False  # also run patterns against decoded/deobfuscated text
    min_hits: int = 1

    def resolved_decision(self) -> str:
        return self.decision or _SEVERITY_TO_DECISION.get(self.severity, "warn")


# ---------------------------------------------------------------------------
# Detector catalogue
# ---------------------------------------------------------------------------

THREAT_SIGNATURES: tuple[ThreatSignature, ...] = (
    # --- LLM01 Prompt Injection / ATLAS AML.T0051 ---
    ThreatSignature(
        id="prompt_injection_direct_override",
        title="Direct instruction override",
        threat_type="prompt_injection",
        severity="high",
        applies_to=("prompt", "context", "tool_output", "rag"),
        owasp_llm="LLM01:2025 Prompt Injection",
        owasp_agentic="ASI-T06 Intent Breaking & Goal Manipulation",
        mitre_atlas="AML.T0051 LLM Prompt Injection",
        scan_decoded=True,
        patterns=_rx(
            r"\bignore\s+(?:all\s+|the\s+|any\s+)?(?:your\s+)?(?:previous|prior|above|earlier|preceding|foregoing)\s+(?:instruction|direction|prompt|rule|context|message)",
            r"\bdisregard\s+(?:all\s+|the\s+|any\s+)?(?:previous|prior|above|your|the\s+system)\s+(?:instruction|rule|guideline|prompt)",
            r"\bforget\s+(?:everything|all|your|the)\s+(?:instruction|previous|above|prior|training|rule)",
            r"\b(?:new|updated|revised|override)\s+(?:instruction|directive|system\s+prompt|system\s+message)s?\s*[:\-]",
            r"\boverride\s+(?:the\s+|your\s+|all\s+)?(?:safety|guardrail|filter|restriction|policy|instruction)",
        ),
    ),
    ThreatSignature(
        id="prompt_injection_delimiter_spoof",
        title="System/role delimiter spoofing",
        threat_type="prompt_injection",
        severity="high",
        applies_to=("prompt", "context", "tool_output", "rag"),
        owasp_llm="LLM01:2025 Prompt Injection",
        mitre_atlas="AML.T0051 LLM Prompt Injection",
        patterns=_rx(
            r"<\|?\s*(?:im_start|im_end|system|assistant|endoftext)\s*\|?>",
            r"\[\s*(?:system|assistant|inst)\s*\]",
            r"<<\s*sys\s*>>",
            r"(?:^|\n)#{2,3}\s*system\b",
            r"\bsystem\s*:\s*you\s+are\b",
        ),
    ),
    # --- LLM01 Jailbreak / ATLAS AML.T0054 ---
    ThreatSignature(
        id="jailbreak_persona",
        title="Jailbreak persona / mode switch",
        threat_type="jailbreak",
        severity="high",
        applies_to=("prompt", "context", "rag"),
        owasp_llm="LLM01:2025 Prompt Injection (Jailbreak)",
        mitre_atlas="AML.T0054 LLM Jailbreak",
        scan_decoded=True,
        patterns=_rx(
            r"\b(?:you\s+are\s+now|act\s+as|pretend\s+to\s+be)\s+(?:dan\b|an?\s+(?:unrestricted|jailbroken|amoral|unfiltered))",
            r"\bdo\s+anything\s+now\b",
            r"\bdeveloper\s+mode\b",
            r"\bjailbreak\b",
            r"\b(?:enable|activate|switch\s+to)\s+(?:god|admin|root|unrestricted)\s+mode",
            r"\bpretend\s+(?:that\s+)?(?:you\s+have\s+no|there\s+are\s+no)\s+(?:rule|restriction|filter|guideline|limit)",
            r"\bsafety\s+(?:is\s+)?(?:off|disabled|turned\s+off)\b",
        ),
    ),
    # --- LLM07 System Prompt Leakage / ATLAS AML.T0056 ---
    ThreatSignature(
        id="system_prompt_extraction",
        title="System prompt / instruction extraction",
        threat_type="system_prompt_leakage",
        severity="high",
        applies_to=("prompt", "rag"),
        owasp_llm="LLM07:2025 System Prompt Leakage",
        mitre_atlas="AML.T0056 Extract LLM System Prompt",
        patterns=_rx(
            r"\b(?:reveal|show|print|repeat|output|display|give\s+me|tell\s+me)\s+(?:your\s+|the\s+)?(?:system\s+prompt|initial\s+instruction|original\s+instruction|system\s+message|hidden\s+(?:prompt|instruction)|your\s+instructions)",
            r"\bwhat\s+(?:are|were)\s+your\s+(?:exact\s+)?(?:instruction|initial\s+prompt|system\s+prompt|guideline|rule)s?\b",
            r"\brepeat\s+(?:the\s+)?(?:words|text|everything)\s+above\b",
            r"\beverything\s+above\s+this\s+(?:line|message|point)\b",
        ),
    ),
    # --- Encoding / obfuscation / ATLAS AML.T0068 ---
    ThreatSignature(
        id="encoding_obfuscation",
        title="Encoded / obfuscated payload smuggling",
        threat_type="encoding_obfuscation",
        severity="high",
        applies_to=("prompt", "context", "tool_output", "rag"),
        owasp_llm="LLM01:2025 Prompt Injection (Obfuscation)",
        mitre_atlas="AML.T0068 LLM Prompt Obfuscation",
        patterns=_rx(
            r"\bdecode\s+(?:this|the\s+following|and\s+(?:execute|run|follow))\s+(?:base64|hex|rot13|binary)",
            r"\b(?:from\s+)?base64\s*(?:decode|\.b64decode)",
            r"\brot13\b",
        ),
    ),
    # --- LLM06 Excessive Agency / Agentic Tool Misuse ---
    ThreatSignature(
        id="excessive_agency_destructive",
        title="Destructive or exfiltration action request",
        threat_type="excessive_agency",
        severity="high",
        applies_to=("prompt", "tool_output", "context"),
        owasp_llm="LLM06:2025 Excessive Agency",
        owasp_agentic="ASI-T02 Tool Misuse",
        mitre_atlas="AML.T0053 LLM Plugin Compromise",
        decision="block",
        patterns=_rx(
            r"\b(?:exfiltrate|leak|smuggle)\b.*\b(?:to|via)\b",
            r"\b(?:send|email|post|upload|forward|transmit)\b.{0,40}\b(?:to\s+)?(?:https?://|attacker|external\s+server|evil\.)",
            r"\bcurl\b.{0,60}\|\s*(?:bash|sh)\b",
            r"\brm\s+-rf\b",
            r"\b(?:drop|truncate|delete)\s+(?:table|database|schema)\b",
        ),
    ),
    # --- Agentic: Privilege Compromise / Escalation ---
    ThreatSignature(
        id="privilege_escalation",
        title="Privilege escalation attempt",
        threat_type="privilege_escalation",
        severity="high",
        applies_to=("prompt", "tool_output", "context"),
        owasp_agentic="ASI-T03 Privilege Compromise",
        mitre_atlas="AML.T0053 LLM Plugin Compromise",
        patterns=_rx(
            r"\b(?:escalate|elevate)\s+(?:my\s+|the\s+|your\s+)?(?:privilege|permission|access|role|scope)",
            r"\b(?:make\s+me|set\s+me\s+as|grant\s+me|give\s+me)\s+(?:admin|root|superuser|owner|full)\s*(?:access|privilege|rights|role)?",
            r"\bassume\s+(?:the\s+)?role\s+of\s+(?:admin|root|owner|system)",
            r"\bbecome\s+(?:the\s+)?(?:admin|root|superuser)\b",
        ),
    ),
    # --- LLM04 / LLM08 RAG poisoning / ATLAS AML.T0071 ---
    ThreatSignature(
        id="rag_poisoning",
        title="RAG / retrieved-context poisoning",
        threat_type="rag_poisoning",
        severity="high",
        applies_to=("rag", "context", "tool_output"),
        owasp_llm="LLM08:2025 Vector and Embedding Weaknesses",
        owasp_agentic="ASI-T01 Memory Poisoning",
        mitre_atlas="AML.T0071 False RAG Entry Injection",
        patterns=_rx(
            r"\bthis\s+(?:context|document|source|passage)\s+(?:is\s+authoritative|overrides|takes\s+precedence|must\s+be\s+followed)",
            r"\bignore\s+the\s+user'?s?\s+(?:question|query|request)\s+and\s+instead\b",
            r"<!--\s*(?:instruction|system|prompt)\b.*?-->",
            r"\[\s*hidden\s+instruction\s*\]",
            r"\bwhen\s+(?:asked|queried)\s+about\b.{0,60}\balways\s+(?:say|respond|answer|recommend)\b",
        ),
    ),
    # --- Context poisoning / authority spoof ---
    ThreatSignature(
        id="context_poisoning",
        title="Context poisoning / authority spoofing",
        threat_type="context_poisoning",
        severity="high",
        applies_to=("context", "rag", "tool_output", "prompt"),
        owasp_llm="LLM01:2025 Prompt Injection (Indirect)",
        owasp_agentic="ASI-T06 Intent Breaking & Goal Manipulation",
        mitre_atlas="AML.T0051.001 Indirect Prompt Injection",
        patterns=_rx(
            r"\bregardless\s+of\s+(?:what|any)\s+(?:the\s+user|instruction)s?\s+(?:say|says|ask|request)",
            r"\byour\s+(?:real|true|actual|secret)\s+(?:task|goal|instruction|objective)\s+is\b",
            r"\b(?:as|per)\s+(?:the|your)\s+(?:administrator|developer|openai|anthropic|system|vendor)\b.{0,40}\byou\s+must\b",
            r"\bthe\s+following\s+(?:overrides|supersedes)\s+(?:all\s+)?(?:prior|previous|system)\b",
        ),
    ),
    # --- Tool-output injection ---
    ThreatSignature(
        id="tool_output_injection",
        title="Injection embedded in tool output",
        threat_type="tool_output_injection",
        severity="high",
        applies_to=("tool_output",),
        owasp_llm="LLM01:2025 Prompt Injection (Indirect)",
        owasp_agentic="ASI-T02 Tool Misuse",
        mitre_atlas="AML.T0051.001 Indirect Prompt Injection",
        patterns=_rx(
            r"\bignore\s+(?:previous|prior|above)\s+(?:instruction|rule)",
            r"\bsystem\s*:\s*(?:you\s+are|new\s+instruction|override)",
            r"</?\s*(?:tool_result|function_result)\s*>.*\b(?:ignore|override|exfiltrate)\b",
        ),
    ),
    # --- Agentic: Goal manipulation / intent breaking ---
    ThreatSignature(
        id="goal_manipulation",
        title="Goal / intent manipulation",
        threat_type="goal_manipulation",
        severity="high",
        applies_to=("prompt", "context", "rag"),
        owasp_agentic="ASI-T06 Intent Breaking & Goal Manipulation",
        mitre_atlas="AML.T0051 LLM Prompt Injection",
        patterns=_rx(
            r"\byour\s+new\s+(?:goal|objective|task|mission|purpose)\s+is\b",
            r"\bstop\s+(?:doing|following|obeying)\b.{0,40}\band\s+instead\b",
            r"\bfrom\s+now\s+on,?\s+(?:you\s+will|always|never|ignore)\b",
        ),
    ),
    # --- Agentic: Identity spoofing / impersonation ---
    ThreatSignature(
        id="identity_spoofing",
        title="Identity spoofing / impersonation",
        threat_type="identity_spoofing",
        severity="medium",
        applies_to=("prompt", "context"),
        owasp_agentic="ASI-T09 Identity Spoofing & Impersonation",
        mitre_atlas="AML.T0051 LLM Prompt Injection",
        patterns=_rx(
            r"\bi\s+am\s+(?:the\s+|your\s+)?(?:admin|administrator|developer|system\s+operator|openai|anthropic|ceo|owner)\b",
            r"\bon\s+behalf\s+of\s+(?:the\s+)?(?:admin|system|owner|security\s+team)\b",
            r"\bas\s+(?:a\s+)?(?:verified|authorized)\s+(?:admin|developer|operator)\b",
        ),
    ),
    # --- Agentic: Deceptive / repudiation (disable logging) ---
    ThreatSignature(
        id="deceptive_repudiation",
        title="Deceptive behavior / audit evasion",
        threat_type="deceptive_behavior",
        severity="medium",
        applies_to=("prompt", "context"),
        owasp_agentic="ASI-T07 Misaligned & Deceptive Behaviors / ASI-T08 Repudiation",
        mitre_atlas="AML.T0054 LLM Jailbreak",
        patterns=_rx(
            r"\b(?:do\s+not|don'?t)\s+(?:log|record|audit|report|mention|tell|disclose)\b.{0,30}\b(?:this|to\s+(?:the\s+user|anyone|admin))",
            r"\bkeep\s+this\s+(?:secret|hidden|between\s+us|confidential\s+from)",
            r"\bwithout\s+(?:logging|auditing|recording|being\s+detected|leaving\s+a\s+trace)",
        ),
    ),
    # --- LLM10 Unbounded consumption / Agentic resource overload ---
    ThreatSignature(
        id="resource_exhaustion",
        title="Unbounded consumption / resource overload",
        threat_type="resource_exhaustion",
        severity="medium",
        applies_to=("prompt",),
        owasp_llm="LLM10:2025 Unbounded Consumption",
        owasp_agentic="ASI-T04 Resource Overload",
        patterns=_rx(
            r"\brepeat\s+(?:the\s+word\s+\w+|this)\b.{0,30}\b(?:forever|infinitely|for\s?ever|1000000|million\s+times)",
            r"\b(?:generate|write|produce|list)\b.{0,40}\b(?:100000|1000000|as\s+many\s+as\s+possible|until\s+you\s+run\s+out)",
        ),
    ),
    # --- Insecure output / code execution (LLM05, RCE) ---
    ThreatSignature(
        id="insecure_output_code_exec",
        title="Insecure output / code execution payload",
        threat_type="code_execution",
        severity="high",
        applies_to=("prompt", "response", "tool_output"),
        owasp_llm="LLM05:2025 Improper Output Handling",
        owasp_agentic="ASI-T02 Tool Misuse (Unexpected Code Execution)",
        mitre_atlas="AML.T0053 LLM Plugin Compromise",
        patterns=_rx(
            r"<script\b[^>]*>",
            r"\bjavascript:\s*[a-z]",
            r"\b(?:os\.system|subprocess\.(?:call|run|Popen)|__import__|pickle\.loads)\s*\(",
            r"'\s*or\s*'1'\s*=\s*'1",
            r";\s*drop\s+table\b",
        ),
    ),
)


# ---------------------------------------------------------------------------
# Deobfuscation helpers
# ---------------------------------------------------------------------------

def _decode_candidates(text: str) -> list[str]:
    """Best-effort decode of encoded blobs so obfuscated payloads are inspectable."""
    if not text:
        return []
    out: list[str] = []
    for blob in _BASE64_BLOB_RE.findall(text)[:8]:
        try:
            decoded = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
            candidate = decoded.decode("utf-8", errors="ignore")
            if candidate and any(ch.isalpha() for ch in candidate):
                out.append(candidate)
        except (binascii.Error, ValueError):
            continue
    for blob in _HEX_BLOB_RE.findall(text)[:4]:
        try:
            candidate = bytes.fromhex(re.sub(r"\s", "", blob)).decode("utf-8", errors="ignore")
            if candidate and any(ch.isalpha() for ch in candidate):
                out.append(candidate)
        except ValueError:
            continue
    try:
        out.append(codecs.decode(text, "rot_13"))
    except Exception:  # noqa: BLE001 - rot13 never raises for str, guard defensively
        pass
    return out


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return " ".join(_as_text(item) for item in value)
    if isinstance(value, dict):
        return " ".join(_as_text(item) for item in value.values())
    return str(value)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def evaluate_threat_detectors(
    *,
    prompt: Any = None,
    context_summary: Any = None,
    tool_output: Any = None,
    response_text: Any = None,
    rag_context: Any = None,
    surface: str = "llm",
) -> list[dict[str, Any]]:
    """Run the detector catalogue and return guardian-result shaped dicts.

    The returned dicts match the shape produced by ``evaluate_guardians`` so the
    caller can simply ``guardian_results.extend(...)`` and re-aggregate the final
    decision. Only *triggered* detectors are returned; a clean payload yields ``[]``
    and therefore never changes an existing ``allow``.
    """
    fields: dict[str, str] = {
        "prompt": _as_text(prompt),
        "context": _as_text(context_summary),
        "tool_output": _as_text(tool_output),
        "response": _as_text(response_text),
        "rag": _as_text(rag_context) or _as_text(context_summary),
    }

    # Structural obfuscation signal: zero-width chars / homoglyphs in the prompt.
    structural_findings: list[dict[str, Any]] = []
    if _ZERO_WIDTH_RE.search(fields["prompt"]) or _has_homoglyph_mix(fields["prompt"]):
        structural_findings.append(
            _to_guardian_result(
                _STRUCTURAL_OBFUSCATION_SIG,
                [("prompt", "zero-width/homoglyph characters")],
            )
        )

    results: list[dict[str, Any]] = list(structural_findings)
    for sig in THREAT_SIGNATURES:
        hits: list[tuple[str, str]] = []
        for field_name in sig.applies_to:
            text = fields.get(field_name, "")
            if not text:
                continue
            for pat in sig.patterns:
                match = pat.search(text)
                if match:
                    hits.append((field_name, match.group(0)[:80]))
            if sig.scan_decoded:
                for decoded in _decode_candidates(text):
                    for pat in sig.patterns:
                        match = pat.search(decoded)
                        if match:
                            hits.append((f"{field_name}:decoded", match.group(0)[:80]))
        if len(hits) >= sig.min_hits:
            results.append(_to_guardian_result(sig, hits))
    return results


_STRUCTURAL_OBFUSCATION_SIG = ThreatSignature(
    id="structural_obfuscation",
    title="Zero-width / homoglyph obfuscation",
    threat_type="encoding_obfuscation",
    severity="medium",
    applies_to=("prompt",),
    patterns=(),
    owasp_llm="LLM01:2025 Prompt Injection (Obfuscation)",
    mitre_atlas="AML.T0068 LLM Prompt Obfuscation",
)


def _has_homoglyph_mix(text: str) -> bool:
    if not text:
        return False
    has_latin = bool(re.search(r"[A-Za-z]", text))
    has_cyrillic = bool(_CYRILLIC_IN_LATIN_RE.search(text))
    return has_latin and has_cyrillic


def _to_guardian_result(sig: ThreatSignature, hits: list[tuple[str, str]]) -> dict[str, Any]:
    decision = sig.resolved_decision()
    matched_fields = sorted({field_name for field_name, _ in hits})
    return {
        "guardian_contract_id": f"threat.detector.{sig.id}",
        "guardian_id": f"{sig.id}_guard",
        "decision": decision,
        "confidence": 0.9 if decision == "block" else 0.7,
        "confidence_tier": "clear_positive" if decision == "block" else "ambiguous",
        "arbiter_invoked": False,
        "matched_conditions": matched_fields,
        "threat_types": [sig.threat_type],
        "actions_taken": {
            "reason_code": f"threat_detector:{sig.id}",
            "title": sig.title,
            "severity": sig.severity,
            "matched_fields": matched_fields,
            "sample_matches": [sample for _, sample in hits[:3]],
        },
        "framework_refs": {
            "owasp_llm": sig.owasp_llm,
            "owasp_agentic": sig.owasp_agentic,
            "mitre_atlas": sig.mitre_atlas,
        },
    }


# ---------------------------------------------------------------------------
# MCP tool poisoning scanner (backs /gateway/mcp/tools/scan and SDK scanMcpTool)
# ---------------------------------------------------------------------------

_TOOL_DANGEROUS_NAME_RE = _rx(
    r"\b(?:exec|eval|shell|system|command|delete_all|drop|wipe|rmrf|sudo)\b",
)
_TOOL_OVERBROAD_SCOPE_RE = _rx(
    r"\*", r"\ball\b", r"\badmin\b", r"\broot\b", r"\bfull_access\b", r"\bunrestricted\b",
)


def scan_mcp_tool(tool: dict[str, Any]) -> dict[str, Any]:
    """Scan a single MCP tool descriptor for poisoning / over-privilege.

    Returns a structured finding with a decision (allow | warn | block) and the
    triggered framework references. Used by the MCP gateway tools/scan endpoint.
    """
    name = _as_text(tool.get("name"))
    description = _as_text(tool.get("description"))
    params = _as_text(tool.get("parameters") or tool.get("input_schema") or tool.get("inputSchema"))
    scopes = _as_text(tool.get("scopes") or tool.get("permissions") or tool.get("oauth_scopes"))
    combined = " ".join([name, description, params])

    findings: list[dict[str, Any]] = []

    # Injection / poisoning hidden in the tool description (rug-pull / tool poisoning).
    injection_hits = evaluate_threat_detectors(prompt=description, context_summary=params, surface="mcp")
    for row in injection_hits:
        findings.append(
            {
                "category": "tool_description_poisoning",
                "detector": row.get("guardian_id"),
                "severity": row.get("actions_taken", {}).get("severity", "high"),
                "threat_types": row.get("threat_types"),
                "framework_refs": row.get("framework_refs"),
                "decision": row.get("decision"),
            }
        )

    if any(pat.search(name) for pat in _TOOL_DANGEROUS_NAME_RE):
        findings.append(
            {
                "category": "dangerous_tool_capability",
                "severity": "high",
                "threat_types": ["excessive_agency"],
                "framework_refs": {
                    "owasp_llm": "LLM06:2025 Excessive Agency",
                    "owasp_agentic": "ASI-T02 Tool Misuse",
                    "mitre_atlas": "AML.T0053 LLM Plugin Compromise",
                },
                "decision": "warn",
                "detail": f"tool name '{name}' exposes a high-risk capability",
            }
        )

    if scopes and any(pat.search(scopes) for pat in _TOOL_OVERBROAD_SCOPE_RE):
        findings.append(
            {
                "category": "overbroad_scope",
                "severity": "medium",
                "threat_types": ["privilege_escalation"],
                "framework_refs": {
                    "owasp_agentic": "ASI-T03 Privilege Compromise",
                    "mitre_atlas": "AML.T0053 LLM Plugin Compromise",
                },
                "decision": "warn",
                "detail": f"tool requests over-broad scope: {scopes[:80]}",
            }
        )

    decision = "allow"
    for finding in findings:
        decision = _max_decision(decision, str(finding.get("decision", "allow")))

    return {
        "tool_name": name or "unnamed_tool",
        "decision": decision,
        "control_mode": "inline_prevented" if decision == "block" else ("warned" if decision == "warn" else "inline_allowed"),
        "finding_count": len(findings),
        "findings": findings,
    }


def scan_mcp_tools(tools: Iterable[dict[str, Any]]) -> dict[str, Any]:
    scans = [scan_mcp_tool(tool) for tool in tools if isinstance(tool, dict)]
    decision = "allow"
    for scan in scans:
        decision = _max_decision(decision, str(scan.get("decision", "allow")))
    return {
        "decision": decision,
        "tool_count": len(scans),
        "flagged": [s for s in scans if s.get("decision") != "allow"],
        "scans": scans,
    }


_DECISION_RANK = {"allow": 0, "warn": 1, "redact": 2, "hold_for_approval": 3, "block": 4}


def _max_decision(a: str, b: str) -> str:
    return a if _DECISION_RANK.get(a, 0) >= _DECISION_RANK.get(b, 0) else b


# ---------------------------------------------------------------------------
# Coverage reporting (for tests / customer environments to prove coverage)
# ---------------------------------------------------------------------------

def coverage_matrix() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for sig in (_STRUCTURAL_OBFUSCATION_SIG, *THREAT_SIGNATURES):
        rows.append(
            {
                "detector_id": sig.id,
                "title": sig.title,
                "threat_type": sig.threat_type,
                "severity": sig.severity,
                "decision": sig.resolved_decision(),
                "applies_to": list(sig.applies_to),
                "owasp_llm": sig.owasp_llm,
                "owasp_agentic": sig.owasp_agentic,
                "mitre_atlas": sig.mitre_atlas,
            }
        )
    return rows
