"""Reference catalog of AI notetakers and AI apps.

This is *reference data*, not an authoritative allow/deny list — the effective
policy always comes from the backend. Detection keys on process-name substrings
and well-known web domains (both reliable) plus audio-capture correlation, rather
than on exact bundle identifiers that vary by version and cannot be asserted with
confidence. Fleets extend ``bundle_ids`` / ``process_hints`` via backend policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re


class NotetakerCategory:
    MEETING_BOT = "meeting_bot"          # joins the call as a participant
    LOCAL_RECORDER = "local_recorder"    # captures system/laptop audio locally
    PLATFORM_NATIVE = "platform_native"  # built into the meeting platform


@dataclass(frozen=True)
class NotetakerSignature:
    id: str
    name: str
    vendor: str
    category: str
    process_hints: tuple[str, ...] = ()   # lowercased substrings of process/app name
    domains: tuple[str, ...] = ()         # SaaS domains (network egress / browser)
    bundle_ids: tuple[str, ...] = ()      # optional, fleet-extendable


# Well-known AI notetakers. process_hints/domains are matched case-insensitively
# as substrings; keep them specific enough to avoid collisions with unrelated apps.
NOTETAKER_CATALOG: tuple[NotetakerSignature, ...] = (
    NotetakerSignature("otter", "Otter.ai", "Otter", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("otter",), domains=("otter.ai",)),
    NotetakerSignature("fireflies", "Fireflies.ai", "Fireflies", NotetakerCategory.MEETING_BOT,
                       process_hints=("fireflies",), domains=("fireflies.ai",)),
    NotetakerSignature("fathom", "Fathom", "Fathom", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("fathom",), domains=("fathom.video",)),
    NotetakerSignature("granola", "Granola", "Granola", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("granola",), domains=("granola.ai",)),
    NotetakerSignature("jamie", "Jamie", "Jamie", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("jamie", "meetjamie"), domains=("meetjamie.ai",)),
    NotetakerSignature("plaud", "Plaud", "Plaud", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("plaud",), domains=("plaud.ai",)),
    NotetakerSignature("tactiq", "Tactiq", "Tactiq", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("tactiq",), domains=("tactiq.io",)),
    NotetakerSignature("read_ai", "Read.ai", "Read AI", NotetakerCategory.MEETING_BOT,
                       process_hints=("read.ai", "read ai"), domains=("read.ai",)),
    NotetakerSignature("avoma", "Avoma", "Avoma", NotetakerCategory.MEETING_BOT,
                       process_hints=("avoma",), domains=("avoma.com",)),
    NotetakerSignature("gong", "Gong", "Gong.io", NotetakerCategory.MEETING_BOT,
                       process_hints=("gong",), domains=("gong.io",)),
    NotetakerSignature("chorus", "Chorus", "ZoomInfo Chorus", NotetakerCategory.MEETING_BOT,
                       process_hints=("chorus",), domains=("chorus.ai",)),
    NotetakerSignature("tldv", "tl;dv", "tl;dv", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("tldv", "tl;dv"), domains=("tldv.io",)),
    NotetakerSignature("grain", "Grain", "Grain", NotetakerCategory.MEETING_BOT,
                       process_hints=("grain",), domains=("grain.com",)),
    NotetakerSignature("sembly", "Sembly AI", "Sembly", NotetakerCategory.MEETING_BOT,
                       process_hints=("sembly",), domains=("sembly.ai",)),
    NotetakerSignature("supernormal", "Supernormal", "Supernormal", NotetakerCategory.MEETING_BOT,
                       process_hints=("supernormal",), domains=("supernormal.com",)),
    NotetakerSignature("krisp", "Krisp", "Krisp", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("krisp",), domains=("krisp.ai",)),
    NotetakerSignature("notta", "Notta", "Notta", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("notta",), domains=("notta.ai",)),
    NotetakerSignature("rewind", "Rewind / Limitless", "Limitless", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("rewind", "limitless"), domains=("rewind.ai", "limitless.ai")),
    NotetakerSignature("meetgeek", "MeetGeek", "MeetGeek", NotetakerCategory.MEETING_BOT,
                       process_hints=("meetgeek",), domains=("meetgeek.ai",)),
    NotetakerSignature("circleback", "Circleback", "Circleback", NotetakerCategory.LOCAL_RECORDER,
                       process_hints=("circleback",), domains=("circleback.ai",)),
    NotetakerSignature("spinach", "Spinach", "Spinach.io", NotetakerCategory.MEETING_BOT,
                       process_hints=("spinach",), domains=("spinach.io",)),
    NotetakerSignature("zoom_ai", "Zoom AI Companion", "Zoom", NotetakerCategory.PLATFORM_NATIVE,
                       process_hints=(), domains=("zoom.us",)),
)

# Meeting apps whose presence contextualizes a notetaker (a recorder + an active
# meeting is higher-risk than a recorder alone).
MEETING_APP_HINTS: tuple[str, ...] = (
    "zoom", "zoom.us", "microsoft teams", "teams", "webex", "google meet", "meet.google", "slack call",
)

# Known AI apps/tools for endpoint shadow-AI discovery.
AI_APP_DOMAINS: dict[str, str] = {
    "chatgpt.com": "OpenAI ChatGPT",
    "chat.openai.com": "OpenAI ChatGPT",
    "claude.ai": "Anthropic Claude",
    "gemini.google.com": "Google Gemini",
    "copilot.microsoft.com": "Microsoft Copilot",
    "perplexity.ai": "Perplexity",
    "poe.com": "Poe",
    "grok.com": "xAI Grok",
    "x.ai": "xAI",
    "you.com": "You.com",
    "notebooklm.google.com": "Google NotebookLM",
    "huggingface.co": "Hugging Face",
    "midjourney.com": "Midjourney",
}


def _norm(value: str | None) -> str:
    return (value or "").strip().lower()


def process_hint_matches(value: str | None, hints: tuple[str, ...]) -> bool:
    """Match complete app-name tokens, never substrings inside renderer flags.

    Browser and desktop renderers expose feature names such as ``WebAssembly``
    and ``chorusIn3p`` in their command lines. Substring matching those values
    can misclassify the renderer as Sembly or Chorus and make a later process
    action target the browser itself.
    """
    normalized = _norm(value)
    if not normalized:
        return False
    return any(
        re.search(rf"(?<![a-z0-9]){re.escape(_norm(hint))}(?![a-z0-9])", normalized)
        for hint in hints
        if _norm(hint)
    )


def match_notetaker(*, process_name: str | None = None, domain: str | None = None) -> list[NotetakerSignature]:
    """Return catalog signatures matching a process name and/or domain."""
    pname = _norm(process_name)
    dom = _norm(domain)
    matches: list[NotetakerSignature] = []
    for sig in NOTETAKER_CATALOG:
        by_process = process_hint_matches(pname, sig.process_hints)
        by_domain = bool(dom) and any(dom == d or dom.endswith(f".{d}") for d in sig.domains)
        if by_process or by_domain:
            matches.append(sig)
    return matches


def is_meeting_context(process_names: list[str], domains: list[str]) -> bool:
    haystack = " ".join(_norm(x) for x in [*process_names, *domains])
    return any(hint in haystack for hint in MEETING_APP_HINTS)


def match_ai_app(domain: str | None) -> str | None:
    dom = _norm(domain)
    if not dom:
        return None
    for known, label in AI_APP_DOMAINS.items():
        if known in dom or dom.endswith(known):
            return label
    return None
