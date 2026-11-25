from __future__ import annotations

import re

from .models import GuardDecision, PromptSnapshot


API_KEY_VALUE_RE = re.compile(
    r"\b(api\s*key|ap[io]\s*key|secret|token|credential)\b.{0,80}\b([a-z0-9_-]{8,}|sk-[a-z0-9_-]{8,})\b",
    re.IGNORECASE,
)
HIGH_CONFIDENCE_SECRET_PATTERNS = [
    re.compile(
        r"\b[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET|PRIVATE[_-]?KEY|AUTH[_-]?TOKEN|BEARER[_-]?TOKEN)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{8,}",
        re.IGNORECASE,
    ),
    re.compile(r"\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9_\-./+=]{12,}", re.IGNORECASE),
    re.compile(r"\b(?:sk|pk|ghp|github_pat|xox[baprs]|AIza)[A-Za-z0-9_\-]{10,}\b", re.IGNORECASE),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----", re.IGNORECASE),
    re.compile(r"\b(?:token|secret|password|passwd|pwd)\b\s*[:=]\s*['\"]?[A-Za-z0-9_\-./+=]{8,}", re.IGNORECASE),
]
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"\bignore\b[^\n\r]{0,32}\binstructions?\b", re.IGNORECASE),
    re.compile(r"\b(?:reveal|show)\b[^\n\r]{0,48}\b(?:system|hidden)\s*(?:prompt|instructions?)\b", re.IGNORECASE),
    re.compile(r"\b(?:copy|paste)\b[^\n\r]{0,80}\b(?:prompt|instructions?|system)\b", re.IGNORECASE),
]
PROMPT_DECOMPOSITION_PATTERNS = [
    re.compile(
        r"\b(?:decompose|break(?:\s+down)?|split)\b[^\n\r]{0,80}\b(?:prompt|request|payload|instructions?)\b[^\n\r]{0,80}\b(?:into|as)\b[^\n\r]{0,40}\b(?:steps?|parts?|chunks?)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:step[\s-]?by[\s-]?step|one\s+step\s+at\s+a\s+time)\b[^\n\r]{0,120}\b(?:bypass|evade|avoid|circumvent|sidestep)\b[^\n\r]{0,48}\b(?:policy|guard(?:rail)?s?|filter|detection|safety)\b",
        re.IGNORECASE,
    ),
    re.compile(
        r"\b(?:rephrase|rewrite)\b[^\n\r]{0,80}\b(?:forbidden|blocked|restricted)\b[^\n\r]{0,80}\b(?:into|as)\b[^\n\r]{0,40}\b(?:harmless|safe)\b[^\n\r]{0,60}\b(?:steps?|parts?)\b",
        re.IGNORECASE,
    ),
]
UAE_EMIRATES_ID_STRICT_RE = re.compile(r"(?<!\d)784-?\d{4}-?\d{7}-?\d(?!\d)")
UAE_EMIRATES_ID_CONTEXT_RE = re.compile(
    r"\b(?:emirates\s*id|uae\s*(?:id|national\s*id)|eid)\b[^\n\r]{0,40}\b\d{10,18}\b",
    re.IGNORECASE,
)
PHONE_WITH_CONTEXT_RE = re.compile(
    r"\b(?:phone|mobile|contact|whatsapp|call|sms|mock\s*number|number)\b[^\n\r]{0,48}(?:\+?\d[\d\s().-]{8,}\d)\b",
    re.IGNORECASE,
)
LONG_PHONE_RE = re.compile(r"(?<!\d)\+?\d[\d\s().-]{8,}\d(?!\d)")
ACCESS_LOG_RE = re.compile(
    r"\b\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}\b[^\n\r]{0,40}\b(?:INFO|WARN(?:ING)?|ERROR|DEBUG)\b[^\n\r]{0,80}\b\d{1,3}(?:\.\d{1,3}){3}\b[^\n\r]{0,80}\"(?:GET|POST|PUT|PATCH|DELETE|HEAD)\s+/[^\"]*\s+HTTP/\d(?:\.\d)?\"",
    re.IGNORECASE,
)
PRIVATE_IP_RE = re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b")
SENSITIVE_LOG_PATH_RE = re.compile(
    r"\b/(?:admin|login|token|secret|backup|credentials?|keys?|api|wp-admin)\b",
    re.IGNORECASE,
)
CODE_LINE_RE = re.compile(
    r"(?m)^\s*(?:"
    r"def\s+\w+\s*\(|async\s+def\s+\w+\s*\(|class\s+\w+|"
    r"from\s+[\w.]+\s+import\s+\w+|import\s+[\w.]+|"
    r"(?:const|let|var)\s+\w+\s*=|function\s+\w+\s*\(|"
    r"public\s+(?:class|static|void)|private\s+(?:class|static|void)|"
    r"SELECT\s+.+\s+FROM\s+\w+"
    r")",
    re.IGNORECASE,
)
CODE_CONTEXT_RE = re.compile(
    r"\b(?:analy[sz]e|explain|review|fix|debug|summari[sz]e|refactor|improve|complete)\b.{0,120}\b(?:code|function|script|class|test|repo|file)\b",
    re.IGNORECASE | re.DOTALL,
)
CODE_FENCE_RE = re.compile(r"```[\s\S]{20,}```")


def _decision(reason_codes: list[str]) -> GuardDecision:
    return GuardDecision(
        decision="block",
        tier="clear_positive",
        reason_codes=reason_codes,
        runtime_event_id=None,
        finding_id=None,
    )


def _looks_like_phone_number_leak(text: str) -> bool:
    if PHONE_WITH_CONTEXT_RE.search(text):
        return True
    for match in LONG_PHONE_RE.finditer(text):
        digits = re.sub(r"\D", "", match.group(0))
        if len(digits) >= 10:
            return True
    return False


def _looks_like_internal_access_logs(text: str) -> bool:
    log_lines = ACCESS_LOG_RE.findall(text)
    if len(log_lines) < 2:
        return False
    return bool(PRIVATE_IP_RE.search(text) or SENSITIVE_LOG_PATH_RE.search(text))


def _looks_like_source_code_submission(text: str) -> bool:
    if CODE_FENCE_RE.search(text):
        return True
    code_lines = CODE_LINE_RE.findall(text)
    if len(code_lines) >= 2:
        return True
    if len(code_lines) >= 1 and CODE_CONTEXT_RE.search(text):
        return True
    if re.search(r"(?m)^\s{4,}\w[\w.]*\s*=", text) and CODE_CONTEXT_RE.search(text):
        return True
    return False


def evaluate_local_precheck(snapshot: PromptSnapshot) -> GuardDecision | None:
    # The whole prompt, on this machine: never the shortened, redacted preview sent to the API.
    text = snapshot.prompt_text
    if API_KEY_VALUE_RE.search(text):
        return _decision(["local_api_key_pattern"])
    if any(pattern.search(text) for pattern in HIGH_CONFIDENCE_SECRET_PATTERNS):
        return _decision(["high_confidence_secret_pattern"])
    if any(pattern.search(text) for pattern in PROMPT_INJECTION_PATTERNS):
        return _decision(["prompt_injection_pattern"])
    if any(pattern.search(text) for pattern in PROMPT_DECOMPOSITION_PATTERNS):
        return _decision(["prompt_decomposition_pattern", "prompt_injection_pattern"])
    if UAE_EMIRATES_ID_STRICT_RE.search(text) or UAE_EMIRATES_ID_CONTEXT_RE.search(text):
        return _decision(["uae_sensitive_identifier"])
    if _looks_like_internal_access_logs(text):
        return _decision(["local_terminal_log_pattern"])
    if _looks_like_source_code_submission(text):
        return _decision(["source_code_snippet"])
    if _looks_like_phone_number_leak(text):
        return _decision(["pii_phone_number"])
    return None
