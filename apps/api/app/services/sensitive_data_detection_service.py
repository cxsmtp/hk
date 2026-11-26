from __future__ import annotations

import base64
import importlib.util
import io
import os
import re
from typing import Any

from app.core.config import settings
from app.services.detection import dlp_engine
from app.services.detection.profile import REPORT_MIN_CONFIDENCE, DetectionProfile, current_profile


MAX_OCR_FILE_BYTES = 10 * 1024 * 1024

EMAIL_PATTERN = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
PHONE_PATTERN = re.compile(r"(?<!\d)(?:\+?\d[\d\-\s().]{7,}\d)(?!\d)")
ISO_DATETIME_PATTERN = re.compile(
    r"\b\d{4}-\d{2}-\d{2}"
    r"(?:[T ][0-2]\d:[0-5]\d(?::[0-5]\d(?:\.\d{1,6})?)?(?:Z|[+-][0-2]\d:?[0-5]\d)?)?\b"
)
CC_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
API_KEY_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|secret|private[_ -]?key|token)\b[\s:=]{0,3}[A-Za-z0-9_\-]{6,}"
)
LONG_SECRET_PATTERN = re.compile(r"\b(?:sk|pk|ghp|xoxb|xoxp|AIza)[A-Za-z0-9_\-]{10,}\b")
EMIRATES_ID_STRICT_PATTERN = re.compile(r"(?<!\d)784-?\d{4}-?\d{7}-?\d(?!\d)")
EMIRATES_ID_CONTEXT_PATTERN = re.compile(
    r"(?i)\b(?:emirates\s*id|uae\s*(?:id|national\s*id)|eid)\b[^\n\r]{0,24}\b\d{12,18}\b"
)
UAE_IBAN_PATTERN = re.compile(r"(?i)\bAE\d{2}(?:[ -]?\d){19}\b")
PASSPORT_LABEL_PATTERN = re.compile(r"(?i)\bpassport(?:\s+(?:number|no))?\s*[:#-]\s*([A-Z][A-Z0-9]{6,12})\b")
BANK_ACCOUNT_LABEL_PATTERN = re.compile(r"(?i)\b(?:bank\s+)?account(?:\s+(?:number|no))?\s*[:#-]\s*([0-9][0-9 -]{5,28}[0-9])\b")
BANK_ACCOUNT_TABLE_PATTERN = re.compile(r'(?i)"(?:bank\s+)?account(?:\s+(?:number|no))?"\s*,\s*"([0-9][0-9 -]{5,28}[0-9])"')
NAME_TABLE_PATTERN = re.compile(r'(?i)"(?:name|candidate|employee|customer|user)"\s*,\s*"([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,2})"')
PASSPORT_TABLE_PATTERN = re.compile(r'(?i)"passport(?:\s+(?:number|no))?"\s*,\s*"([A-Z][A-Z0-9]{6,12})"')
NAME_HINT_PATTERN = re.compile(
    r"(?i)\b(?:name|candidate|employee|customer|user)[ \t]*[:\-][ \t]*([A-Z][a-z]+(?:[ \t]+[A-Z][a-z]+){1,2})\b"
)
ADDRESS_PATTERN = re.compile(
    r"(?i)\b\d{1,5}\s+[A-Za-z0-9.\- ]+\s+(?:street|st|road|rd|avenue|ave|boulevard|blvd|lane|ln|drive|dr)\b"
)
ORG_PATTERN = re.compile(r"\b[A-Z][A-Za-z0-9&.\- ]{2,}\s+(?:Inc|LLC|Ltd|Corporation|Corp|Company)\b")

_PRESIDIO_ANALYZER: Any | None = None
_PRESIDIO_ATTEMPTED = False
_SPACY_NLP: Any | None = None
_SPACY_ATTEMPTED = False

_SENSITIVE_ENTITY_TYPES = {
    "email",
    "phone",
    "credit_card",
    "api_key",
    "emirates_id",
    "bank_account",
    "person",
    "address",
    "organization",
}
# Types the validated detectors (app/services/detection) add. Sensitive unless a tenant's profile says otherwise;
# ``ip_address`` is reported but not sensitive by default.
_VALIDATED_SENSITIVE_TYPES = {
    "iban",
    "us_ssn",
    "uk_nino",
    "passport",
    "private_key",
    "credential",
    "date_of_birth",
    "exact_data_match",
}
_NER_MODELS = ("en_core_web_lg", "en_core_web_md", "en_core_web_sm")


def _normalize_text(value: Any) -> str:
    if value is None:
        return ""
    text = str(value)
    return text.strip()


def _redact_preview(value: str, *, max_chars: int = 48) -> str:
    text = _normalize_text(value)
    if not text:
        return ""
    if len(text) <= 8:
        return "[redacted]"
    preview = text[: min(len(text), max_chars)]
    return f"{preview[:4]}...{preview[-4:]}"


def _digits_only(value: str) -> str:
    return "".join(char for char in value if char.isdigit())


def _luhn_valid(number: str) -> bool:
    digits = _digits_only(number)
    if len(digits) < 13 or len(digits) > 19:
        return False
    checksum = 0
    reverse_digits = digits[::-1]
    for index, char in enumerate(reverse_digits):
        digit = int(char)
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _entity_row(
    *,
    entity_type: str,
    value: str,
    confidence: float,
    source: str,
    context: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "entity_type": entity_type,
        "value_preview": _redact_preview(value),
        "confidence": round(max(0.0, min(1.0, float(confidence))), 4),
        "source": source,
        "context": dict(context or {}),
    }


def _regex_entities(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    phone_scan_text = ISO_DATETIME_PATTERN.sub(" ", text)
    for match in EMAIL_PATTERN.findall(text):
        rows.append(_entity_row(entity_type="email", value=match, confidence=0.95, source="regex"))
    for match in PHONE_PATTERN.findall(phone_scan_text):
        rows.append(_entity_row(entity_type="phone", value=match, confidence=0.85, source="regex"))
    for match in CC_PATTERN.findall(text):
        if _luhn_valid(match):
            rows.append(_entity_row(entity_type="credit_card", value=match, confidence=0.98, source="regex"))
    for match in API_KEY_PATTERN.findall(text):
        rows.append(_entity_row(entity_type="api_key", value=match, confidence=0.94, source="regex"))
    for match in LONG_SECRET_PATTERN.findall(text):
        rows.append(_entity_row(entity_type="api_key", value=match, confidence=0.92, source="regex"))
    for match in EMIRATES_ID_STRICT_PATTERN.findall(text):
        rows.append(_entity_row(entity_type="emirates_id", value=match, confidence=0.99, source="regex"))
    for match in EMIRATES_ID_CONTEXT_PATTERN.findall(text):
        rows.append(_entity_row(entity_type="emirates_id", value=match, confidence=0.96, source="regex"))
    for match in UAE_IBAN_PATTERN.findall(text):
        rows.append(_entity_row(entity_type="bank_account", value=match, confidence=0.95, source="regex"))
    for match in PASSPORT_LABEL_PATTERN.finditer(text):
        rows.append(_entity_row(entity_type="passport", value=match.group(1), confidence=0.96, source="regex"))
    for match in BANK_ACCOUNT_LABEL_PATTERN.finditer(text):
        rows.append(_entity_row(entity_type="bank_account", value=match.group(1), confidence=0.95, source="regex"))
    for match in BANK_ACCOUNT_TABLE_PATTERN.finditer(text):
        rows.append(_entity_row(entity_type="bank_account", value=match.group(1), confidence=0.95, source="regex"))
    for match in NAME_TABLE_PATTERN.finditer(text):
        rows.append(_entity_row(entity_type="person", value=match.group(1), confidence=0.76, source="regex"))
    for match in PASSPORT_TABLE_PATTERN.finditer(text):
        rows.append(_entity_row(entity_type="passport", value=match.group(1), confidence=0.96, source="regex"))
    for match in NAME_HINT_PATTERN.findall(text):
        rows.append(_entity_row(entity_type="person", value=match, confidence=0.76, source="regex"))
    for match in ADDRESS_PATTERN.findall(text):
        rows.append(_entity_row(entity_type="address", value=match, confidence=0.8, source="regex"))
    for match in ORG_PATTERN.findall(text):
        rows.append(_entity_row(entity_type="organization", value=match, confidence=0.78, source="regex"))
    return rows


def private_sensitive_spans(text: str) -> list[tuple[int, int, str]]:
    """Return private offsets for deterministic masking; never attach them to detection results."""
    candidates: list[tuple[int, int, str, int]] = []
    patterns = [
        (PASSPORT_LABEL_PATTERN, "passport", 0, 1),
        (BANK_ACCOUNT_LABEL_PATTERN, "bank_account", 0, 1),
        (BANK_ACCOUNT_TABLE_PATTERN, "bank_account", 0, 1),
        (PASSPORT_TABLE_PATTERN, "passport", 0, 1),
        (NAME_TABLE_PATTERN, "person", 0, 1),
        (NAME_HINT_PATTERN, "person", 0, 1),
        (UAE_IBAN_PATTERN, "bank_account", 1, 0),
        (EMIRATES_ID_STRICT_PATTERN, "emirates_id", 1, 0),
        (EMAIL_PATTERN, "email", 1, 0),
        (LONG_SECRET_PATTERN, "api_key", 1, 0),
        (API_KEY_PATTERN, "api_key", 2, 0),
        (CC_PATTERN, "credit_card", 3, 0),
        (PHONE_PATTERN, "phone", 4, 0),
    ]
    for pattern, kind, priority, group in patterns:
        for match in pattern.finditer(text):
            start, end = match.span(group)
            if start == end or (kind == "credit_card" and not _luhn_valid(match.group(group))):
                continue
            candidates.append((start, end, kind, priority))
    profile = current_profile()
    try:
        scan = dlp_engine.scan(text, profile=profile)
        for finding in scan.reportable():
            if finding.entity_type not in profile.sensitive_types:
                continue
            span = scan.original_span(finding)
            if span is None or span[0] >= span[1]:
                continue
            candidates.append((span[0], span[1], finding.entity_type, 5))
    except Exception:  # noqa: BLE001 - masking keeps the long-standing patterns if the engine fails
        pass
    candidates.sort(key=lambda row: (row[3], -(row[1] - row[0]), row[0]))
    selected: list[tuple[int, int, str]] = []
    for start, end, kind, _priority in candidates:
        if not any(start < other_end and end > other_start for other_start, other_end, _ in selected):
            selected.append((start, end, kind))
    return sorted(selected)


def _get_presidio_analyzer() -> Any | None:
    global _PRESIDIO_ANALYZER, _PRESIDIO_ATTEMPTED
    if _PRESIDIO_ATTEMPTED:
        return _PRESIDIO_ANALYZER
    _PRESIDIO_ATTEMPTED = True
    try:
        # Only a model already installed in the image: Presidio would otherwise try to download one, and nothing
        # here may reach the network.
        model = _installed_ner_model()
        if model is None:
            _PRESIDIO_ANALYZER = None
            return None
        from presidio_analyzer import AnalyzerEngine  # type: ignore

        if model == "en_core_web_lg":
            _PRESIDIO_ANALYZER = AnalyzerEngine()
        else:
            from presidio_analyzer.nlp_engine import NlpEngineProvider  # type: ignore

            provider = NlpEngineProvider(
                nlp_configuration={"nlp_engine_name": "spacy", "models": [{"lang_code": "en", "model_name": model}]}
            )
            _PRESIDIO_ANALYZER = AnalyzerEngine(nlp_engine=provider.create_engine(), supported_languages=["en"])
    except (Exception, SystemExit):
        _PRESIDIO_ANALYZER = None
    return _PRESIDIO_ANALYZER


def _installed_ner_model() -> str | None:
    preferred = str(os.environ.get("HAWK_NER_MODEL") or "").strip()
    for name in ((preferred,) if preferred else ()) + _NER_MODELS:
        try:
            if name and importlib.util.find_spec(name) is not None:
                return name
        except (ImportError, ValueError):
            continue
    return None


def ner_status() -> dict[str, Any]:
    """Whether the named-entity layer (people, places, organisations) can run, without loading a model."""
    model = _installed_ner_model()
    engines = {
        "presidio": importlib.util.find_spec("presidio_analyzer") is not None,
        "spacy": importlib.util.find_spec("spacy") is not None,
    }
    if model is None:
        reason = "no spaCy model is installed in this image; names, places and organisations fall back to patterns"
    elif not any(engines.values()):
        reason = "neither Presidio nor spaCy is installed"
    else:
        reason = "ready"
    return {
        "available": model is not None and any(engines.values()),
        "model": model,
        "engines": engines,
        "loaded": _PRESIDIO_ANALYZER is not None or _SPACY_NLP is not None,
        "degraded_to": None if model else "patterns",
        "reason": reason,
    }


def _presidio_entities(text: str) -> list[dict[str, Any]]:
    analyzer = _get_presidio_analyzer()
    if analyzer is None or not text:
        return []
    rows: list[dict[str, Any]] = []
    try:
        results = analyzer.analyze(text=text, language="en")
    except (Exception, SystemExit):
        return []
    label_map = {
        "PERSON": "person",
        "LOCATION": "address",
        "NRP": "address",
        "ORGANIZATION": "organization",
        "EMAIL_ADDRESS": "email",
        "PHONE_NUMBER": "phone",
        "CREDIT_CARD": "credit_card",
        "US_BANK_NUMBER": "api_key",
    }
    for result in results or []:
        raw_entity_type = str(getattr(result, "entity_type", "")).upper()
        entity_name = label_map.get(raw_entity_type)
        if not entity_name:
            continue
        start = int(getattr(result, "start", 0) or 0)
        end = int(getattr(result, "end", 0) or 0)
        snippet = text[start:end] if end > start else ""
        score = float(getattr(result, "score", 0.8) or 0.8)
        if raw_entity_type in {"LOCATION", "NRP"} and len(snippet.split()) == 1 and score < 0.9:
            continue
        rows.append(
            _entity_row(
                entity_type=entity_name,
                value=snippet or entity_name,
                confidence=score,
                source="presidio",
            )
        )
    return rows


def _get_spacy_model() -> Any | None:
    global _SPACY_NLP, _SPACY_ATTEMPTED
    if _SPACY_ATTEMPTED:
        return _SPACY_NLP
    _SPACY_ATTEMPTED = True
    try:
        import spacy  # type: ignore

        try:
            _SPACY_NLP = spacy.load(_installed_ner_model() or "en_core_web_sm")
        except Exception:
            _SPACY_NLP = None
    except Exception:
        _SPACY_NLP = None
    return _SPACY_NLP


def _spacy_entities(text: str) -> list[dict[str, Any]]:
    nlp = _get_spacy_model()
    if nlp is None or not text:
        return []
    try:
        doc = nlp(text)
    except Exception:
        return []

    mapping = {
        "PERSON": "person",
        "ORG": "organization",
        "GPE": "address",
        "LOC": "address",
        "FAC": "address",
    }
    rows: list[dict[str, Any]] = []
    for ent in getattr(doc, "ents", []):
        entity_type = mapping.get(str(getattr(ent, "label_", "")).upper())
        if not entity_type:
            continue
        confidence = float(getattr(ent, "kb_id_", 0.0) or 0.78)
        if confidence <= 0.0:
            confidence = 0.78
        rows.append(
            _entity_row(
                entity_type=entity_type,
                value=str(getattr(ent, "text", "") or entity_type),
                confidence=min(confidence, 0.88),
                source="spacy",
            )
        )
    return rows


def _decode_file_bytes(file_meta: dict[str, Any]) -> bytes | None:
    content_b64 = (
        file_meta.get("content_b64")
        or file_meta.get("content_base64")
        or file_meta.get("file_base64")
    )
    if isinstance(content_b64, str) and content_b64.strip():
        try:
            return base64.b64decode(content_b64.encode("utf-8"), validate=False)
        except Exception:
            return None

    raw = file_meta.get("bytes")
    if isinstance(raw, (bytes, bytearray)):
        return bytes(raw)
    if isinstance(raw, str) and raw:
        try:
            return raw.encode("utf-8")
        except Exception:
            return None

    file_path = (
        file_meta.get("path")
        or file_meta.get("file_path")
        or file_meta.get("local_path")
        or file_meta.get("tmp_path")
    )
    if isinstance(file_path, str) and file_path.strip() and os.path.exists(file_path):
        try:
            if os.path.getsize(file_path) > MAX_OCR_FILE_BYTES:
                return None
            with open(file_path, "rb") as handle:
                return handle.read()
        except Exception:
            return None
    return None


def _looks_like_pdf(file_meta: dict[str, Any]) -> bool:
    name = _normalize_text(file_meta.get("name")).lower()
    mime = _normalize_text(file_meta.get("mime_type") or file_meta.get("content_type")).lower()
    return name.endswith(".pdf") or "pdf" in mime


def _looks_like_image(file_meta: dict[str, Any]) -> bool:
    name = _normalize_text(file_meta.get("name")).lower()
    mime = _normalize_text(file_meta.get("mime_type") or file_meta.get("content_type")).lower()
    return (
        any(name.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".webp"))
        or mime.startswith("image/")
    )


def _extract_text_with_pdf_libs(file_bytes: bytes) -> str:
    try:
        import fitz  # type: ignore

        doc = fitz.open(stream=file_bytes, filetype="pdf")
        return "\n".join(page.get_text("text") for page in doc)
    except Exception:
        pass

    try:
        from pypdf import PdfReader  # type: ignore

        reader = PdfReader(io.BytesIO(file_bytes))
        return "\n".join(page.extract_text() or "" for page in reader.pages)
    except Exception:
        return ""


def _extract_text_with_tesseract(file_bytes: bytes) -> str:
    try:
        import cv2  # type: ignore
        import numpy as np  # type: ignore
        import pytesseract  # type: ignore

        arr = np.frombuffer(file_bytes, dtype=np.uint8)
        image = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if image is None:
            return ""
        gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
        denoised = cv2.GaussianBlur(gray, (3, 3), 0)
        normalized = cv2.threshold(denoised, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
        return str(pytesseract.image_to_string(normalized) or "")
    except Exception:
        pass

    try:
        from PIL import Image  # type: ignore
        import pytesseract  # type: ignore

        image = Image.open(io.BytesIO(file_bytes))
        return str(pytesseract.image_to_string(image) or "")
    except Exception:
        return ""


def extract_text_from_binary_for_ocr_task(
    *,
    file_name: str | None,
    mime_type: str | None,
    content_bytes: bytes,
) -> str:
    meta = {"name": file_name, "mime_type": mime_type}
    if _looks_like_pdf(meta):
        text = _extract_text_with_pdf_libs(content_bytes)
        if text.strip():
            return text
        return _extract_text_with_tesseract(content_bytes)
    if _looks_like_image(meta):
        return _extract_text_with_tesseract(content_bytes)
    return ""


def _extract_file_text(file_meta: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    if not isinstance(file_meta, dict):
        return "", {"error": "invalid_file_meta"}

    for field in ("ocr_text", "extracted_text", "text", "text_preview"):
        value = _normalize_text(file_meta.get(field))
        if value:
            return value, {"engine": "provided_metadata", "field": field}

    content = _decode_file_bytes(file_meta)
    if content is None:
        return "", {"error": "missing_file_content"}
    if len(content) > MAX_OCR_FILE_BYTES:
        return "", {"error": "file_too_large", "size": len(content)}

    # Async OCR for larger files when explicitly enabled.
    if (
        bool(getattr(settings, "sensitive_detection_async_ocr_enabled", False))
        and len(content) >= int(getattr(settings, "sensitive_detection_async_ocr_min_bytes", 400_000))
    ):
        try:
            from app.jobs.celery_app import celery_app

            task = celery_app.send_task(
                "app.jobs.enforcement_jobs.ocr_extract_text",
                kwargs={
                    "file_name": _normalize_text(file_meta.get("name")) or None,
                    "mime_type": _normalize_text(file_meta.get("mime_type") or file_meta.get("content_type")) or None,
                    "content_b64": base64.b64encode(content).decode("utf-8"),
                },
            )
            text = task.get(timeout=float(getattr(settings, "sensitive_detection_async_ocr_timeout_seconds", 2.0)))
            extracted = _normalize_text(text)
            if extracted:
                return extracted, {"engine": "celery_ocr", "async": True}
        except Exception:
            # Fall back to deterministic local OCR.
            pass

    extracted = extract_text_from_binary_for_ocr_task(
        file_name=_normalize_text(file_meta.get("name")) or None,
        mime_type=_normalize_text(file_meta.get("mime_type") or file_meta.get("content_type")) or None,
        content_bytes=content,
    )
    if extracted.strip():
        return extracted, {"engine": "local_ocr", "async": False}
    return "", {"error": "ocr_no_text"}


def _dedupe_entities(entities: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str]] = set()
    for row in entities:
        entity_type = _normalize_text(row.get("entity_type")).lower()
        value_preview = _normalize_text(row.get("value_preview")).lower()
        key = (entity_type, re.sub(r"[\s\-.\u200b]", "", value_preview))
        if not entity_type or not value_preview or key in seen:
            continue
        seen.add(key)
        out.append(row)
    return out


def _validated_entities(scan: dlp_engine.DLPScan) -> list[dict[str, Any]]:
    """Entity rows for the validated detectors' findings at or above the reporting confidence (no raw values)."""
    rows: list[dict[str, Any]] = []
    for finding in scan.reportable(REPORT_MIN_CONFIDENCE):
        if finding.encoded:
            value = finding.entity_type
        else:
            start, end = scan.normalized.original_span(finding.start, finding.end)
            value = scan.normalized.original[start:end] or finding.entity_type
        context: dict[str, Any] = {"detector": finding.detector, "reasons": list(finding.reasons)}
        if finding.subtype:
            context["subtype"] = finding.subtype
        if finding.context_hit:
            context["context_word"] = True
        if finding.encoded:
            context["encoded"] = finding.encoded
        rows.append(
            _entity_row(entity_type=finding.entity_type, value=value, confidence=finding.confidence, source="validated", context=context)
        )
    for hit in scan.edm_matches:
        rows.append(
            _entity_row(
                entity_type="exact_data_match",
                value=f"edm:{hit['set_id']}",
                confidence=0.99,
                source="exact_data_match",
                context={"set_id": hit["set_id"], "set_name": hit["name"], "category": hit["category"], "matches": hit["matches"]},
            )
        )
    return rows


def _score_entities(entities: list[dict[str, Any]], *, has_ocr: bool) -> float:
    if not entities:
        return 0.0
    confidence_values = [float(row.get("confidence") or 0.0) for row in entities]
    avg_conf = sum(confidence_values) / max(1, len(confidence_values))
    sensitive_weight = 0.15 if any(str(row.get("entity_type")) in _SENSITIVE_ENTITY_TYPES for row in entities) else 0.0
    ocr_bonus = 0.08 if has_ocr else 0.0
    volume_bonus = min(0.2, len(entities) * 0.03)
    return round(min(1.0, avg_conf + sensitive_weight + ocr_bonus + volume_bonus), 4)


def detect_sensitive_data(
    *,
    text_inputs: list[str] | None = None,
    file_meta: list[dict[str, Any]] | None = None,
    source: str | None = None,
    destination: str | None = None,
    ai_system_id: str | None = None,
    agent_id: str | None = None,
    user_id: str | None = None,
    correlation_id: str | None = None,
    profile: DetectionProfile | None = None,
) -> dict[str, Any]:
    profile = profile or current_profile()
    text_chunks = [_normalize_text(item) for item in (text_inputs or []) if _normalize_text(item)]
    ocr_details: list[dict[str, Any]] = []
    file_text_chunks: list[str] = []

    for entry in (file_meta or []):
        text, detail = _extract_file_text(entry if isinstance(entry, dict) else {})
        ocr_details.append(
            {
                "name": _normalize_text((entry or {}).get("name")) if isinstance(entry, dict) else "",
                **detail,
            }
        )
        normalized = _normalize_text(text)
        if normalized:
            file_text_chunks.append(normalized)

    bounded_chunks: list[str] = []
    remaining_chars = 60_000
    for chunk in [*text_chunks, *file_text_chunks]:
        if remaining_chars <= 0:
            break
        bounded = chunk[:remaining_chars]
        if bounded:
            bounded_chunks.append(bounded)
            remaining_chars -= len(bounded)

    combined = "\n".join(bounded_chunks).strip()
    entities: list[dict[str, Any]] = []
    # Inputs are separate trust/content fields. Scan them independently so a
    # trailing keyword in one field cannot consume a value from the next.
    categories: dict[str, dict[str, Any]] = {}
    obfuscation: set[str] = set()
    engine_error: str | None = None
    for chunk in bounded_chunks:
        entities.extend(_regex_entities(chunk))
        if profile.ner_enabled:
            entities.extend(_presidio_entities(chunk))
            entities.extend(_spacy_entities(chunk))
        try:
            scan = dlp_engine.scan(chunk, profile=profile)
        except Exception as exc:  # noqa: BLE001 - the long-standing patterns above still apply
            engine_error = type(exc).__name__
            continue
        entities.extend(_validated_entities(scan))
        for name, result in scan.detected_categories(profile).items():
            row = result.to_dict()
            if name not in categories or row["score"] > categories[name]["score"]:
                categories[name] = row
        obfuscation.update(scan.obfuscation)
    entities = _dedupe_entities(entities)
    entities = [row for row in entities if profile.enabled(str(row.get("entity_type")))]

    sensitive_types = _SENSITIVE_ENTITY_TYPES | (_VALIDATED_SENSITIVE_TYPES & profile.sensitive_types) | (
        {"ip_address"} & profile.sensitive_types
    )
    sensitive_categories = [
        name
        for name in categories
        if name in profile.sensitive_categories or name.startswith(("custom:", "edm:"))
    ]
    contains_sensitive = any(str(row.get("entity_type")) in sensitive_types for row in entities) or bool(sensitive_categories)
    confidence_score = _score_entities(entities, has_ocr=bool(file_text_chunks))
    if sensitive_categories:
        confidence_score = max(confidence_score, max(float(categories[name]["score"]) for name in sensitive_categories))

    return {
        "contains_sensitive": contains_sensitive,
        "entities": entities,
        "confidence_score": confidence_score,
        "extracted_text_preview_redacted": _redact_preview(combined, max_chars=160),
        "context": {
            "source": _normalize_text(source) or None,
            "destination": _normalize_text(destination) or None,
            "ai_system_id": _normalize_text(ai_system_id) or None,
            "agent_id": _normalize_text(agent_id) or None,
            "user_id": _normalize_text(user_id) or None,
            "correlation_id": _normalize_text(correlation_id) or None,
        },
        "ocr": {
            "files_processed": len(file_meta or []),
            "files_with_text": len(file_text_chunks),
            "details": ocr_details,
        },
        "document_categories": sorted(categories.values(), key=lambda row: (-float(row["score"]), str(row["category"]))),
        "sensitive_categories": sorted(sensitive_categories),
        "obfuscation": sorted(obfuscation),
        "detection": {
            **dlp_engine.versions(),
            "profile_revision": profile.revision,
            "ner_available": bool(_installed_ner_model()) and profile.ner_enabled,
            **({"engine_error": engine_error} if engine_error else {}),
        },
    }


def classify_data(
    *,
    detection_result: dict[str, Any],
    classification_hint: str | None = None,
    allow_unknown: bool = True,
) -> str:
    hint = _normalize_text(classification_hint).lower()
    if bool(detection_result.get("contains_sensitive")):
        return "protected"
    if hint in {"protected", "sensitive"}:
        return "protected"
    if hint in {"internal", "confidential"}:
        return "internal"
    if hint in {"public"}:
        return "public"
    return "unknown" if allow_unknown else "public"


def detection_signal_types(detection_result: dict[str, Any]) -> list[str]:
    if not detection_result:
        return []
    signals: set[str] = set()
    for entity in detection_result.get("entities") or []:
        entity_type = _normalize_text((entity or {}).get("entity_type")).lower()
        if entity_type:
            signals.add(f"sensitive_entity:{entity_type}")
    for category in detection_result.get("document_categories") or []:
        name = _normalize_text((category or {}).get("category")).lower()
        if name:
            signals.add(f"sensitive_category:{name}")
    if detection_result.get("contains_sensitive"):
        signals.add("sensitive_data_detected")
    if (detection_result.get("ocr") or {}).get("files_with_text"):
        signals.add("ocr_text_extracted")
    return sorted(signals)
