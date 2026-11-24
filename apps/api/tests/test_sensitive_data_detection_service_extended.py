from __future__ import annotations

import base64
import importlib.util
import sys
import types

import pytest

from app.services import sensitive_data_detection_service as sds


def _reset_nlp_globals() -> None:
    sds._PRESIDIO_ANALYZER = None
    sds._PRESIDIO_ATTEMPTED = False
    sds._SPACY_NLP = None
    sds._SPACY_ATTEMPTED = False


def test_private_helpers_and_regex_coverage() -> None:
    assert sds._normalize_text(None) == ""
    assert sds._normalize_text("  ok  ") == "ok"
    assert sds._redact_preview("short") == "[redacted]"
    assert sds._digits_only("+1 (415) 555-0198") == "14155550198"
    assert sds._luhn_valid("4242 4242 4242 4242") is True
    assert sds._luhn_valid("1234 5678 9012 3456") is False

    text = (
        "name: John Smith email john.smith@example.com "
        "address 10 Main Street "
        "Acme Corporation LLC "
        "api_key: sk-live-abcdef1234567890"
    )
    rows = sds._regex_entities(text)
    entity_types = {row["entity_type"] for row in rows}
    assert "email" in entity_types
    assert "person" in entity_types
    assert "address" in entity_types
    assert "organization" in entity_types
    assert "api_key" in entity_types


def test_presidio_entities_mapping_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Result:
        def __init__(self, entity_type: str, start: int, end: int, score: float) -> None:
            self.entity_type = entity_type
            self.start = start
            self.end = end
            self.score = score

    class _Analyzer:
        def analyze(self, text: str, language: str):  # type: ignore[no-untyped-def]
            del language
            return [
                _Result("PERSON", 0, 4, 0.9),
                _Result("EMAIL_ADDRESS", 5, len(text), 0.95),
                _Result("UNKNOWN", 0, 0, 0.1),
            ]

    monkeypatch.setattr(sds, "_get_presidio_analyzer", lambda: _Analyzer())
    rows = sds._presidio_entities("John john@example.com")
    assert {row["entity_type"] for row in rows} == {"person", "email"}

    class _BrokenAnalyzer:
        def analyze(self, text: str, language: str):  # type: ignore[no-untyped-def]
            del text, language
            raise RuntimeError("broken")

    monkeypatch.setattr(sds, "_get_presidio_analyzer", lambda: _BrokenAnalyzer())
    assert sds._presidio_entities("anything") == []


def test_presidio_model_bootstrap_system_exit_falls_back_to_regex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _reset_nlp_globals()
    fake_presidio = types.ModuleType("presidio_analyzer")

    class _AnalyzerEngine:
        def __init__(self) -> None:
            raise SystemExit(1)

    fake_presidio.AnalyzerEngine = _AnalyzerEngine  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "presidio_analyzer", fake_presidio)

    result = sds.detect_sensitive_data(text_inputs=["Contact demo@example.com"])

    assert result["contains_sensitive"] is True
    assert {row["source"] for row in result["entities"]} == {"regex"}
    assert sds._PRESIDIO_ATTEMPTED is True
    assert sds._PRESIDIO_ANALYZER is None


def test_missing_presidio_model_skips_analyzer_construction_and_uses_regex(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _reset_nlp_globals()
    fake_presidio = types.ModuleType("presidio_analyzer")
    constructed = False

    class _AnalyzerEngine:
        def __init__(self) -> None:
            nonlocal constructed
            constructed = True
            raise AssertionError("AnalyzerEngine must not be constructed without the packaged model")

    fake_presidio.AnalyzerEngine = _AnalyzerEngine  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "presidio_analyzer", fake_presidio)
    original_find_spec = importlib.util.find_spec
    monkeypatch.setattr(
        importlib.util,
        "find_spec",
        lambda name: None if name == "en_core_web_lg" else original_find_spec(name),
    )
    monkeypatch.setattr(sds, "_spacy_entities", lambda _text: [])

    result = sds.detect_sensitive_data(text_inputs=["Contact demo@example.com"])

    assert constructed is False
    assert sds._PRESIDIO_ATTEMPTED is True
    assert sds._PRESIDIO_ANALYZER is None
    assert any(row["entity_type"] == "email" and row["source"] == "regex" for row in result["entities"])


def test_presidio_analysis_system_exit_returns_no_optional_entities(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class _ExitAnalyzer:
        def analyze(self, text: str, language: str):  # type: ignore[no-untyped-def]
            del text, language
            raise SystemExit(1)

    monkeypatch.setattr(sds, "_get_presidio_analyzer", lambda: _ExitAnalyzer())

    assert sds._presidio_entities("Contact demo@example.com") == []


def test_spacy_entities_mapping_and_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Entity:
        def __init__(self, label_: str, text: str, kb_id_: float | str) -> None:
            self.label_ = label_
            self.text = text
            self.kb_id_ = kb_id_

    class _Doc:
        ents = [
            _Entity("PERSON", "Jane Roe", 0.0),
            _Entity("ORG", "Acme Corp", 1.2),
            _Entity("UNKNOWN", "skip", 0.1),
        ]

    monkeypatch.setattr(sds, "_get_spacy_model", lambda: (lambda _text: _Doc()))
    rows = sds._spacy_entities("Jane Roe from Acme Corp")
    assert {row["entity_type"] for row in rows} == {"person", "organization"}

    monkeypatch.setattr(sds, "_get_spacy_model", lambda: (lambda _text: (_ for _ in ()).throw(RuntimeError("fail"))))
    assert sds._spacy_entities("input") == []


def test_decode_file_bytes_variants_and_limits(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    encoded = base64.b64encode(b"hello").decode("utf-8")
    assert sds._decode_file_bytes({"content_b64": encoded}) == b"hello"
    assert sds._decode_file_bytes({"bytes": b"abc"}) == b"abc"
    assert sds._decode_file_bytes({"bytes": "abc"}) == b"abc"

    small = tmp_path / "small.txt"
    small.write_bytes(b"small")
    assert sds._decode_file_bytes({"path": str(small)}) == b"small"

    monkeypatch.setattr(sds, "MAX_OCR_FILE_BYTES", 3)
    assert sds._decode_file_bytes({"path": str(small)}) is None
    assert sds._decode_file_bytes({"content_b64": "%%%not-base64%%%"}) is None


def test_pdf_and_tesseract_extractors_with_fallbacks(monkeypatch: pytest.MonkeyPatch) -> None:
    fake_fitz = types.ModuleType("fitz")
    fake_fitz.open = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("fitz unavailable"))  # type: ignore[attr-defined]
    fake_pypdf = types.ModuleType("pypdf")

    class _FakePage:
        def extract_text(self) -> str:
            return "PDF text line"

    class _FakeReader:
        def __init__(self, _stream) -> None:
            self.pages = [_FakePage()]

    fake_pypdf.PdfReader = _FakeReader  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "fitz", fake_fitz)
    monkeypatch.setitem(sys.modules, "pypdf", fake_pypdf)
    assert "PDF text line" in sds._extract_text_with_pdf_libs(b"%PDF-1.4")

    fake_numpy = types.ModuleType("numpy")
    fake_numpy.uint8 = object()
    fake_numpy.frombuffer = lambda _buf, dtype=None: b"arr"  # type: ignore[attr-defined]

    fake_cv2 = types.ModuleType("cv2")
    fake_cv2.IMREAD_COLOR = 1  # type: ignore[attr-defined]
    fake_cv2.COLOR_BGR2GRAY = 2  # type: ignore[attr-defined]
    fake_cv2.THRESH_BINARY = 4  # type: ignore[attr-defined]
    fake_cv2.THRESH_OTSU = 8  # type: ignore[attr-defined]
    fake_cv2.imdecode = lambda _arr, _flag: "image"  # type: ignore[attr-defined]
    fake_cv2.cvtColor = lambda image, _mode: image  # type: ignore[attr-defined]
    fake_cv2.GaussianBlur = lambda image, _kernel, _sig: image  # type: ignore[attr-defined]
    fake_cv2.threshold = lambda image, _a, _b, _c: (0, image)  # type: ignore[attr-defined]

    fake_tesseract = types.ModuleType("pytesseract")
    fake_tesseract.image_to_string = lambda _img: "OCR from cv2 path"  # type: ignore[attr-defined]

    monkeypatch.setitem(sys.modules, "numpy", fake_numpy)
    monkeypatch.setitem(sys.modules, "cv2", fake_cv2)
    monkeypatch.setitem(sys.modules, "pytesseract", fake_tesseract)
    assert "OCR from cv2 path" in sds._extract_text_with_tesseract(b"img")

    fake_cv2_no_image = types.ModuleType("cv2")
    fake_cv2_no_image.IMREAD_COLOR = 1  # type: ignore[attr-defined]
    fake_cv2_no_image.imdecode = lambda _arr, _flag: None  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "cv2", fake_cv2_no_image)
    assert sds._extract_text_with_tesseract(b"img") == ""


def test_extract_file_text_async_ocr_and_local_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    _reset_nlp_globals()
    monkeypatch.setattr(sds.settings, "sensitive_detection_async_ocr_enabled", True, raising=False)
    monkeypatch.setattr(sds.settings, "sensitive_detection_async_ocr_min_bytes", 1, raising=False)
    monkeypatch.setattr(sds.settings, "sensitive_detection_async_ocr_timeout_seconds", 0.5, raising=False)

    class _Task:
        def get(self, timeout: float):  # type: ignore[no-untyped-def]
            del timeout
            return "Async OCR user@example.com"

    class _Celery:
        @staticmethod
        def send_task(*args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs
            return _Task()

    fake_celery_module = types.SimpleNamespace(celery_app=_Celery())
    monkeypatch.setitem(sys.modules, "app.jobs.celery_app", fake_celery_module)

    text, detail = sds._extract_file_text(
        {
            "name": "scan.png",
            "mime_type": "image/png",
            "bytes": b"binary-image-content",
        }
    )
    assert "user@example.com" in text
    assert detail["engine"] == "celery_ocr"
    assert detail["async"] is True

    class _BrokenCelery:
        @staticmethod
        def send_task(*args, **kwargs):  # type: ignore[no-untyped-def]
            del args, kwargs
            raise RuntimeError("queue unavailable")

    monkeypatch.setitem(sys.modules, "app.jobs.celery_app", types.SimpleNamespace(celery_app=_BrokenCelery()))
    monkeypatch.setattr(
        sds,
        "extract_text_from_binary_for_ocr_task",
        lambda **kwargs: "Local OCR fallback text",  # type: ignore[no-untyped-def]
    )
    text2, detail2 = sds._extract_file_text(
        {
            "name": "scan2.png",
            "mime_type": "image/png",
            "bytes": b"binary-image-content-2",
        }
    )
    assert text2 == "Local OCR fallback text"
    assert detail2["engine"] == "local_ocr"
    assert detail2["async"] is False


def test_extract_file_text_validation_errors() -> None:
    text, detail = sds._extract_file_text("invalid-meta")  # type: ignore[arg-type]
    assert text == ""
    assert detail["error"] == "invalid_file_meta"

    text2, detail2 = sds._extract_file_text({"name": "missing.bin"})
    assert text2 == ""
    assert detail2["error"] == "missing_file_content"


def test_detect_sensitive_data_truncation_classification_and_signal_types(monkeypatch: pytest.MonkeyPatch) -> None:
    _reset_nlp_globals()
    monkeypatch.setattr(sds, "_presidio_entities", lambda _text: [])
    monkeypatch.setattr(sds, "_spacy_entities", lambda _text: [])

    huge = "jane.doe@example.com " + ("A" * 61000)
    result = sds.detect_sensitive_data(
        text_inputs=[huge],
        file_meta=[{"name": "note.txt", "text": "Org: Acme Corporation LLC"}],
        source="browser",
        destination="ai_tool",
        ai_system_id="ai-1",
        agent_id="agent-1",
        user_id="user-1",
        correlation_id="corr-1",
    )
    assert result["contains_sensitive"] is True
    assert result["context"]["ai_system_id"] == "ai-1"
    assert result["ocr"]["files_processed"] == 1
    assert result["confidence_score"] > 0.0

    deduped = sds._dedupe_entities(
        [
            {"entity_type": "email", "value_preview": "john...com", "confidence": 0.9},
            {"entity_type": "email", "value_preview": "john...com", "confidence": 0.8},
            {"entity_type": "phone", "value_preview": "1234...1234", "confidence": 0.7},
        ]
    )
    assert len(deduped) == 2
    assert sds._score_entities([], has_ocr=False) == 0.0
    assert sds._score_entities(deduped, has_ocr=True) > 0.0

    assert sds.classify_data(detection_result={"contains_sensitive": False}, classification_hint="internal") == "internal"
    assert sds.classify_data(detection_result={"contains_sensitive": False}, classification_hint="public") == "public"
    assert sds.classify_data(detection_result={"contains_sensitive": False}, classification_hint=None, allow_unknown=False) == "public"
    assert sds.detection_signal_types({}) == []
    assert "sensitive_data_detected" in sds.detection_signal_types(result)
