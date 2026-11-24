from __future__ import annotations

import base64

from app.services.sensitive_data_detection_service import (
    classify_data,
    detect_sensitive_data,
    extract_text_from_binary_for_ocr_task,
)


def test_regex_detection_identifies_sensitive_entities() -> None:
    result = detect_sensitive_data(
        text_inputs=[
            "Contact jane.doe@example.com or +1 (415) 555-0198",
            "Card 4242 4242 4242 4242 and api_key: sk-live-abcdef123456",
        ],
        source="browser",
        destination="chat.openai.com",
    )
    assert result["contains_sensitive"] is True
    entity_types = {row["entity_type"] for row in result["entities"]}
    assert "email" in entity_types
    assert "phone" in entity_types
    assert "credit_card" in entity_types
    assert "api_key" in entity_types
    assert float(result["confidence_score"]) > 0.5


def test_detection_does_not_classify_iso_timestamp_as_phone() -> None:
    result = detect_sensitive_data(
        text_inputs=[
            "Hawk realtime prompt visibility acceptance 2026-09-15T17:18:32.821Z. Reply telemetry-ok.",
        ],
        source="browser",
        destination="chatgpt.com",
    )

    entity_types = {row["entity_type"] for row in result["entities"]}
    assert "phone" not in entity_types
    assert result["contains_sensitive"] is False


def test_detection_uses_file_ocr_text_from_metadata() -> None:
    result = detect_sensitive_data(
        text_inputs=["clean text"],
        file_meta=[
            {"name": "upload-image.png", "ocr_text": "Primary contact: pii.user@corp.example"},
            {"name": "upload-doc.pdf", "ocr_text": "Phone +44 20 7946 0018"},
        ],
        source="browser",
        destination="mail.google.com",
    )
    assert result["contains_sensitive"] is True
    assert int(result["ocr"]["files_processed"]) == 2
    assert int(result["ocr"]["files_with_text"]) == 2
    assert classify_data(detection_result=result, classification_hint="unknown") == "protected"


def test_extract_text_from_binary_for_ocr_task_uses_pdf_extractors(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.sensitive_data_detection_service._extract_text_with_pdf_libs",
        lambda _: "PDF OCR text with user@example.com",
    )
    output = extract_text_from_binary_for_ocr_task(
        file_name="sample.pdf",
        mime_type="application/pdf",
        content_bytes=b"%PDF-1.4 fake",
    )
    assert "user@example.com" in output


def test_extract_text_from_binary_for_ocr_task_uses_image_ocr(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.sensitive_data_detection_service._extract_text_with_tesseract",
        lambda _: "Image OCR with 4242 4242 4242 4242",
    )
    output = extract_text_from_binary_for_ocr_task(
        file_name="sample.png",
        mime_type="image/png",
        content_bytes=b"\x89PNG\r\n\x1a\nfake",
    )
    assert "4242" in output


def test_detection_reads_base64_file_content_with_ocr(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.sensitive_data_detection_service.extract_text_from_binary_for_ocr_task",
        lambda **_: "OCR extracted api_key: sk-test-123456789",
    )
    encoded = base64.b64encode(b"fake image bytes").decode("utf-8")
    result = detect_sensitive_data(
        text_inputs=[],
        file_meta=[{"name": "capture.jpg", "content_b64": encoded, "mime_type": "image/jpeg"}],
        source="browser",
        destination="chatgpt.com",
    )
    assert result["contains_sensitive"] is True
    assert any(row["entity_type"] == "api_key" for row in result["entities"])


def test_detection_handles_empty_text_without_false_positive() -> None:
    result = detect_sensitive_data(text_inputs=["", "   "], file_meta=[], source="browser", destination="internal")
    assert result["contains_sensitive"] is False
    assert result["entities"] == []
    assert float(result["confidence_score"]) == 0.0


def test_detection_does_not_match_secrets_across_input_boundaries() -> None:
    result = detect_sensitive_data(
        text_inputs=["needs-approval-token", "guardian-engine-test"],
        file_meta=[],
        source="api",
        destination="external_api",
    )

    assert result["contains_sensitive"] is False
    assert result["entities"] == []


def test_detection_ignores_low_confidence_single_word_location_false_positive() -> None:
    result = detect_sensitive_data(
        text_inputs=[],
        file_meta=[{"name": "public-brief.png", "ocr_text": "Quarterly public roadmap summary"}],
        source="browser",
        destination="wiki.acme.ai",
    )

    assert result["contains_sensitive"] is False
    assert result["entities"] == []


def test_detection_handles_ocr_failure_gracefully(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.sensitive_data_detection_service.extract_text_from_binary_for_ocr_task",
        lambda **_: "",
    )
    encoded = base64.b64encode(b"broken image").decode("utf-8")
    result = detect_sensitive_data(
        text_inputs=[],
        file_meta=[{"name": "broken.png", "content_b64": encoded, "mime_type": "image/png"}],
        source="browser",
        destination="chat.openai.com",
    )
    assert result["contains_sensitive"] is False
    assert int(result["ocr"]["files_processed"]) == 1


def test_detection_identifies_emirates_id_and_uae_iban() -> None:
    result = detect_sensitive_data(
        text_inputs=[
            "my emirates id number 78256125675156",
            "salary account iban AE070331234567890123456",
        ],
        source="browser",
        destination="chatgpt.com",
    )
    assert result["contains_sensitive"] is True
    entity_types = {row["entity_type"] for row in result["entities"]}
    assert "emirates_id" in entity_types
    assert "bank_account" in entity_types
