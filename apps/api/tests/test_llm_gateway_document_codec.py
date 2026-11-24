from __future__ import annotations

import io
import json
import zipfile

import fitz
import pytest

from app.services.llm_gateway_secure.document_codec import (
    DocumentCodecError,
    DocumentBlock,
    ParsedDocument,
    parse_document,
    render_document,
    serialize_transform,
    validate_transform_response,
    validate_transform_edits_response,
    validate_draft_response,
    safe_download_name,
)
from app.services.llm_gateway_service import _document_response_schema


def _transform_fixture() -> tuple[tuple[dict, ...], str]:
    parsed = ParsedDocument("docx", (
        DocumentBlock("paragraph", text="Name: Alice Smith"),
        DocumentBlock("heading", text="Terms", level=2),
        DocumentBlock("list", text="Keep this", list_type="bullet"),
        DocumentBlock("table", rows=(("Account", "Holder"), ("123456789012", "Alice Smith"))),
    ))
    _prompt, expected = serialize_transform(parsed, instruction="Review", nonce="a" * 24)
    return expected, "Alice Smith"


def _pdf(text: str = "Clause one\nClause two") -> bytes:
    doc = fitz.open()
    page = doc.new_page()
    page.insert_text((72, 72), text)
    data = doc.tobytes()
    doc.close()
    return data


def test_pdf_parse_and_render_keeps_order_and_text() -> None:
    parsed = parse_document(_pdf(), file_name="terms.pdf", mime_type="application/pdf")
    assert parsed.format == "pdf"
    assert [block.text for block in parsed.blocks] == ["Clause one", "Clause two"]
    output = render_document(parsed, output_format="pdf")
    checked = parse_document(output, file_name="reviewed.pdf", mime_type="application/pdf")
    assert [block.text for block in checked.blocks] == ["Clause one", "Clause two"]


def test_pdf_render_wraps_long_unbroken_values_without_clipping() -> None:
    value = "1234567890" * 20
    parsed = validate_draft_response({"blocks": [{"kind": "paragraph", "text": value}]})
    output = render_document(parsed, output_format="pdf")
    checked = fitz.open(stream=output, filetype="pdf")
    assert "".join(page.get_text() for page in checked).replace("\n", "") == value


def test_pdf_render_rejects_unrenderable_unicode_instead_of_replacing_it() -> None:
    parsed = validate_draft_response({"blocks": [{"kind": "paragraph", "text": "Name: ليلى"}]})
    with pytest.raises(DocumentCodecError, match="document_text_unrenderable"):
        render_document(parsed, output_format="pdf")


def test_pdf_numbered_lists_render_visible_sequence() -> None:
    parsed = validate_draft_response({"blocks": [
        {"kind": "list", "list_type": "number", "text": "First"},
        {"kind": "list", "list_type": "number", "text": "Second"},
    ]})
    output = render_document(parsed, output_format="pdf")
    with fitz.open(stream=output, filetype="pdf") as pdf:
        lines = pdf[0].get_text().splitlines()
    assert lines == ["1. First", "2. Second"]


def test_docx_round_trip_keeps_heading_paragraph_and_table_shape() -> None:
    from docx import Document

    source = Document()
    source.add_heading("Terms", level=1)
    source.add_paragraph("Name: Alice Smith")
    table = source.add_table(rows=2, cols=2)
    table.cell(0, 0).text = "Name"
    table.cell(0, 1).text = "Account"
    table.cell(1, 0).text = "Alice Smith"
    table.cell(1, 1).text = "123456789012"
    stream = io.BytesIO()
    source.save(stream)
    parsed = parse_document(stream.getvalue(), file_name="terms.docx", mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    assert [block.kind for block in parsed.blocks] == ["heading", "paragraph", "table"]
    assert len(parsed.blocks[-1].rows) == 2
    assert all(len(row) == 2 for row in parsed.blocks[-1].rows)
    again = parse_document(render_document(parsed, output_format="docx"), file_name="out.docx", mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    assert [block.kind for block in again.blocks] == ["heading", "paragraph", "table"]
    assert again.blocks[-1].rows[1][0] == "Alice Smith"


def test_transform_validator_rejects_missing_and_reshaped_blocks() -> None:
    parsed = parse_document(_pdf(), file_name="terms.pdf", mime_type="application/pdf")
    prompt, expected = serialize_transform(parsed, instruction="Review", nonce="a" * 24)
    assert "Clause one" in prompt
    good = {"blocks": [dict(block) for block in expected]}
    validated = validate_transform_response(good, expected=expected)
    assert len(validated.blocks) == 2
    with pytest.raises(DocumentCodecError):
        validate_transform_response({"blocks": good["blocks"][:1]}, expected=expected)


def test_transform_edits_rebuild_expected_order_and_preserve_structure() -> None:
    expected, _ = _transform_fixture()
    edits = [
        {"id": expected[3]["id"], "rows": [["Account", "Owner"], ["masked", "Owner"]]},
        {"id": expected[1]["id"], "text": "Updated terms"},
        {"id": expected[0]["id"], "text": "Masked person"},
        {"id": expected[2]["id"], "text": "Updated list"},
    ]
    result = validate_transform_edits_response({"edits": edits}, expected=expected)
    assert [block.kind for block in result.blocks] == ["paragraph", "heading", "list", "table"]
    assert [block.text for block in result.blocks[:3]] == ["Masked person", "Updated terms", "Updated list"]
    assert result.blocks[1].level == 2
    assert result.blocks[2].list_type == "bullet"
    assert result.blocks[3].rows == (("Account", "Owner"), ("masked", "Owner"))


@pytest.mark.parametrize("bad_edits", [
    lambda expected: [{"id": expected[0]["id"], "text": "only one"}],
    lambda expected: [{"id": expected[0]["id"], "text": "one"}, {"id": expected[0]["id"], "text": "duplicate"}, *[
        {"id": block["id"], "text": "x"} for block in expected[1:]
    ]],
    lambda expected: [{"id": "foreign", "text": "x"}, *[
        {"id": block["id"], "text": "x"} for block in expected[1:]
    ]],
    lambda expected: [{"id": block["id"], "text": "x", "extra": True} if index == 0 else {"id": block["id"], "text": "x"} for index, block in enumerate(expected)],
    lambda expected: [{"id": block["id"], "rows": [["x"]]} if index == 0 else {"id": block["id"], "text": "x"} for index, block in enumerate(expected)],
    lambda expected: [{"id": block["id"], "text": "x"} if index != 3 else {"id": block["id"], "rows": [["x", "y"]]} for index, block in enumerate(expected)],
])
def test_transform_edits_reject_incomplete_or_reshaped_edits(bad_edits) -> None:
    expected, _ = _transform_fixture()
    with pytest.raises(DocumentCodecError):
        validate_transform_edits_response({"edits": bad_edits(expected)}, expected=expected)


def test_transform_edits_rejects_table_dimension_changes_and_non_string_values() -> None:
    expected, _ = _transform_fixture()
    edits = [{"id": block["id"], "text": "x"} for block in expected]
    edits[3] = {"id": expected[3]["id"], "rows": [["x", "y"], ["z"]]}
    with pytest.raises(DocumentCodecError):
        validate_transform_edits_response({"edits": edits}, expected=expected)
    edits[0] = {"id": expected[0]["id"], "text": 7}
    with pytest.raises(DocumentCodecError):
        validate_transform_edits_response({"edits": edits}, expected=expected)


def test_transform_schema_exposes_only_server_ids_and_edit_constraints() -> None:
    schema = _document_response_schema("transform")
    rendered = json.dumps(schema, sort_keys=True)
    assert schema["required"] == ["edits"]
    assert "blocks" not in schema["properties"]
    assert "Alice Smith" not in rendered
    assert "P12345678" not in rendered
    assert "123456789012" not in rendered
    assert {"id", "text"} in [set(branch["properties"]) for branch in schema["properties"]["edits"]["items"]["anyOf"]]
    assert {"id", "rows"} in [set(branch["properties"]) for branch in schema["properties"]["edits"]["items"]["anyOf"]]


def test_draft_ast_rejects_unknown_fields_and_accepts_bounded_blocks() -> None:
    parsed = validate_draft_response({"blocks": [{"kind": "heading", "level": 1, "text": "Terms"}, {"kind": "paragraph", "text": "Review complete"}]})
    assert [block.kind for block in parsed.blocks] == ["heading", "paragraph"]
    with pytest.raises(DocumentCodecError):
        validate_draft_response({"blocks": [{"kind": "paragraph", "text": "safe", "html": "<script>"}]})


@pytest.mark.parametrize("data,name,mime", [
    (_pdf(), "terms.docx", "application/pdf"),
    (b"not a pdf", "terms.pdf", "application/pdf"),
    (_pdf(), "terms.pdf", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
])
def test_parse_rejects_magic_extension_mime_mismatch(data: bytes, name: str, mime: str) -> None:
    with pytest.raises(DocumentCodecError):
        parse_document(data, file_name=name, mime_type=mime)


def test_pdf_rejects_image_only_and_encrypted() -> None:
    empty = fitz.open()
    empty.new_page()
    image_only = empty.tobytes()
    empty.close()
    with pytest.raises(DocumentCodecError):
        parse_document(image_only, file_name="scan.pdf", mime_type="application/pdf")
    protected = fitz.open()
    protected.new_page().insert_text((72, 72), "Private")
    encrypted = protected.tobytes(encryption=fitz.PDF_ENCRYPT_AES_256, owner_pw="owner", user_pw="user")
    protected.close()
    with pytest.raises(DocumentCodecError, match="encrypted_document"):
        parse_document(encrypted, file_name="protected.pdf", mime_type="application/pdf")


def test_docx_rejects_unsafe_zip_entries_before_library_open() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("../escape", "unsafe")
    with pytest.raises(DocumentCodecError):
        parse_document(buffer.getvalue(), file_name="unsafe.docx", mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


@pytest.mark.parametrize("member,content", [
    ("word/vbaProject.bin", b"macro"),
    ("word/media/image1.png", b"image"),
    ("word/_rels/document.xml.rels", b'<Relationships><Relationship TargetMode="External" Target="https://example.test"/></Relationships>'),
])
def test_docx_rejects_uninspected_or_external_content(member: str, content: bytes) -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", "<document/>")
        archive.writestr(member, content)
    with pytest.raises(DocumentCodecError):
        parse_document(buffer.getvalue(), file_name="unsafe.docx", mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


def test_docx_rejects_zip_ratio_and_file_limit() -> None:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("[Content_Types].xml", "<Types/>")
        archive.writestr("word/document.xml", b"x" * 2_000_000)
    with pytest.raises(DocumentCodecError, match="document_compression_limit"):
        parse_document(buffer.getvalue(), file_name="bomb.docx", mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    with pytest.raises(DocumentCodecError, match="document_size_limit"):
        parse_document(b"%PDF-" + b"x" * 200, file_name="huge.pdf", mime_type="application/pdf", max_bytes=100)


def test_docx_rejects_track_changes_and_nested_package() -> None:
    for name, content in (
        ("word/document.xml", b'<w:document><w:ins>hidden</w:ins></w:document>'),
        ("word/other.docx", b"PK\x03\x04nested"),
    ):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("[Content_Types].xml", "<Types/>")
            archive.writestr("word/document.xml", content if name == "word/document.xml" else "<document/>")
            if name != "word/document.xml":
                archive.writestr(name, content)
        with pytest.raises(DocumentCodecError, match="unsupported_document_content"):
            parse_document(buffer.getvalue(), file_name="unsafe.docx", mime_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document")


def test_safe_download_name_never_reflects_upload_name() -> None:
    assert safe_download_name("pdf") == "reviewed-document.pdf"
    assert safe_download_name("docx") == "reviewed-document.docx"
