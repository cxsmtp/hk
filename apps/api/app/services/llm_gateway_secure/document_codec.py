"""Bounded text-only PDF/DOCX conversion for the authenticated LLM Gateway."""

from __future__ import annotations

import io
import hashlib
import json
import re
import zipfile
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Any

import fitz

DOCX_MIME = "application/vnd.openxmlformats-officedocument.wordprocessingml.document"
PDF_MIME = "application/pdf"
MAX_BLOCKS = 1000
MAX_CELLS = 5000
MAX_EXPANDED_BYTES = 30 * 1024 * 1024
MAX_ZIP_ENTRIES = 512
MAX_ZIP_RATIO = 100
_EMPTY_DOCX_THUMBNAIL_SHA256 = "96367138dc44ce09bf2c8f0f8e49348a1478d2c5c0af69bbc2bbc38b63cdcead"
_EMPTY_DOCX_CUSTOM_XML_HASHES = {
    "customxml/item1.xml": "a86086ffc5d8e83ebd6c71a55d1d2efaa31b137977f5f3a752366e1023612144",
    "customxml/_rels/item1.xml.rels": "1ca6c9a64edcebe24ee703a54403611b322d96da33371779e742d2d3f7ed7a6c",
    "customxml/itemprops1.xml": "c542307b13ec29a8b546217bb37936ab4822e044b265d2952985ec3d6afed24e",
}


class DocumentCodecError(ValueError):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class DocumentBlock:
    kind: str
    text: str = ""
    page: int = 0
    level: int = 0
    list_type: str = ""
    rows: tuple[tuple[str, ...], ...] = ()


@dataclass(frozen=True, slots=True)
class ParsedDocument:
    format: str
    blocks: tuple[DocumentBlock, ...]
    page_count: int | None = None


def safe_download_name(fmt: str) -> str:
    if fmt not in {"pdf", "docx"}:
        raise DocumentCodecError("unsupported_document_format")
    return f"reviewed-document.{fmt}"


def _check_text(text: Any, *, max_chars: int) -> str:
    if not isinstance(text, str) or len(text) > max_chars or "\x00" in text:
        raise DocumentCodecError("document_text_limit")
    return text


def _check_structure(blocks: tuple[DocumentBlock, ...], *, max_chars: int) -> None:
    if not blocks or len(blocks) > MAX_BLOCKS:
        raise DocumentCodecError("document_block_limit")
    cells = 0
    chars = 0
    for block in blocks:
        chars += len(block.text)
        cells += sum(len(row) for row in block.rows)
        chars += sum(len(cell) for row in block.rows for cell in row)
        if block.kind == "table":
            if not block.rows or len({len(row) for row in block.rows}) != 1 or not block.rows[0]:
                raise DocumentCodecError("document_table_shape")
        elif not block.text.strip():
            raise DocumentCodecError("document_empty_block")
    if cells > MAX_CELLS or chars > max_chars:
        raise DocumentCodecError("document_text_limit")


def _check_docx_archive(data: bytes) -> None:
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
        infos = archive.infolist()
        if not infos or len(infos) > MAX_ZIP_ENTRIES:
            raise DocumentCodecError("invalid_document_archive")
        expanded = 0
        names: set[str] = set()
        for info in infos:
            path = PurePosixPath(info.filename)
            name = info.filename.lower()
            if (
                info.filename.startswith("/")
                or "\\" in info.filename
                or ".." in path.parts
                or info.filename in names
                or (info.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise DocumentCodecError("unsafe_document_archive")
            names.add(info.filename)
            expanded += info.file_size
            if info.file_size > MAX_EXPANDED_BYTES or expanded > MAX_EXPANDED_BYTES:
                raise DocumentCodecError("document_expanded_limit")
            if info.file_size > MAX_ZIP_RATIO * max(1, info.compress_size):
                raise DocumentCodecError("document_compression_limit")
            if name == "docprops/thumbnail.jpeg":
                if hashlib.sha256(archive.read(info)).hexdigest() != _EMPTY_DOCX_THUMBNAIL_SHA256:
                    raise DocumentCodecError("unsupported_document_content")
                continue
            if name in _EMPTY_DOCX_CUSTOM_XML_HASHES:
                if hashlib.sha256(archive.read(info)).hexdigest() != _EMPTY_DOCX_CUSTOM_XML_HASHES[name]:
                    raise DocumentCodecError("unsupported_document_content")
                continue
            if any(part in name for part in (
                "vbaproject", "activex", "embeddings/", "media/", "charts/", "comments", "footnotes", "endnotes",
                "header", "footer", "customxml/", "people/", "webextensions/",
            )):
                raise DocumentCodecError("unsupported_document_content")
            if not (name.endswith(".xml") or name.endswith(".rels")) and name != "[content_types].xml":
                raise DocumentCodecError("unsupported_document_content")
        if "word/document.xml" not in names or "[Content_Types].xml" not in names:
            raise DocumentCodecError("invalid_document_archive")
        for name in names:
            if name.endswith(".xml") or name.endswith(".rels"):
                payload = archive.read(name)
                if b'TargetMode="External"' in payload or b"TargetMode='External'" in payload:
                    raise DocumentCodecError("unsupported_document_content")
                if any(tag in payload for tag in (
                    b"altChunk", b"txbxContent", b"<w:drawing", b"<w:pict", b"<w:object",
                    b"commentRange", b"commentReference",
                )) or re.search(rb"<w:(?:ins|del|moveFrom|moveTo|sdt)(?:\s|>)", payload):
                    raise DocumentCodecError("unsupported_document_content")
        archive.close()
    except DocumentCodecError:
        raise
    except (zipfile.BadZipFile, RuntimeError, OSError, ValueError):
        raise DocumentCodecError("invalid_document_archive") from None


def parse_document(
    data: bytes,
    *,
    file_name: str,
    mime_type: str,
    max_bytes: int = 10 * 1024 * 1024,
    max_pages: int = 100,
    max_chars: int = 60000,
) -> ParsedDocument:
    if not isinstance(data, bytes) or not data or len(data) > max_bytes:
        raise DocumentCodecError("document_size_limit")
    name = str(file_name or "").lower()
    mime = str(mime_type or "").lower().split(";", 1)[0].strip()
    if name.endswith(".pdf") and mime == PDF_MIME and data.startswith(b"%PDF-"):
        try:
            pdf = fitz.open(stream=data, filetype="pdf")
            if pdf.needs_pass:
                raise DocumentCodecError("encrypted_document")
            if not 1 <= len(pdf) <= max_pages:
                raise DocumentCodecError("document_page_limit")
            blocks: list[DocumentBlock] = []
            for page_number, page in enumerate(pdf):
                if page.get_images(full=True) or any(page.widgets() or ()) or any(page.annots() or ()):
                    raise DocumentCodecError("unsupported_document_content")
                for text_block in page.get_text("blocks", sort=True):
                    if len(text_block) < 7 or text_block[6] != 0:
                        continue
                    for line in str(text_block[4] or "").splitlines():
                        if line.strip():
                            blocks.append(DocumentBlock(kind="paragraph", text=_check_text(line.strip(), max_chars=max_chars), page=page_number))
                            if len(blocks) > MAX_BLOCKS or sum(len(block.text) for block in blocks) > max_chars:
                                raise DocumentCodecError("document_text_limit")
            result = ParsedDocument("pdf", tuple(blocks), len(pdf))
            _check_structure(result.blocks, max_chars=max_chars)
            pdf.close()
            return result
        except DocumentCodecError:
            raise
        except Exception:
            raise DocumentCodecError("invalid_pdf_document") from None
    if name.endswith(".docx") and mime == DOCX_MIME and data.startswith(b"PK\x03\x04"):
        _check_docx_archive(data)
        try:
            from docx import Document
            from docx.table import Table
            from docx.text.paragraph import Paragraph

            doc = Document(io.BytesIO(data))
            blocks = []
            for element in doc.element.body.iterchildren():
                if element.tag.endswith("}p"):
                    paragraph = Paragraph(element, doc)
                    text = paragraph.text.strip()
                    if not text:
                        continue
                    style = str(paragraph.style.name or "")
                    if style.startswith("Heading "):
                        match = re.fullmatch(r"Heading ([1-6])", style)
                        if not match:
                            raise DocumentCodecError("unsupported_document_content")
                        blocks.append(DocumentBlock("heading", _check_text(text, max_chars=max_chars), level=int(match.group(1))))
                    elif style.startswith("List Bullet"):
                        blocks.append(DocumentBlock("list", _check_text(text, max_chars=max_chars), list_type="bullet"))
                    elif style.startswith("List Number"):
                        blocks.append(DocumentBlock("list", _check_text(text, max_chars=max_chars), list_type="number"))
                    else:
                        blocks.append(DocumentBlock("paragraph", _check_text(text, max_chars=max_chars)))
                elif element.tag.endswith("}tbl"):
                    table = Table(element, doc)
                    rows = tuple(tuple(_check_text(cell.text, max_chars=max_chars) for cell in row.cells) for row in table.rows)
                    blocks.append(DocumentBlock("table", rows=rows))
                elif not element.tag.endswith("}sectPr"):
                    raise DocumentCodecError("unsupported_document_content")
            result = ParsedDocument("docx", tuple(blocks))
            _check_structure(result.blocks, max_chars=max_chars)
            return result
        except DocumentCodecError:
            raise
        except Exception:
            raise DocumentCodecError("invalid_docx_document") from None
    raise DocumentCodecError("unsupported_document_format")


def _block_record(block: DocumentBlock, index: int, nonce: str) -> dict[str, Any]:
    # Separate nonce digits so sensitive-number detection cannot rewrite protocol IDs.
    protected_nonce = "".join(f"x{char}" for char in nonce)
    record: dict[str, Any] = {"id": f"block-{protected_nonce}-{index:04d}", "kind": block.kind}
    if block.kind == "table":
        record["rows"] = [list(row) for row in block.rows]
    else:
        record["text"] = block.text
        if block.kind == "heading":
            record["level"] = block.level
        if block.kind == "list":
            record["list_type"] = block.list_type
    return record


def serialize_transform(parsed: ParsedDocument, *, instruction: str, nonce: str) -> tuple[str, tuple[dict[str, Any], ...]]:
    if not re.fullmatch(r"[0-9a-f]{24}", nonce):
        raise DocumentCodecError("invalid_document_protocol")
    expected = tuple(_block_record(block, index, nonce) for index, block in enumerate(parsed.blocks, 1))
    payload = {"mode": "transform", "instruction": instruction, "blocks": expected}
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")), expected


def _decode_response(value: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(value, str):
        if len(value) > 200000:
            raise DocumentCodecError("document_response_limit")
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            raise DocumentCodecError("invalid_document_response") from None
    if not isinstance(value, dict) or set(value) != {"blocks"} or not isinstance(value["blocks"], list):
        raise DocumentCodecError("invalid_document_response")
    return value


def _validated_block(record: Any, *, allow_id: bool, max_chars: int) -> DocumentBlock:
    if not isinstance(record, dict):
        raise DocumentCodecError("invalid_document_response")
    kind = record.get("kind")
    fields = {
        "paragraph": {"kind", "text"},
        "heading": {"kind", "text", "level"},
        "list": {"kind", "text", "list_type"},
        "table": {"kind", "rows"},
    }
    if kind not in fields or set(record) != fields[kind] | ({"id"} if allow_id else set()):
        raise DocumentCodecError("invalid_document_response")
    if kind == "table":
        rows = record["rows"]
        if not isinstance(rows, list) or not rows or len(rows) > MAX_BLOCKS:
            raise DocumentCodecError("document_table_shape")
        if not all(isinstance(row, list) and row and len(row) <= 100 for row in rows):
            raise DocumentCodecError("document_table_shape")
        return DocumentBlock("table", rows=tuple(tuple(_check_text(cell, max_chars=max_chars) for cell in row) for row in rows))
    text = _check_text(record["text"], max_chars=max_chars)
    if kind == "heading":
        level = record["level"]
        if isinstance(level, bool) or not isinstance(level, int) or level not in range(1, 7):
            raise DocumentCodecError("invalid_document_response")
        return DocumentBlock("heading", text=text, level=level)
    if kind == "list":
        if record["list_type"] not in {"bullet", "number"}:
            raise DocumentCodecError("invalid_document_response")
        return DocumentBlock("list", text=text, list_type=record["list_type"])
    return DocumentBlock("paragraph", text=text)


def validate_transform_response(value: str | dict[str, Any], *, expected: tuple[dict[str, Any], ...], max_chars: int = 60000) -> ParsedDocument:
    rows = _decode_response(value)["blocks"]
    if len(rows) != len(expected):
        raise DocumentCodecError("document_structure_changed")
    blocks = []
    for row, original in zip(rows, expected, strict=True):
        if not isinstance(row, dict) or row.get("id") != original["id"] or row.get("kind") != original["kind"]:
            raise DocumentCodecError("document_structure_changed")
        block = _validated_block(row, allow_id=True, max_chars=max_chars)
        if block.kind == "table":
            original_rows = original["rows"]
            if len(block.rows) != len(original_rows) or any(len(row) != len(source_row) for row, source_row in zip(block.rows, original_rows, strict=True)):
                raise DocumentCodecError("document_structure_changed")
        if block.kind == "heading" and block.level != original["level"]:
            raise DocumentCodecError("document_structure_changed")
        if block.kind == "list" and block.list_type != original["list_type"]:
            raise DocumentCodecError("document_structure_changed")
        blocks.append(block)
    result = ParsedDocument("structured", tuple(blocks))
    _check_structure(result.blocks, max_chars=max_chars)
    return result


def validate_transform_edits_response(
    value: str | dict[str, Any],
    *,
    expected: tuple[dict[str, Any], ...],
    max_chars: int = 60000,
) -> ParsedDocument:
    """Validate keyed edits and rebuild the immutable document structure.

    The provider receives block identifiers and structural constraints, then returns
    only replacement text or table cells.  The gateway owns the resulting block
    order and all non-editable metadata before sending it through the full strict
    transform validator.
    """
    if isinstance(value, str):
        if len(value) > 200000:
            raise DocumentCodecError("document_response_limit")
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, ValueError):
            raise DocumentCodecError("invalid_document_response") from None
    if not isinstance(value, dict) or set(value) != {"edits"} or not isinstance(value["edits"], list):
        raise DocumentCodecError("invalid_document_response")
    edits = value["edits"]
    if len(edits) != len(expected):
        raise DocumentCodecError("document_structure_changed")
    expected_by_id = {record["id"]: record for record in expected}
    if len(expected_by_id) != len(expected):
        raise DocumentCodecError("invalid_document_protocol")
    seen: set[str] = set()
    rebuilt_by_id: dict[str, dict[str, Any]] = {}
    for edit in edits:
        if not isinstance(edit, dict) or "id" not in edit:
            raise DocumentCodecError("invalid_document_response")
        identifier = edit["id"]
        if not isinstance(identifier, str) or not identifier:
            raise DocumentCodecError("invalid_document_response")
        if identifier not in expected_by_id:
            raise DocumentCodecError("document_structure_changed")
        if identifier in seen:
            raise DocumentCodecError("document_structure_changed")
        seen.add(identifier)
        original = expected_by_id[identifier]
        kind = original["kind"]
        if kind == "table":
            if set(edit) != {"id", "rows"} or not isinstance(edit["rows"], list):
                raise DocumentCodecError("invalid_document_response")
            rows = edit["rows"]
            original_rows = original["rows"]
            if len(rows) != len(original_rows) or any(
                not isinstance(row, list)
                or len(row) != len(source_row)
                for row, source_row in zip(rows, original_rows, strict=False)
            ):
                raise DocumentCodecError("document_structure_changed")
            rebuilt_by_id[identifier] = {
                "id": identifier,
                "kind": "table",
                "rows": [
                    [_check_text(cell, max_chars=max_chars) for cell in row]
                    for row in rows
                ],
            }
        else:
            if set(edit) != {"id", "text"}:
                raise DocumentCodecError("invalid_document_response")
            record = {"id": identifier, "kind": kind, "text": _check_text(edit["text"], max_chars=max_chars)}
            if kind == "heading":
                record["level"] = original["level"]
            elif kind == "list":
                record["list_type"] = original["list_type"]
            rebuilt_by_id[identifier] = record
    if seen != set(expected_by_id):
        raise DocumentCodecError("document_structure_changed")
    rebuilt = {"blocks": [rebuilt_by_id[record["id"]] for record in expected]}
    return validate_transform_response(rebuilt, expected=expected, max_chars=max_chars)


def validate_draft_response(value: str | dict[str, Any], *, max_chars: int = 60000) -> ParsedDocument:
    rows = _decode_response(value)["blocks"]
    if not 1 <= len(rows) <= MAX_BLOCKS:
        raise DocumentCodecError("document_block_limit")
    result = ParsedDocument("structured", tuple(_validated_block(row, allow_id=False, max_chars=max_chars) for row in rows))
    _check_structure(result.blocks, max_chars=max_chars)
    return result


def render_document(parsed: ParsedDocument, *, output_format: str, max_bytes: int = 10 * 1024 * 1024) -> bytes:
    if output_format == "docx":
        from docx import Document

        document = Document()
        for block in parsed.blocks:
            if block.kind == "heading":
                document.add_heading(block.text, level=block.level)
            elif block.kind == "list":
                document.add_paragraph(block.text, style="List Bullet" if block.list_type == "bullet" else "List Number")
            elif block.kind == "table":
                table = document.add_table(rows=len(block.rows), cols=len(block.rows[0]))
                for row_index, row in enumerate(block.rows):
                    for column_index, value in enumerate(row):
                        table.cell(row_index, column_index).text = value
            else:
                document.add_paragraph(block.text)
        out = io.BytesIO()
        document.save(out)
        data = out.getvalue()
    elif output_format == "pdf":
        pdf = fitz.open()
        page = pdf.new_page()
        y = 72.0
        width = page.rect.width - 144
        numbered_index = 0
        for block in parsed.blocks:
            if block.kind == "list" and block.list_type == "number":
                numbered_index += 1
            else:
                numbered_index = 0
            texts = ([" | ".join(row) for row in block.rows] if block.kind == "table" else [block.text])
            size = 16 if block.kind == "heading" else 11
            for text in texts:
                if any(ord(char) < 32 and char not in "\n\t" or ord(char) > 126 for char in text):
                    pdf.close()
                    raise DocumentCodecError("document_text_unrenderable")
                prefix = (
                    "- " if block.kind == "list" and block.list_type == "bullet"
                    else f"{numbered_index}. " if block.kind == "list" and block.list_type == "number"
                    else ""
                )
                words = (prefix + text).split()
                line = ""
                lines: list[str] = []
                for word in words:
                    while word:
                        next_line = f"{line} {word}".strip()
                        if fitz.get_text_length(next_line, fontname="helv", fontsize=size) <= width:
                            line = next_line
                            break
                        if line:
                            lines.append(line)
                            line = ""
                            continue
                        split_at = 1
                        while split_at < len(word) and fitz.get_text_length(word[:split_at + 1], fontname="helv", fontsize=size) <= width:
                            split_at += 1
                        lines.append(word[:split_at])
                        word = word[split_at:]
                if line:
                    lines.append(line)
                for rendered_line in lines:
                    if y > page.rect.height - 72:
                        page = pdf.new_page()
                        y = 72.0
                    page.insert_text((72, y), rendered_line, fontsize=size)
                    y += size * 1.45
                y += 8
        data = pdf.tobytes()
        pdf.close()
    else:
        raise DocumentCodecError("unsupported_document_format")
    if len(data) > max_bytes:
        raise DocumentCodecError("document_size_limit")
    return data
