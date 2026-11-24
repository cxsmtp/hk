from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable


LETTER_WIDTH = 612.0
LETTER_HEIGHT = 792.0


def _escape_text(value: str) -> str:
    cleaned = "".join(ch if 32 <= ord(ch) <= 126 else "?" for ch in str(value or ""))
    return cleaned.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _clip(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def _color_ops(rgb: tuple[float, float, float], *, stroke: bool) -> str:
    op = "RG" if stroke else "rg"
    return f"{_clip(rgb[0]):.3f} {_clip(rgb[1]):.3f} {_clip(rgb[2]):.3f} {op}"


def _wrap_text(text: str, *, max_width: float, font_size: float) -> list[str]:
    normalized = " ".join(str(text or "").split())
    if not normalized:
        return [""]
    max_chars = max(8, int(max_width / max(font_size * 0.52, 1.0)))
    words = normalized.split(" ")
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = word if not current else f"{current} {word}"
        if len(candidate) <= max_chars:
            current = candidate
            continue
        if current:
            lines.append(current)
        while len(word) > max_chars:
            lines.append(word[:max_chars])
            word = word[max_chars:]
        current = word
    if current:
        lines.append(current)
    return lines or [normalized[:max_chars]]


@dataclass
class PdfPage:
    width: float = LETTER_WIDTH
    height: float = LETTER_HEIGHT
    operations: list[str] = field(default_factory=list)

    def add_text(
        self,
        text: str,
        *,
        x: float,
        y: float,
        font_size: float = 12,
        color: tuple[float, float, float] = (0.12, 0.14, 0.19),
    ) -> None:
        safe = _escape_text(text)
        self.operations.append(
            f"BT /F1 {font_size:.2f} Tf {_color_ops(color, stroke=False)} 1 0 0 1 {x:.2f} {y:.2f} Tm ({safe}) Tj ET"
        )

    def add_wrapped_text(
        self,
        text: str,
        *,
        x: float,
        y: float,
        max_width: float,
        font_size: float = 12,
        leading: float | None = None,
        color: tuple[float, float, float] = (0.12, 0.14, 0.19),
        max_lines: int | None = None,
    ) -> float:
        lines = _wrap_text(text, max_width=max_width, font_size=font_size)
        if max_lines is not None:
            lines = lines[:max_lines]
        line_gap = leading or (font_size * 1.35)
        cursor = y
        for line in lines:
            self.add_text(line, x=x, y=cursor, font_size=font_size, color=color)
            cursor -= line_gap
        return cursor

    def add_rect(
        self,
        *,
        x: float,
        y: float,
        width: float,
        height: float,
        fill: tuple[float, float, float] | None = None,
        stroke: tuple[float, float, float] | None = None,
        line_width: float = 1.0,
    ) -> None:
        ops: list[str] = [f"{line_width:.2f} w"]
        if fill is not None:
            ops.append(_color_ops(fill, stroke=False))
        if stroke is not None:
            ops.append(_color_ops(stroke, stroke=True))
        paint = "B" if fill is not None and stroke is not None else "f" if fill is not None else "S"
        ops.append(f"{x:.2f} {y:.2f} {width:.2f} {height:.2f} re {paint}")
        self.operations.append("\n".join(ops))

    def add_line(
        self,
        *,
        x1: float,
        y1: float,
        x2: float,
        y2: float,
        color: tuple[float, float, float] = (0.75, 0.78, 0.86),
        line_width: float = 1.0,
    ) -> None:
        self.operations.append(
            "\n".join(
                [
                    f"{line_width:.2f} w",
                    _color_ops(color, stroke=True),
                    f"{x1:.2f} {y1:.2f} m",
                    f"{x2:.2f} {y2:.2f} l",
                    "S",
                ]
            )
        )


class SimplePdfDocument:
    def __init__(self, *, title: str = "Hawk AI Report") -> None:
        self.title = title
        self.pages: list[PdfPage] = []

    def new_page(self) -> PdfPage:
        page = PdfPage()
        self.pages.append(page)
        return page

    def _build_objects(self) -> list[tuple[int, bytes]]:
        objects: list[tuple[int, bytes]] = []
        objects.append((1, b"<< /Type /Catalog /Pages 2 0 R >>"))
        objects.append((3, b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>"))

        page_refs: list[int] = []
        next_object_id = 4
        page_objects: list[tuple[int, bytes]] = []

        for page in self.pages:
            content_id = next_object_id
            page_id = next_object_id + 1
            next_object_id += 2
            page_refs.append(page_id)

            stream_text = "\n".join(page.operations).encode("latin-1", "replace")
            content = b"<< /Length %d >>\nstream\n%s\nendstream" % (len(stream_text), stream_text)
            page_body = (
                f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {page.width:.2f} {page.height:.2f}] "
                f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>"
            ).encode("latin-1")
            page_objects.append((content_id, content))
            page_objects.append((page_id, page_body))

        kids = " ".join(f"{page_id} 0 R" for page_id in page_refs)
        objects.append((2, f"<< /Type /Pages /Kids [{kids}] /Count {len(page_refs)} >>".encode("latin-1")))
        objects.extend(page_objects)
        return sorted(objects, key=lambda item: item[0])

    def render(self) -> bytes:
        if not self.pages:
            self.new_page()
        objects = self._build_objects()
        chunks: list[bytes] = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
        offsets: list[int] = [0]
        for object_id, body in objects:
            offsets.append(sum(len(chunk) for chunk in chunks))
            chunks.append(f"{object_id} 0 obj\n".encode("latin-1"))
            chunks.append(body)
            chunks.append(b"\nendobj\n")

        xref_offset = sum(len(chunk) for chunk in chunks)
        object_count = max(object_id for object_id, _ in objects)
        xref_rows = [b"xref\n", f"0 {object_count + 1}\n".encode("latin-1"), b"0000000000 65535 f \n"]
        object_offset_map = {object_id: offsets[idx + 1] for idx, (object_id, _) in enumerate(objects)}
        for object_id in range(1, object_count + 1):
            offset = object_offset_map[object_id]
            xref_rows.append(f"{offset:010d} 00000 n \n".encode("latin-1"))
        chunks.extend(xref_rows)
        trailer = (
            f"trailer\n<< /Size {object_count + 1} /Root 1 0 R /Info << /Title ({_escape_text(self.title)}) >> >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        )
        chunks.append(trailer.encode("latin-1", "replace"))
        return b"".join(chunks)


def capped_rows(rows: Iterable[dict[str, str]], *, limit: int) -> list[dict[str, str]]:
    return list(list(rows)[:limit])
