from __future__ import annotations

from typing import Generic, Sequence, TypeVar

from pydantic import BaseModel


T = TypeVar("T")


class ListEnvelope(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int


def paginate_rows(rows: Sequence[T], *, page: int = 1, page_size: int = 50) -> tuple[list[T], int, int, int]:
    safe_page = max(1, int(page))
    safe_page_size = max(1, int(page_size))
    total = len(rows)
    start = (safe_page - 1) * safe_page_size
    end = start + safe_page_size
    return list(rows[start:end]), total, safe_page, safe_page_size
