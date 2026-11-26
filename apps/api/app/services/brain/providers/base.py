from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Callable, Iterator


class LLMProvider(ABC):
    name: str

    @abstractmethod
    def generate_json(self, system_prompt: str, user_prompt: str, json_schema: dict[str, Any]) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def generate_text(self, system_prompt: str, user_prompt: str) -> str:
        raise NotImplementedError

    def stream_text(
        self,
        system_prompt: str,
        user_prompt: str,
        *,
        usage_sink: Callable[[dict[str, Any]], None] | None = None,
    ) -> Iterator[str]:
        """Yield text deltas. Providers without a native stream return one buffered delta."""
        del usage_sink
        yield self.generate_text(system_prompt=system_prompt, user_prompt=user_prompt)

    @abstractmethod
    def health(self) -> dict[str, Any]:
        raise NotImplementedError


def iter_sse_data(lines: Iterator[str]) -> Iterator[str]:
    """Yield the joined ``data:`` payload of each server-sent event."""
    data: list[str] = []
    for line in lines:
        if line == "":
            if data:
                yield "\n".join(data)
                data = []
            continue
        if line.startswith(":"):
            continue
        field, _, value = line.partition(":")
        if field == "data":
            data.append(value[1:] if value.startswith(" ") else value)
    if data:
        yield "\n".join(data)
