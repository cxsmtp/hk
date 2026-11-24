"""Native-messaging wire framing (Chrome / Edge / Firefox).

Each message is a 4-byte length prefix (native byte order) followed by UTF-8 JSON.
Pure functions so the framing can be unit-tested without a browser.
"""

from __future__ import annotations

import json
import struct
from typing import Any, Callable, Iterator

_MAX_MESSAGE = 64 * 1024 * 1024  # browsers cap native-messaging payloads


def encode_message(obj: Any) -> bytes:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    return struct.pack("@I", len(data)) + data


def read_messages(read: Callable[[int], bytes]) -> Iterator[dict[str, Any]]:
    """Yield decoded messages from a byte reader (e.g. ``sys.stdin.buffer.read``)."""
    while True:
        header = read(4)
        if not header or len(header) < 4:
            return
        length = struct.unpack("@I", header)[0]
        if length <= 0 or length > _MAX_MESSAGE:
            return
        payload = read(length)
        if len(payload) < length:
            return
        try:
            yield json.loads(payload.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            continue
