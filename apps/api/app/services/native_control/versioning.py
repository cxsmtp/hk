from __future__ import annotations

import re


_NUMERIC_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)(?:[-+][0-9A-Za-z.-]+)?$")


def _numeric_version(value: str | None) -> tuple[int, ...] | None:
    match = _NUMERIC_VERSION.fullmatch(str(value or "").strip())
    if match is None:
        return None
    return tuple(int(part) for part in match.group(1).split("."))


def version_in_verified_range(
    current: str | None,
    minimum: str | None,
    maximum: str | None,
) -> bool:
    """Compare numeric versions safely and opaque versions by exact allowlisting.

    Mixed/unknown version formats are rejected rather than allowed or compared as
    heterogeneous Python tuples.
    """

    current_text = str(current or "").strip()
    minimum_text = str(minimum or "").strip()
    maximum_text = str(maximum or "").strip()
    if not current_text or current_text.lower() == "unknown":
        return False
    if current_text in {minimum_text, maximum_text}:
        return True
    current_numeric = _numeric_version(current_text)
    minimum_numeric = _numeric_version(minimum_text) if minimum_text else None
    maximum_numeric = _numeric_version(maximum_text) if maximum_text and maximum_text != "*" else None
    if current_numeric is None:
        return False
    if minimum_text and minimum_numeric is None:
        return False
    if maximum_text and maximum_text != "*" and maximum_numeric is None:
        return False
    if minimum_numeric is not None and current_numeric < minimum_numeric:
        return False
    if maximum_numeric is not None and current_numeric > maximum_numeric:
        return False
    return minimum_numeric is not None or maximum_numeric is not None or maximum_text == "*"
