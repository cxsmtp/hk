from __future__ import annotations

from datetime import datetime, timedelta, timezone


_MAX_ABSOLUTE_UTC_OFFSET = timedelta(days=1)
_FIXED_ERROR = "invalid collector timestamp"


class CollectorTimestampNormalizationError(ValueError):
    """Fixed, non-reflective rejection for untrusted collector timestamps."""


def _invalid_timestamp() -> CollectorTimestampNormalizationError:
    return CollectorTimestampNormalizationError(_FIXED_ERROR)


def normalize_collector_timestamp(value: object) -> datetime:
    """Normalize one exact datetime using a single captured UTC offset.

    The source timezone is consulted exactly once. UTC is then calculated from
    the naive wall-clock fields and the captured exact timedelta, so a stateful
    or hostile tzinfo cannot change the result during conversion.
    """

    if type(value) is not datetime:
        raise _invalid_timestamp() from None

    offset_failed = False
    try:
        offset = value.utcoffset()
    except Exception:
        offset = None
        offset_failed = True
    if offset_failed:
        raise _invalid_timestamp() from None

    if type(offset) is not timedelta:
        raise _invalid_timestamp() from None
    if not -_MAX_ABSOLUTE_UTC_OFFSET < offset < _MAX_ABSOLUTE_UTC_OFFSET:
        raise _invalid_timestamp() from None

    arithmetic_failed = False
    try:
        wall_time = datetime(
            value.year,
            value.month,
            value.day,
            value.hour,
            value.minute,
            value.second,
            value.microsecond,
            fold=value.fold,
        )
        utc_wall_time = wall_time - offset
    except Exception:
        arithmetic_failed = True
    if arithmetic_failed:
        raise _invalid_timestamp() from None
    return utc_wall_time.replace(tzinfo=timezone.utc)
