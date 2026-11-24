from __future__ import annotations

from datetime import datetime, timedelta, timezone, tzinfo

import pytest

from app.services.collector_timestamp import (
    CollectorTimestampNormalizationError,
    normalize_collector_timestamp,
)


class _CountingTimezone(tzinfo):
    def __init__(self, offsets: list[object]) -> None:
        self.offsets = list(offsets)
        self.calls = 0

    def utcoffset(self, _dt: datetime | None) -> object:
        index = min(self.calls, len(self.offsets) - 1)
        self.calls += 1
        return self.offsets[index]

    def dst(self, _dt: datetime | None) -> timedelta | None:
        return None


def test_normalizer_uses_one_captured_offset_without_reconsulting_tzinfo() -> None:
    source_tz = _CountingTimezone([timedelta(hours=4), timedelta(0)])
    value = datetime(2026, 7, 24, 12, 30, tzinfo=source_tz)

    normalized = normalize_collector_timestamp(value)

    assert type(normalized) is datetime
    assert normalized == datetime(2026, 7, 24, 8, 30, tzinfo=timezone.utc)
    assert normalized.tzinfo is timezone.utc
    assert source_tz.calls == 1


@pytest.mark.parametrize(
    "offset",
    [
        None,
        0,
        timedelta(days=-1),
        timedelta(days=1),
    ],
)
def test_normalizer_rejects_invalid_or_out_of_range_offsets(offset: object) -> None:
    source_tz = _CountingTimezone([offset])
    value = datetime(2026, 7, 24, 12, 30, tzinfo=source_tz)

    with pytest.raises(
        CollectorTimestampNormalizationError,
        match="^invalid collector timestamp$",
    ) as captured:
        normalize_collector_timestamp(value)

    assert captured.value.__cause__ is None
    assert source_tz.calls == 1


def test_normalizer_rejects_datetime_subclasses_without_accessing_tzinfo() -> None:
    secret = "secret-datetime-subclass"

    class HostileDatetime(datetime):
        def utcoffset(self) -> timedelta | None:
            raise AssertionError(secret)

    value = HostileDatetime(2026, 7, 24, 12, 30, tzinfo=timezone.utc)

    with pytest.raises(CollectorTimestampNormalizationError) as captured:
        normalize_collector_timestamp(value)

    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None


def test_normalizer_rejects_timedelta_offset_subclasses() -> None:
    class OffsetSubclass(timedelta):
        pass

    source_tz = _CountingTimezone([OffsetSubclass(hours=1)])
    value = datetime(2026, 7, 24, 12, 30, tzinfo=source_tz)

    with pytest.raises(CollectorTimestampNormalizationError) as captured:
        normalize_collector_timestamp(value)

    assert str(captured.value) == "invalid collector timestamp"
    assert source_tz.calls == 1


def test_normalizer_hides_hostile_timezone_errors() -> None:
    secret = "secret-hostile-offset"

    class HostileTimezone(tzinfo):
        def utcoffset(self, _dt: datetime | None) -> timedelta | None:
            raise AssertionError(secret)

        def dst(self, _dt: datetime | None) -> timedelta | None:
            return None

    value = datetime(2026, 7, 24, 12, 30, tzinfo=HostileTimezone())

    with pytest.raises(CollectorTimestampNormalizationError) as captured:
        normalize_collector_timestamp(value)

    assert str(captured.value) == "invalid collector timestamp"
    assert secret not in str(captured.value)
    assert captured.value.__cause__ is None
    assert captured.value.__context__ is None


def test_normalizer_fails_closed_on_utc_arithmetic_overflow() -> None:
    source_tz = _CountingTimezone([timedelta(microseconds=1)])
    value = datetime.min.replace(tzinfo=source_tz)

    with pytest.raises(CollectorTimestampNormalizationError) as captured:
        normalize_collector_timestamp(value)

    assert str(captured.value) == "invalid collector timestamp"
    assert captured.value.__cause__ is None
