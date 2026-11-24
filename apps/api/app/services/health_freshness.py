from __future__ import annotations

from datetime import timedelta


# Security freshness for collector evidence is intentionally independent from
# operational deployment heartbeat thresholds, even while their initial values
# are equal.
COLLECTOR_EVIDENCE_MAX_AGE = timedelta(minutes=2)

HEARTBEAT_WARNING_AGE = timedelta(minutes=2)
HEARTBEAT_OFFLINE_AGE = timedelta(minutes=15)
