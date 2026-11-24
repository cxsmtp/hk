from __future__ import annotations

from datetime import timedelta

import pytest

from test_phase5_execution_receipt_v2 import NOW


def test_delegation_attenuation_never_allows_scope_or_value_expansion() -> None:
    from app.services.action_integrity.complex_actions import delegated_child_is_attenuated
    parent = {"resources": ["account:a"], "operations": ["read", "write"], "max_value": "10"}
    assert delegated_child_is_attenuated(parent, {"resources": ["account:a"], "operations": ["read"], "max_value": "10"})
    assert not delegated_child_is_attenuated(parent, {"resources": ["account:b"], "operations": ["read"], "max_value": "1"})
    assert not delegated_child_is_attenuated(parent, {"resources": ["account:a"], "operations": ["write"], "max_value": "10.01"})
