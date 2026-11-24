"""Hawk Endpoint Enforcement Floor domain.

This package supplies bounded local enforcement primitives to Hawk's existing
AI Action -> Policy -> Decision -> Evidence spine.  It is not a second policy
engine and source availability alone is never runtime protection evidence.
"""

from .contracts import (
    CapabilityState,
    EndpointPrimitive,
    EndpointPrimitiveContext,
    EndpointProcessIdentity,
    FloorComponent,
    RuntimeComponentState,
    VerificationState,
)

__all__ = [
    "CapabilityState",
    "EndpointPrimitive",
    "EndpointPrimitiveContext",
    "EndpointProcessIdentity",
    "FloorComponent",
    "RuntimeComponentState",
    "VerificationState",
]

