"""Customer-authorized, metadata-only HMAIR source connectors.

This package is deliberately separate from the legacy monitoring-provider
bridge.  A source is admitted only when it has an explicit source contract;
there is no provider-name fallback.
"""

from app.services.hmair.source_connectors.registry import source_registry

__all__ = ["source_registry"]
