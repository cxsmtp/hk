from __future__ import annotations


REAL_BINARY_ACCEPTANCE_VERSION = "native-control-real-binary-acceptance/2.0"


def acceptance_version_is_current(
    *, acceptance_state: object, validation_version: object
) -> bool:
    """Reject legacy local-binary acceptances minted without v2 evidence."""

    if str(acceptance_state or "") != "REAL_BINARY_ACCEPTED":
        return True
    return str(validation_version or "") == REAL_BINARY_ACCEPTANCE_VERSION
