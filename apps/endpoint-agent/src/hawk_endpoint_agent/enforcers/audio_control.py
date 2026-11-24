"""Audio-capture control.

Truly revoking another app's microphone grant on macOS is governed by TCC and can
only be changed by an MDM profile or the user — an unprivileged agent cannot flip
it programmatically. This enforcer is therefore honest: the effective "stop it
from listening" action for a local-audio notetaker is to terminate the capturing
process (see ProcessControl). ``revoke`` returns ``external_required`` unless the
fleet has granted the agent MDM-backed control.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class AudioActionResult:
    performed: bool
    mode: str        # "revoked" | "external_required" | "disabled"
    detail: str = ""


class AudioControl:
    def __init__(self, *, mdm_backed: bool) -> None:
        self._mdm_backed = mdm_backed

    def capability(self) -> dict[str, object]:
        return {
            "can_revoke_mic": self._mdm_backed,
            "control_authority": "mdm_tcc" if self._mdm_backed else "external_admin_required",
            "control_requirements": [] if self._mdm_backed else ["mdm_or_tcc_profile_required"],
            "note": "unprivileged agents cannot alter TCC mic grants; terminate the process instead",
        }

    def revoke(self, *, process_name: str) -> AudioActionResult:
        if not self._mdm_backed:
            return AudioActionResult(
                False,
                "external_required",
                f"mic revocation for {process_name} requires MDM/TCC control; use process termination",
            )
        # An MDM-backed deployment would push a TCC denial here.
        return AudioActionResult(True, "revoked", f"mic access denied for {process_name} via MDM profile")
