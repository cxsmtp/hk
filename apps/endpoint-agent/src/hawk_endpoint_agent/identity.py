"""AI identity resolution.

Every decision the agent requests carries an identity block so Hawk AI-IAM can bind
the action to a human or non-human identity — no separate identity provider is
needed on the endpoint. Human actions carry the enrolled user; autonomous agent /
MCP actions are marked non-human and tied to the initiating user when known.
"""

from __future__ import annotations

import getpass
from dataclasses import dataclass
from typing import Any

from .config import AgentConfig


@dataclass
class Identity:
    endpoint_id: str
    hostname: str
    os_user: str
    user_id: str | None = None
    user_email: str | None = None

    def actor_block(self, *, actor_type: str = "human", agent_id: str | None = None) -> dict[str, Any]:
        """Identity fields to merge into a control-decision payload."""
        block: dict[str, Any] = {
            "endpoint_id": self.endpoint_id,
            "hostname": self.hostname,
            "actor_type": actor_type,
            "initiating_user_id": self.user_id,
            "user_email": self.user_email,
            "os_user": self.os_user,
        }
        if actor_type != "human":
            block["identity_type"] = "non_human"
            if agent_id:
                block["agent_id"] = agent_id
        else:
            block["identity_type"] = "human"
        return {k: v for k, v in block.items() if v is not None}


def resolve_identity(config: AgentConfig) -> Identity:
    try:
        os_user = getpass.getuser()
    except Exception:  # noqa: BLE001 - getuser can fail on headless hosts
        os_user = "unknown"
    return Identity(
        endpoint_id=config.endpoint_id,
        hostname=config.hostname,
        os_user=os_user,
        user_id=config.user_id or None,
        user_email=config.user_email or None,
    )
