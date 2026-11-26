"""Approving an AI system in tests about other things, through the approval workflow (app/services/
ai_system_approval_service.py), now that PATCH /ai-systems/{id} refuses to set an approved status directly.

``approve_ai_system`` sets the tenant's policy to one approver with self-approval and blanket approvals for every tier
(a policy an owner or admin may choose on Settings → AI system approvals), asks for the approval and approves it as
the same person. The approval puts the system in "approved" or "active"; for "live" (which has prerequisites of its
own) it then PATCHes the status. It returns the last response: the PATCH for live, else GET /ai-systems/{id}.
"""

from __future__ import annotations

from typing import Any

SELF_APPROVAL_POLICY: dict[str, Any] = {
    "tiers": {
        tier: {
            "min_approvers": 1,
            "allow_self_approval": True,
            "approver_roles": ["owner", "admin", "operator"],
            "allowed_scopes": ["blanket", "one_time", "time_bound"],
            "default_scope": "blanket",
        }
        for tier in ("LOW", "MEDIUM", "HIGH", "CRITICAL", "RESTRICTED")
    }
}


def allow_self_approval(client: Any, headers: dict[str, str]) -> None:
    current = client.get("/settings/ai-system-approvals", headers=headers)
    assert current.status_code == 200, current.text
    tiers = current.json()["policy"]["tiers"]
    if all(rule["allow_self_approval"] and rule["min_approvers"] == 1 and "blanket" in rule["allowed_scopes"] for rule in tiers.values()):
        return
    saved = client.put("/settings/ai-system-approvals", headers=headers, json=SELF_APPROVAL_POLICY)
    assert saved.status_code == 200, saved.text


def approve_ai_system(client: Any, headers: dict[str, str], ai_system_id: str, *, status: str = "approved") -> Any:
    allow_self_approval(client, headers)
    target = status if status in ("approved", "active") else "approved"
    asked = client.post(
        f"/ai-systems/{ai_system_id}/approval-requests", headers=headers, json={"scope": "blanket", "target_status": target}
    )
    assert asked.status_code == 200, asked.text
    decided = client.post(
        f"/ai-system-approvals/{asked.json()['request']['id']}/decision",
        headers=headers,
        json={"decision": "approve", "scope": "blanket"},
    )
    assert decided.status_code == 200, decided.text
    if status not in ("approved", "active"):
        return client.patch(f"/ai-systems/{ai_system_id}", headers=headers, json={"status": status})
    return client.get(f"/ai-systems/{ai_system_id}", headers=headers)


def approve_pending_request(client: Any, headers: dict[str, str], ai_system_id: str) -> Any:
    """Approve the request already waiting for this system (one made by discovery's promote, say). The policy must
    have allowed self-approval when the request was made: a request keeps the rule it was made under."""

    pending = client.get("/ai-system-approvals", headers=headers, params={"ai_system_id": ai_system_id})
    assert pending.status_code == 200, pending.text
    items = pending.json()["items"]
    assert items, f"no approval request waiting for {ai_system_id}"
    decided = client.post(f"/ai-system-approvals/{items[0]['id']}/decision", headers=headers, json={"decision": "approve"})
    assert decided.status_code == 200, decided.text
    return decided
