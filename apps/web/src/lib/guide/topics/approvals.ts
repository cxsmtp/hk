import type { GuideTopic } from "../types";

/**
 * app/services/ai_system_approval_service.py (the policy, its defaults, scopes and expiry), app/api/routers/
 * ai_system_approvals.py, app/api/routers/ai_systems.py (asking, and the refused direct write),
 * app/services/governance_resolution.py (what the gateway reads), app/jobs/enforcement_jobs.py (the scheduled check),
 * Settings → AI system approvals.
 */
export const approvals: GuideTopic = {
  slug: "ai-system-approvals",
  title: "AI system approvals",
  summary: "Who approves an AI system and for how long: the policy by risk tier, blanket, one-time and time-bound approvals, the defaults, and what happens when an approval ends.",
  sections: [
    {
      id: "how-it-works",
      title: "How an AI system is approved",
      blocks: [
        {
          kind: "p",
          text: "The gateway lets an AI system through only while it is approved. Nobody sets it to approved directly any more: someone asks for an approval, and the number of different people the policy names for its risk tier approve it. A direct change of its status to approved, active or live is refused and written to the audit log.",
        },
        {
          kind: "steps",
          items: [
            "Someone who works on the inventory asks for the approval (`POST /ai-systems/{id}/approval-requests`), with the scope they want. Promoting a discovered application asks for it too. The system shows **pending approval**.",
            "The approvers see it on [Settings → AI system approvals](/settings/approvals), under **Waiting for a decision**. The first approver may change the scope within what the policy allows; the others approve that scope or deny.",
            "When enough different people said yes, the system is approved. One no denies the request. A request nobody decides expires after a week (the policy sets how long).",
          ],
        },
        {
          kind: "list",
          items: [
            "When a tier needs two or more approvers, the person who asked is never one of them, and nobody counts twice.",
            "With one approver, the person who asked may approve it only if the policy allows self-approval for that tier. By default no tier does.",
            "A request keeps the rule it was made under. A policy change applies to requests made after it.",
            "Prohibited systems are never approved. A risk tier the policy does not name is treated as critical.",
          ],
        },
      ],
    },
    {
      id: "scopes",
      title: "Blanket, one-time and time-bound",
      blocks: [
        {
          kind: "table",
          head: ["Scope", "What it means"],
          rows: [
            ["**Blanket**", "Stands until someone revokes it."],
            ["**One-time**", "Used up by the first request through the gateway. The rest of that request still goes through; the next one needs a new approval."],
            ["**Time-bound**", "Ends on its own after the hours the approver chose, up to the longest the policy allows."],
          ],
        },
        {
          kind: "p",
          text: "When an approval is used up, runs out or is revoked, the system goes to **pending re-approval** at once and the gateway treats it as not approved. A check every minute records time-bound approvals that ran out; the gateway does not wait for it. Raising a system's risk tier also ends its approval, so it is approved again under the stricter tier.",
        },
      ],
    },
    {
      id: "defaults",
      title: "The defaults",
      blocks: [
        {
          kind: "p",
          text: "Higher risk tiers are stricter. Nobody approves their own request in any tier until an owner or admin allows it.",
        },
        {
          kind: "table",
          head: ["Risk tier", "Approvers", "Who approves", "Scopes allowed", "Default"],
          rows: [
            ["Low", "1, not the requester", "Owner, Admin, Operator", "Blanket, one-time, time-bound", "Blanket"],
            ["Medium", "1, not the requester", "Owner, Admin", "Blanket, one-time, time-bound", "Time-bound, 90 days (up to 1 year)"],
            ["High", "2, neither the requester", "Owner, Admin", "One-time, time-bound", "Time-bound, 30 days (up to 90 days)"],
            ["Critical", "2, neither the requester", "Owner, Admin", "Time-bound only", "Time-bound, 7 days (up to 30 days)"],
            ["Restricted", "2, neither the requester", "Owner, Admin", "One-time, time-bound", "One-time (time-bound up to 7 days)"],
          ],
        },
        {
          kind: "note",
          tone: "warn",
          text: "With two approvers and only Owner and Admin approving, a tenant needs at least two people in those roles to approve high, critical or restricted systems. Add an approver, or change the roles for those tiers.",
        },
      ],
    },
    {
      id: "change-the-policy",
      title: "Change the policy",
      who: "Owners and admins",
      blocks: [
        {
          kind: "p",
          text: "On [Settings → AI system approvals](/settings/approvals), under **Approval policy by risk tier**, set for each tier: how many different people approve, whether the person who asked may approve it themselves (only with one approver), which roles approve, which scopes an approver may choose, the default scope, and the default and longest time-bound approval in hours. **Use the defaults** puts every tier back. Each save is in the audit log with what changed.",
        },
      ],
    },
    {
      id: "revoke",
      title: "Revoke an approval",
      who: "Approvers of the tier, owners and admins",
      blocks: [
        {
          kind: "p",
          text: "**Standing approvals** on [Settings → AI system approvals](/settings/approvals) lists every approval in force. **Revoke** ends one at once: the system goes to pending re-approval and the gateway stops letting it through.",
        },
      ],
    },
    {
      id: "upgrade",
      title: "Systems approved before the workflow",
      blocks: [
        {
          kind: "p",
          text: "Upgrading keeps every system that was approved, active or live approved, as a blanket approval marked as carried over. Nothing stops working. They are listed under **Standing approvals**, where they can be revoked and approved again under the policy.",
        },
      ],
    },
    {
      id: "audit",
      title: "In the audit log",
      blocks: [
        {
          kind: "p",
          text: "Every request, approval, denial, expiry, use of a one-time approval and revocation is in the [audit log](/settings/audit), each with an evidence record, as are refused attempts: approving your own request, approving twice, a role that may not approve, and a direct change of status to approved. The auditor's export lists them with the other governance changes.",
        },
      ],
    },
  ],
};
