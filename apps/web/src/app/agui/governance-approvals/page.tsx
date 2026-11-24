"use client";

import { AppShell } from "@/components/app-shell";
import { AguiOversightBoard } from "@/components/agui-oversight-board";


const ACTIONS = [
  "governance.approve_application",
  "governance.block_application",
  "governance.assign_owner",
  "governance.change_risk_tier",
];

export default function AguiGovernanceApprovalsPage() {
  return (
    <AppShell>
      <AguiOversightBoard
        title="Governance Approvals"
        description="Approve or block discovered applications, assign ownership, and adjust risk tier with auditable lineage."
        sourceModule="governance"
        actionIds={ACTIONS}
      />
    </AppShell>
  );
}

