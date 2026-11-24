"use client";

import { AppShell } from "@/components/app-shell";
import { AguiOversightBoard } from "@/components/agui-oversight-board";


const ACTIONS = [
  "aiiam.approve_token_mint",
  "aiiam.approve_kill_switch",
  "aiiam.revoke_privilege",
];

export default function AguiAiIamApprovalsPage() {
  return (
    <AppShell>
      <AguiOversightBoard
        title="AI IAM Approvals"
        description="Human approvals for token minting, kill-switch execution, and privilege revocation."
        sourceModule="aiiam"
        actionIds={ACTIONS}
      />
    </AppShell>
  );
}

