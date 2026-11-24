"use client";

import { AppShell } from "@/components/app-shell";
import { AguiOversightBoard } from "@/components/agui-oversight-board";


const ACTIONS = [
  "policies.approve_activation",
  "policies.override_enforcement",
  "policies.disable_guardian_binding",
];

export default function AguiPolicyOverridesPage() {
  return (
    <AppShell>
      <AguiOversightBoard
        title="Policy Override Approval"
        description="Human approvals for policy activation, enforcement overrides, and guardian binding changes."
        sourceModule="policies"
        actionIds={ACTIONS}
      />
    </AppShell>
  );
}

