"use client";

import { AppShell } from "@/components/app-shell";
import { AguiOversightBoard } from "@/components/agui-oversight-board";


const ACTIONS = [
  "findings.accept_recommendation",
  "findings.reject_recommendation",
  "findings.escalate_to_governance",
  "findings.assign_owner",
  "findings.accept_risk",
];

export default function AguiFindingsReviewPage() {
  return (
    <AppShell>
      <AguiOversightBoard
        title="Findings Review"
        description="Human review queue for finding recommendations, owner assignment, escalation, and explicit risk acceptance."
        sourceModule="findings"
        actionIds={ACTIONS}
      />
    </AppShell>
  );
}

