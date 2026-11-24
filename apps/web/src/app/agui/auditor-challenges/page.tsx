"use client";

import { AppShell } from "@/components/app-shell";
import { AguiOversightBoard } from "@/components/agui-oversight-board";


const ACTIONS = [
  "auditor.challenge_assertion",
  "auditor.resolve_contested_control",
  "auditor.approve_export_pack",
];

export default function AguiAuditorChallengesPage() {
  return (
    <AppShell>
      <AguiOversightBoard
        title="Auditor Challenge & Contested Controls"
        description="Adjudicate contested controls, challenge assertions, and approve export packs with explicit evidence review."
        sourceModule="auditor"
        actionIds={ACTIONS}
      />
    </AppShell>
  );
}

