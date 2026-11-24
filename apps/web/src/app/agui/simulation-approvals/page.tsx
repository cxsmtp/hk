"use client";

import { AppShell } from "@/components/app-shell";
import { AguiOversightBoard } from "@/components/agui-oversight-board";


const ACTIONS = [
  "simulations.approve_pack_run",
  "simulations.suppress_failure_with_justification",
];

export default function AguiSimulationApprovalsPage() {
  return (
    <AppShell>
      <AguiOversightBoard
        title="Simulation Approval & Suppression"
        description="Approve simulation packs and suppress failures with explicit human justification and full traceability."
        sourceModule="simulations"
        actionIds={ACTIONS}
      />
    </AppShell>
  );
}

