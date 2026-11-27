"use client";

import { Check } from "lucide-react";
import { useEffect, useState } from "react";

import { api } from "@/lib/api";
import { getSession, setSession } from "@/lib/auth";
import { defaultRouteForRole } from "@/lib/navigation";
import { rememberWorkspace } from "@/lib/workspace";

type Workspace = { id: string; name: string; role: string };

/**
 * For someone in several workspaces (an MSSP's analyst): which one is open, and opening another (POST
 * /auth/select-tenant gives cookies for it). The choice is remembered in this browser for the next sign-in
 * (lib/workspace.ts). Shows nothing for someone in one workspace, which is almost everyone.
 */
export function WorkspaceSwitch() {
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [busy, setBusy] = useState("");
  const current = getSession()?.tenantId;

  useEffect(() => {
    let active = true;
    api.myTenants().then((answer) => {
      if (active) setWorkspaces(answer.items || []);
    }).catch(() => undefined);
    return () => { active = false; };
  }, []);

  if (workspaces.length < 2) return null;

  async function open(workspace: Workspace) {
    const session = getSession();
    if (!session || workspace.id === session.tenantId) return;
    setBusy(workspace.id);
    try {
      await api.selectTenant(workspace.id);
      setSession({ tenantId: workspace.id, userRole: workspace.role, user: session.user });
      rememberWorkspace(workspace.id);
      window.location.assign(defaultRouteForRole(workspace.role));
    } catch {
      setBusy("");
    }
  }

  return (
    <div className="p-2" data-ui="workspace-switch">
      <p className="px-2 py-1.5 text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-600">Workspace</p>
      {workspaces.map((workspace) => (
        <button
          key={workspace.id}
          type="button"
          onClick={() => void open(workspace)}
          disabled={Boolean(busy)}
          aria-current={workspace.id === current ? "true" : undefined}
          className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-xs text-slate-300 transition hover:bg-white/[0.05] hover:text-white disabled:opacity-60"
        >
          <span className="grid h-3.5 w-3.5 place-items-center">{workspace.id === current ? <Check className="h-3.5 w-3.5 text-orange-300" /> : null}</span>
          <span className="min-w-0 flex-1 truncate">{workspace.name}</span>
          <span className="text-[10px] uppercase tracking-[0.08em] text-slate-500">{busy === workspace.id ? "Opening…" : workspace.role}</span>
        </button>
      ))}
    </div>
  );
}
