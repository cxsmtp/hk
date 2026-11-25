"use client";

import { useCallback, useEffect, useState } from "react";
import { toast } from "sonner";

import { said } from "@/components/iam/ftr-bits";
import { api } from "@/lib/api";
import type { IamJoinSettings } from "@/lib/iam";

/**
 * "Joining by themselves", FTR Command Center's People → Sign-in panel (public/js/people.js signInTab joinPanel,
 * CC-01.116.00), for this tenant. Off until an Owner or Admin turns it on; the domains and the roles people may choose;
 * a role that manages people, roles or teams, or sees every team, is never offered. The activation code's cap of active
 * users and required two-step sign-in apply to people who join. Hidden for those who do not manage people.
 */
export function JoinSettingsPanel() {
  const [j, setJ] = useState<IamJoinSettings | null>(null);
  const load = useCallback(async () => {
    try {
      setJ(await api.iamJoinSettings());
    } catch {
      setJ(null);
    }
  }, []);
  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);
  if (!j) return null;
  const change = async (body: Record<string, unknown>) => {
    try {
      setJ(await api.iamSaveJoinSettings(body));
      toast.success("Saved.");
    } catch (error) {
      toast.error(said(error));
      await load();
    }
  };
  return (
    <div className="panel wide-panel" data-ui="join-settings">
      <h2>
        Joining by themselves <small>from the sign-in page, into this tenant ({j.workspace})</small>
      </h2>
      <p className="muted small">
        Someone with a work address of these domains asks from the sign-in page. Already with access: they are told how to sign in. New: a link (it proves the address is theirs) to give their name and choose their team, one of the roles below and a password. They are in at once, and listed on People for review. Roles that manage people, roles or teams, or see every team, are never offered. The activation code&apos;s limit of active users applies{j.twoStepRequired ? ", and they set up two-step sign-in before they get in" : ""}.
      </p>
      <div className="form">
        <label className="check">
          <input type="checkbox" checked={j.enabled} disabled={!j.canChange} onChange={(e) => change({ enabled: e.target.checked })} />
          <span>People may join by themselves</span>
        </label>
        <label className="f">
          Email domains <span className="muted">one or more, such as company.com</span>
          <input key={j.domains.join(",")} defaultValue={j.domains.join(", ")} disabled={!j.canChange} onBlur={(e) => e.target.value !== j.domains.join(", ") && change({ domains: e.target.value })} />
        </label>
        <div className="f">
          <span>Roles they may choose</span>
          <div className="flex wrap">
            {j.allRoles.map((r) => (
              <label className="check" key={r.id}>
                <input
                  type="checkbox"
                  checked={j.roles.includes(r.id)}
                  disabled={!j.canChange || !r.open}
                  onChange={(e) => change({ roles: e.target.checked ? [...j.roles, r.id] : j.roles.filter((x) => x !== r.id) })}
                />
                <span>
                  {r.name}
                  {r.open ? "" : " "}
                  {r.open ? null : <small className="muted">never</small>}
                </span>
              </label>
            ))}
          </div>
        </div>
      </div>
      {j.ready.ready ? <div className="callout mt">Joining is working: the sign-in page shows the way in.</div> : <div className="callout warn mt">Not available yet: {j.ready.missing.join(" ")}</div>}
      {j.canChange ? <p className="small muted">Changes save as you choose.</p> : <p className="small muted mt">An Owner or Admin changes this.</p>}
    </div>
  );
}
