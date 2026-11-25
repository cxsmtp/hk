"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { Dialog, Icon, said } from "@/components/iam/ftr-bits";
import { api } from "@/lib/api";
import { can, changedRoles, matrixRows } from "@/lib/iam";
import type { IamPermission, IamRole, IamView } from "@/lib/iam";

/**
 * Settings → Roles & permissions: FTR Command Center's roles matrix (public/js/people.js rolesMatrix), in its layout
 * and words. Roles are columns, permissions rows: tick, find a permission, "Show only the differences", save; New role
 * (starting from another: a duplicate), Rename or Edit. Nobody ticks a permission they do not hold; Owner and Admin
 * always hold everything; the "Admin only" permissions stay with them. People see only the roles at their level and
 * below.
 */
export default function RolesPage() {
  const [d, setD] = useState<IamView | null>(null);
  const [loadError, setLoadError] = useState("");
  const load = useCallback(async () => {
    try {
      setD(await api.iamPeople());
      setLoadError("");
    } catch (error) {
      setLoadError(said(error, "Roles could not be loaded."));
    }
  }, []);
  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);
  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-roles">
        <div className="head">
          <div>
            <h1 className="serif">Roles &amp; permissions</h1>
            <p>What each role may do, in this tenant. Changes apply at once to everyone with the role.</p>
          </div>
        </div>
        {loadError ? <div className="callout warn">{loadError}</div> : null}
        {!d && !loadError ? <p className="muted">Loading…</p> : null}
        {d ? <Matrix key={d.roles.map((r) => `${r.id}:${r.permissions.join(",")}:${r.name}`).join("|")} d={d} reload={load} /> : null}
      </div>
    </AppShell>
  );
}

function Matrix({ d, reload }: { d: IamView; reload: () => Promise<void> }) {
  const edit = can(d, "roles.manage");
  const [draft, setDraft] = useState<Record<string, Set<string>>>(() => Object.fromEntries(d.roles.map((r) => [r.id, new Set(r.permissions)])));
  const [q, setQ] = useState("");
  const [diff, setDiff] = useState(false);
  const [form, setForm] = useState<IamRole | "new" | null>(null);
  const editable = (r: IamRole, p: IamPermission) => edit && !r.locked && !p.special && can(d, p.id) && Boolean(r.grantable);
  const groups = matrixRows(d.permissions, d.roles, draft, q, diff);
  const changed = useMemo(() => changedRoles(d.roles, draft), [d.roles, draft]);
  const tick = (roleId: string, pid: string, on: boolean) => {
    const next = { ...draft, [roleId]: new Set(draft[roleId]) };
    if (on) next[roleId].add(pid);
    else next[roleId].delete(pid);
    setDraft(next);
  };
  const save = async () => {
    try {
      for (const r of changed) await api.iamSaveRole(r.id, { name: r.name, description: r.description, permissions: [...draft[r.id]] });
      toast.success("Roles saved.");
      await reload();
    } catch (error) {
      toast.error(said(error));
    }
  };
  return (
    <div className="panel">
      <div className="flex">
        <h2 className="grow-h">
          Roles &amp; permissions{" "}
          <small>
            changes apply at once to everyone with the role · <span className="chip">Admin only</span> stays with Owners and Admins
          </small>
        </h2>
        {edit ? (
          <button type="button" id="newrole" onClick={() => setForm("new")}>
            <Icon name="plus" />
            New role
          </button>
        ) : null}
      </div>
      <div className="flex mt">
        <div className="search">
          <Icon name="search" />
          <input id="pq" placeholder="Find a permission" value={q} onChange={(e) => setQ(e.target.value)} />
        </div>
        <label className="check inline">
          <input type="checkbox" id="diff" checked={diff} onChange={(e) => setDiff(e.target.checked)} />
          <span>Show only the differences</span>
        </label>
        <span className="spacer" />
        {edit ? (
          <>
            <span className="small muted" id="dirty">
              {changed.length ? `Changed: ${changed.map((r) => r.name).join(", ")}` : ""}
            </span>
            <button className="primary" type="button" id="save" disabled={!changed.length} onClick={save}>
              Save role changes
            </button>
            <button className="ghost" type="button" id="discard" disabled={!changed.length} onClick={() => setDraft(Object.fromEntries(d.roles.map((r) => [r.id, new Set(r.permissions)])))}>
              Discard
            </button>
          </>
        ) : (
          <span className="small muted">Read only: an Owner or Admin changes roles.</span>
        )}
      </div>
      <div className="tw mt matrix-wrap">
        <table className="matrix">
          <thead>
            <tr>
              <th>Permission</th>
              {d.roles.map((r) => (
                <th className="rc" key={r.id} title={r.description}>
                  {r.name}
                  <span className="sub">
                    {r.holders ?? 0} {r.holders === 1 ? "person" : "people"}
                  </span>
                  {edit && r.grantable ? (
                    <button className="sm ghost" type="button" title={r.builtin ? "Rename this role (its permissions stay as ticked below)" : "Rename, describe or remove this role"} onClick={() => setForm(r)}>
                      {r.builtin ? "Rename" : "Edit"}
                    </button>
                  ) : null}
                </th>
              ))}
            </tr>
          </thead>
          <tbody id="mx">
            {groups.map((g) => [
              <tr className="grp" key={`g-${g.group}`}>
                <td colSpan={d.roles.length + 1}>{g.group}</td>
              </tr>,
              ...g.rows.map((p) => (
                <tr key={p.id}>
                  <td>
                    <b>{p.label}</b>
                    {p.special ? (
                      <>
                        {" "}
                        <span className="chip">Admin only</span>
                      </>
                    ) : null}
                    <span className="sub">{p.description}</span>
                  </td>
                  {d.roles.map((r) => (
                    <td className="rc" key={r.id}>
                      <input type="checkbox" aria-label={`${r.name}: ${p.label}`} checked={draft[r.id]?.has(p.id) ?? false} disabled={!editable(r, p)} onChange={(e) => tick(r.id, p.id, e.target.checked)} />
                    </td>
                  ))}
                </tr>
              )),
            ])}
          </tbody>
        </table>
      </div>
      {form ? <RoleForm d={d} role={form === "new" ? null : form} draft={draft} onClose={() => setForm(null)} reload={reload} /> : null}
    </div>
  );
}

function RoleForm({ d, role: r, draft, onClose, reload }: { d: IamView; role: IamRole | null; draft: Record<string, Set<string>>; onClose: () => void; reload: () => Promise<void> }) {
  const [err, setErr] = useState("");
  const special = new Set(d.permissions.filter((p) => p.special).map((p) => p.id));
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const from = d.roles.find((x) => x.id === f.get("from"));
    try {
      await api.iamSaveRole(r?.id ?? "new", {
        name: f.get("name"),
        description: f.get("desc"),
        permissions: r ? [...(draft[r.id] ?? [])] : (from?.permissions ?? []).filter((p) => can(d, p) && !special.has(p)),
      });
      onClose();
      await reload();
    } catch (error) {
      setErr(said(error));
    }
  };
  const remove = async () => {
    if (!r) return;
    try {
      await api.iamRemoveRole(r.id);
      onClose();
      await reload();
    } catch (error) {
      setErr(said(error));
    }
  };
  return (
    <form id="rf" onSubmit={submit}>
      <Dialog
        title={r ? `${r.builtin ? "Rename" : "Edit"} ${r.name}` : "New role"}
        sub={r ? (r.locked ? "The name everyone sees. This role always holds every permission." : "The name everyone sees, on People and invitations. Who holds it and what it allows stay the same.") : "Then tick its permissions in the matrix."}
        onClose={onClose}
        footer={
          <>
            {r && !r.builtin ? (
              <>
                <button type="button" className="danger" id="rdel" onClick={remove}>
                  Remove
                </button>
                <span className="spacer" />
              </>
            ) : null}
            <button type="button" className="ghost" onClick={onClose}>
              Cancel
            </button>
            <button className="primary" type="submit">
              {r ? "Save" : "Create role"}
            </button>
          </>
        }
      >
        <label className="f">
          Name
          <input name="name" required maxLength={60} defaultValue={r?.name ?? ""} />
        </label>
        <label className="f">
          Description
          <input name="desc" maxLength={300} defaultValue={r?.description ?? ""} />
        </label>
        {r ? null : (
          <label className="f">
            Start from
            <select name="from" defaultValue="">
              <option value="">Nothing</option>
              {d.roles
                .filter((x) => !x.locked)
                .map((x) => (
                  <option key={x.id} value={x.id}>
                    {x.name}
                  </option>
                ))}
            </select>
          </label>
        )}
        <div className="err" id="rerr">
          {err}
        </div>
      </Dialog>
    </form>
  );
}
