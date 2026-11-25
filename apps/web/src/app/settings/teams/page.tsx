"use client";

import "../ftr-settings.css";

import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";

import { AppShell } from "@/components/app-shell";
import { Dialog, Icon, said } from "@/components/iam/ftr-bits";
import { api } from "@/lib/api";
import { can, teamTree } from "@/lib/iam";
import type { IamTeam, IamView } from "@/lib/iam";

/**
 * Settings → Teams: FTR Command Center's Teams (public/js/teams.js viewTeams), in its layout and words. Teams form a
 * tree, each with its leaders; a team's leaders see it and every team below it. In Hawk, teams decide whose people one
 * sees and manages (Settings → People); the inventory, evidence and the other records belong to the tenant, not to a
 * team, so teams scope nothing else.
 */
export default function TeamsPage() {
  const [d, setD] = useState<IamView | null>(null);
  const [loadError, setLoadError] = useState("");
  const [editing, setEditing] = useState<IamTeam | "new" | null>(null);
  const load = useCallback(async () => {
    try {
      setD(await api.iamPeople());
      setLoadError("");
    } catch (error) {
      setLoadError(said(error, "Teams could not be loaded."));
    }
  }, []);
  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);
  const manage = can(d, "teams.manage");
  const rows = d ? teamTree(d.teams) : [];
  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-teams">
        <div className="head">
          <div>
            <h1 className="serif">Teams</h1>
            <p>The team structure: a team&apos;s leaders see it and every team below it, and manage its people. Owners and Admins see every team. Teams organise people only: Hawk&apos;s records belong to the whole tenant.</p>
          </div>
          <div className="tools">
            {manage ? (
              <button className="primary" type="button" id="add" onClick={() => setEditing("new")}>
                <Icon name="plus" />
                New team
              </button>
            ) : null}
          </div>
        </div>
        {loadError ? <div className="callout warn">{loadError}</div> : null}
        {!d && !loadError ? <p className="muted">Loading…</p> : null}
        {d ? (
          <div className="panel">
            <div className="tree">
              {rows.map(({ team: t, depth }) => (
                <div className="node" key={t.id} data-id={t.id}>
                  <div className="t">
                    <span className="indent" style={{ width: depth * 22 }} />
                    {depth ? <span className="twig" /> : null}
                    <div>
                      <b>{t.name}</b> <small>{t.region}</small>
                      <div className="small muted">{t.leaders.length ? `Led by ${t.leaders.map((l) => l.name).join(", ")}` : "No leader yet"}</div>
                    </div>
                  </div>
                  <span className="m">{t.members} people</span>
                  <span className="m">{t.path}</span>
                  {manage ? (
                    <button className="sm" type="button" onClick={() => setEditing(t)}>
                      Edit
                    </button>
                  ) : (
                    <span />
                  )}
                </div>
              ))}
              {!rows.length ? (
                <div className="empty">
                  <b>No teams</b>
                </div>
              ) : null}
            </div>
          </div>
        ) : null}
        {d && editing ? <TeamForm d={d} team={editing === "new" ? null : editing} onClose={() => setEditing(null)} reload={load} /> : null}
      </div>
    </AppShell>
  );
}

function TeamForm({ d, team: t, onClose, reload }: { d: IamView; team: IamTeam | null; onClose: () => void; reload: () => Promise<void> }) {
  const [err, setErr] = useState("");
  const others = d.teams.filter((x) => x.id !== t?.id).sort((a, b) => a.path.localeCompare(b.path));
  const people = [...d.people].sort((a, b) => a.name.localeCompare(b.name));
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    try {
      await api.iamSaveTeam(t?.id ?? null, { name: f.get("name"), region: f.get("region"), parentId: f.get("parent") || null, leaderIds: f.getAll("leaders") });
      onClose();
      await reload();
    } catch (error) {
      setErr(said(error));
    }
  };
  const remove = async () => {
    if (!t) return;
    try {
      await api.iamRemoveTeam(t.id);
      onClose();
      await reload();
    } catch (error) {
      setErr(said(error));
    }
  };
  return (
    <form id="tf" onSubmit={submit}>
      <Dialog
        title={t ? `Edit ${t.name}` : "New team"}
        onClose={onClose}
        footer={
          <>
            {t ? (
              <>
                <button type="button" className="danger" onClick={remove}>
                  Remove team
                </button>
                <span className="spacer" />
              </>
            ) : null}
            <button type="button" className="ghost" onClick={onClose}>
              Cancel
            </button>
            <button className="primary" type="submit">
              Save
            </button>
          </>
        }
      >
        <div className="row">
          <label className="f">
            Name
            <input name="name" required maxLength={80} defaultValue={t?.name ?? ""} />
          </label>
          <label className="f">
            Region
            <input name="region" maxLength={60} defaultValue={t?.region ?? ""} placeholder="EMEA, APAC, NA…" />
          </label>
        </div>
        <label className="f">
          Sits below
          <select name="parent" defaultValue={t?.parentId ?? ""}>
            <option value="">Nothing: a top team</option>
            {others.map((o) => (
              <option key={o.id} value={o.id}>
                {o.path}
              </option>
            ))}
          </select>
        </label>
        <label className="f">
          Leaders <span className="muted">(they see this team and every team below it)</span>
          <select name="leaders" multiple size={6} defaultValue={t?.leaderIds ?? []}>
            {people.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name} · {p.roleName}
              </option>
            ))}
          </select>
        </label>
        <div className="err">{err}</div>
      </Dialog>
    </form>
  );
}
