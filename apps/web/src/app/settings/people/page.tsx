"use client";

import "../ftr-settings.css";

import Link from "next/link";
import { useCallback, useEffect, useMemo, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { Avatar, Dialog, Icon, said } from "@/components/iam/ftr-bits";
import { api } from "@/lib/api";
import { ago, can, csvCell, filterPeople, generatePassword, PAGE, STATUS } from "@/lib/iam";
import type { IamPerson, IamView, PeopleFilters } from "@/lib/iam";

/**
 * Settings → People: FTR Command Center's People (public/js/people.js peopleTable, reviewJoiners, openPerson and
 * personAction), in its layout and words. Everyone sees the people in their teams and the teams they lead; those who
 * manage people add them, change their role, team and manager in the row or in Manage, reset passwords and two-step
 * sign-in, unlock, sign out, turn access off and remove, never beyond their own permissions. People who joined by
 * themselves (CC-01.116.00) are listed at the top for review.
 */
export default function PeoplePage() {
  const [d, setD] = useState<IamView | null>(null);
  const [loadError, setLoadError] = useState("");
  const load = useCallback(async () => {
    try {
      setD(await api.iamPeople());
      setLoadError("");
    } catch (error) {
      setLoadError(said(error, "People could not be loaded."));
    }
  }, []);
  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);
  const manage = can(d, "users.manage");
  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-people">
        <div className="head">
          <div>
            <h1 className="serif">People</h1>
            <p>
              {manage
                ? can(d, "scope.all")
                  ? "Everyone who can sign in, and what they may do. You manage people in every team."
                  : "The people in the teams you lead. You can invite them, change their role and team, reset passwords, unlock, sign out and turn access off, never beyond your own permissions."
                : "The people in your teams and the teams you lead."}
            </p>
          </div>
          <div className="flex">
            {manage || can(d, "roles.manage") ? (
              <Link className="btn ghost" href="/settings/roles">
                Roles &amp; permissions <em>{d ? d.roles.length : ""}</em>
              </Link>
            ) : null}
            <Link className="btn ghost" href="/settings/teams">
              Teams
            </Link>
            {can(d, "security.sso") ? (
              <Link className="btn ghost" href="/settings/signin">
                Sign-in
              </Link>
            ) : null}
          </div>
        </div>
        {loadError ? <div className="callout warn">{loadError}</div> : null}
        {!d && !loadError ? <p className="muted">Loading…</p> : null}
        {d ? <PeopleTable d={d} reload={load} /> : null}
      </div>
    </AppShell>
  );
}

function ReviewJoiners({ d, reload }: { d: IamView; reload: () => Promise<void> }) {
  const waiting = d.people.filter((u) => u.joined && !u.joined.reviewedAt && u.active && u.manageable);
  const roles = d.roles.filter((r) => r.grantable);
  const teams = [...d.teams].sort((a, b) => a.path.localeCompare(b.path));
  if (!waiting.length || !can(d, "users.manage")) return null;
  const change = async (id: string, body: Record<string, unknown>, text: string) => {
    try {
      await api.iamChangePerson(id, body);
      toast.success(text);
    } catch (error) {
      toast.error(said(error));
    }
    await reload();
  };
  return (
    <div className="panel join-review" id="join-review">
      <h2>
        Joined, to review{" "}
        <small>
          {waiting.length} {waiting.length === 1 ? "person" : "people"} joined by themselves: check their team and role, then approve
        </small>
      </h2>
      <div className="tw">
        <table className="join-table">
          <thead>
            <tr>
              <th>Person</th>
              <th>Team</th>
              <th>Role</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {waiting.map((u) => (
              <tr key={u.id}>
                <td>
                  <b>{u.name}</b>
                  <div className="muted small">
                    {u.email}
                    {u.title ? ` · ${u.title}` : ""} · joined {ago(u.joined?.at)}
                  </div>
                </td>
                <td>
                  <select aria-label={`Team of ${u.name}`} value={u.teamId ?? ""} onChange={(e) => change(u.id, { teamId: e.target.value || null }, `Team: ${e.target.selectedOptions[0].textContent}.`)}>
                    <option value="">No team</option>
                    {teams.map((t) => (
                      <option key={t.id} value={t.id}>
                        {t.path}
                      </option>
                    ))}
                  </select>
                </td>
                <td>
                  <select aria-label={`Role of ${u.name}`} value={u.role} onChange={(e) => change(u.id, { role: e.target.value }, `Role: ${e.target.selectedOptions[0].textContent}.`)}>
                    {roles.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.name}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="actions">
                  <span className="flex nowrap">
                    <button
                      type="button"
                      className="primary sm"
                      onClick={async () => {
                        try {
                          await api.iamPersonAction(u.id, "approve");
                          toast.success("Approved.");
                        } catch (error) {
                          toast.error(said(error));
                        }
                        await reload();
                      }}
                    >
                      Approve
                    </button>
                    <button
                      type="button"
                      className="ghost sm danger"
                      onClick={() => {
                        if (window.confirm(`Turn off ${u.name}'s access? They are signed out at once and cannot sign in until it is turned on again.`)) change(u.id, { active: false }, "Access turned off.");
                      }}
                    >
                      Turn off
                    </button>
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

const EMPTY: PeopleFilters = { q: "", role: "", team: "", status: "", boss: "" };

function PeopleTable({ d, reload }: { d: IamView; reload: () => Promise<void> }) {
  const manage = can(d, "users.manage");
  const roles = d.roles.filter((r) => r.grantable);
  const teams = useMemo(() => [...d.teams].sort((a, b) => a.path.localeCompare(b.path)), [d.teams]);
  const [filters, setFilters] = useState<PeopleFilters>(EMPTY);
  const [page, setPage] = useState(0);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [adding, setAdding] = useState(false);
  const [person, setPerson] = useState<IamPerson | null>(null);
  const [temporary, setTemporary] = useState<{ email: string; password: string } | null>(null);
  const [bulkOut, setBulkOut] = useState("");
  const all = filterPeople(d.people, filters);
  const pages = Math.max(1, Math.ceil(all.length / PAGE));
  const current = Math.min(page, pages - 1);
  const shown = all.slice(current * PAGE, current * PAGE + PAGE);
  const pickable = all.filter((u) => u.manageable);
  const setF = (key: keyof PeopleFilters) => (e: { target: { value: string } }) => {
    setFilters({ ...filters, [key]: e.target.value });
    setPage(0);
  };

  const inline = async (u: IamPerson, kind: "role" | "team", value: string, label: string) => {
    try {
      await api.iamChangePerson(u.id, kind === "role" ? { role: value } : { teamId: value || null });
      toast.success(`${u.name}: ${kind} changed to ${label}.`);
    } catch (error) {
      toast.error(said(error));
    }
    await reload();
  };

  const runBulk = async (label: string, fn: (u: IamPerson) => Promise<unknown>) => {
    const people = d.people.filter((u) => selected.has(u.id));
    const failed: string[] = [];
    const done: { u: IamPerson; r: unknown }[] = [];
    let n = 0;
    for (const u of people) {
      setBulkOut(`${label}: ${++n} of ${people.length}…`);
      try {
        done.push({ u, r: await fn(u) });
      } catch (error) {
        failed.push(`${u.name}: ${said(error)}`);
      }
    }
    setBulkOut("");
    if (failed.length) toast.error(`${label}: ${done.length} done, ${failed.length} not: ${failed.slice(0, 3).join(" · ")}${failed.length > 3 ? "…" : ""}`);
    else toast.success(`${label}: done for ${done.length} ${done.length === 1 ? "person" : "people"}.`);
    await reload();
    return done;
  };
  const many = `${selected.size} ${selected.size === 1 ? "person" : "people"}`;
  const bulk = async (act: string) => {
    if (act === "on") return runBulk("Access on", (u) => api.iamChangePerson(u.id, { active: true }));
    if (act === "off" && window.confirm(`Turn off access for ${many}? They are signed out at once.`)) return runBulk("Access off", (u) => api.iamChangePerson(u.id, { active: false }));
    if (act === "welcome" && window.confirm(`Email a welcome to ${many}?`)) return runBulk("Welcome sent", (u) => api.iamPersonAction(u.id, "welcome"));
    if (act === "signout" && window.confirm(`Sign ${many} out on every device?`)) return runBulk("Signed out", (u) => api.iamPersonAction(u.id, "signout"));
    if (act === "unlock") return runBulk("Unlocked", (u) => api.iamPersonAction(u.id, "unlock"));
    if (act === "remove" && window.confirm(`Remove ${many}? This cannot be undone.`)) return runBulk("Removed", (u) => api.iamRemovePerson(u.id));
    if (act === "reset" && window.confirm(`Give ${many} a new temporary password? Their current ones stop working and they are signed out everywhere. The new ones download once, as a sheet.`)) {
      const done = await runBulk("Passwords reset", (u) => api.iamPersonAction(u.id, "reset"));
      if (done.length) {
        const csv = ["Name,Email,Temporary password", ...done.map(({ u, r }) => [u.name, u.email, (r as { temporary?: string }).temporary ?? ""].map(csvCell).join(","))].join("\r\n");
        const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(new Blob([csv], { type: "text/csv" })), download: `temporary-passwords-${new Date().toISOString().slice(0, 10)}.csv` });
        a.click();
        setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      }
    }
  };
  const bulkSelect = async (kind: "role" | "team" | "manager", value: string, label: string) => {
    if (!value) return;
    if (kind === "role" && window.confirm(`Give ${many} the role ${label}?`)) await runBulk(`Role → ${label}`, (u) => api.iamChangePerson(u.id, { role: value }));
    if (kind === "team" && window.confirm(`Move ${many} to ${label}?`)) await runBulk(`Team → ${label}`, (u) => api.iamChangePerson(u.id, { teamId: value }));
    if (kind === "manager") {
      const managerId = value === "-" ? null : value;
      if (window.confirm(`${many} ${selected.size === 1 ? "reports" : "report"} to ${managerId ? label : "nobody"}?`)) await runBulk(`Reports to → ${label}`, (u) => api.iamChangePerson(u.id, { managerId }));
    }
  };

  return (
    <>
      <ReviewJoiners d={d} reload={reload} />
      <div className="panel">
        <div className="flex">
          <h2 className="grow-h">
            People <small>everyone who can sign in, and what they may do</small>
          </h2>
          {manage ? (
            <button className="primary" type="button" id="add-toggle" onClick={() => setAdding(!adding)}>
              <Icon name="plus" />
              Add person
            </button>
          ) : null}
        </div>
        {manage && adding ? <AddForm d={d} onDone={reload} onCancel={() => setAdding(false)} /> : null}
        <div className="filters mt">
          <div className="search">
            <Icon name="search" />
            <input id="q" placeholder="Search people, emails, titles" value={filters.q} onChange={setF("q")} />
          </div>
          <select id="f-role" value={filters.role} onChange={setF("role")}>
            <option value="">All roles</option>
            {d.roles.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
          <select id="f-team" value={filters.team} onChange={setF("team")}>
            <option value="">All teams</option>
            {teams.map((t) => (
              <option key={t.id} value={t.id}>
                {t.path}
              </option>
            ))}
          </select>
          <select id="f-manager" title="Everyone under this person, at every level" value={filters.boss} onChange={setF("boss")}>
            <option value="">Reports to: anyone</option>
            <option value="-">Reports to nobody</option>
            {d.people
              .filter((u) => u.reports.length)
              .map((u) => (
                <option key={u.id} value={u.id}>
                  Under {u.name}
                </option>
              ))}
          </select>
          <select id="f-status" value={filters.status} onChange={setF("status")}>
            <option value="">Any status</option>
            {Object.entries(STATUS).map(([k, [, l]]) => (
              <option key={k} value={k}>
                {l}
              </option>
            ))}
          </select>
          <span className="spacer" />
          <span className="muted small" id="count">
            {all.length} of {d.people.length}
          </span>
        </div>
        {manage && selected.size ? (
          <div className="bulk" id="bulk">
            <b>{selected.size} selected</b>
            <label className="bulk-f">
              Role
              <select value="" onChange={(e) => bulkSelect("role", e.target.value, e.target.selectedOptions[0].textContent ?? "")}>
                <option value="">—</option>
                {roles.map((r) => (
                  <option key={r.id} value={r.id}>
                    {r.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="bulk-f">
              Team
              <select value="" onChange={(e) => bulkSelect("team", e.target.value, e.target.selectedOptions[0].textContent ?? "")}>
                <option value="">—</option>
                {teams.map((t) => (
                  <option key={t.id} value={t.id}>
                    {t.path}
                  </option>
                ))}
              </select>
            </label>
            <label className="bulk-f">
              Reports to
              <select value="" onChange={(e) => bulkSelect("manager", e.target.value, e.target.selectedOptions[0].textContent ?? "")}>
                <option value="">—</option>
                <option value="-">Nobody</option>
                {d.managers.map((m) => (
                  <option key={m.id} value={m.id}>
                    {m.name}
                  </option>
                ))}
              </select>
            </label>
            <button type="button" className="sm" onClick={() => bulk("on")}>
              Access on
            </button>
            <button type="button" className="sm" onClick={() => bulk("off")}>
              Access off
            </button>
            {d.mail ? (
              <button type="button" className="sm" onClick={() => bulk("welcome")}>
                Send welcome
              </button>
            ) : null}
            <button type="button" className="sm" onClick={() => bulk("reset")}>
              Reset passwords
            </button>
            <button type="button" className="sm" onClick={() => bulk("signout")}>
              Sign out everywhere
            </button>
            <button type="button" className="sm" onClick={() => bulk("unlock")}>
              Unlock
            </button>
            <button type="button" className="sm danger" onClick={() => bulk("remove")}>
              Remove
            </button>
            <button type="button" className="sm ghost" onClick={() => setSelected(new Set())}>
              Clear
            </button>
            <span className="muted small">{bulkOut}</span>
          </div>
        ) : null}
        <div className="tw mt">
          <table className="people">
            <thead>
              <tr>
                {manage ? (
                  <th className="sel">
                    <input
                      type="checkbox"
                      aria-label="Select everyone shown by the filters"
                      title="Select everyone shown by the filters"
                      checked={pickable.length > 0 && pickable.every((u) => selected.has(u.id))}
                      onChange={(e) => {
                        const next = new Set(selected);
                        for (const u of pickable) if (e.target.checked) next.add(u.id);
                        else next.delete(u.id);
                        setSelected(next);
                      }}
                    />
                  </th>
                ) : null}
                <th>Person</th>
                <th>Role</th>
                <th>Team</th>
                <th>Status</th>
                <th>Last sign-in</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {shown.map((u) => {
                const [kind, label] = STATUS[u.status] ?? STATUS.active;
                return (
                  <tr key={u.id} className={selected.has(u.id) ? "picked" : undefined}>
                    {manage ? (
                      <td className="sel">
                        {u.manageable ? (
                          <input
                            type="checkbox"
                            aria-label={`Select ${u.name}`}
                            checked={selected.has(u.id)}
                            onChange={(e) => {
                              const next = new Set(selected);
                              if (e.target.checked) next.add(u.id);
                              else next.delete(u.id);
                              setSelected(next);
                            }}
                          />
                        ) : null}
                      </td>
                    ) : null}
                    <td>
                      <div className="flex nowrap">
                        <Avatar name={u.name} />
                        <div>
                          <b>{u.name}</b>
                          {u.you ? (
                            <>
                              {" "}
                              <span className="chip">You</span>
                            </>
                          ) : null}
                          <span className="sub">
                            {u.email}
                            {u.title ? ` · ${u.title}` : ""}
                          </span>
                        </div>
                      </div>
                    </td>
                    <td>
                      {u.manageable ? (
                        <select className="inline-sel" title={`Change ${u.name}’s role`} value={u.role} onChange={(e) => inline(u, "role", e.target.value, e.target.selectedOptions[0].textContent ?? "")}>
                          {roles.some((r) => r.id === u.role) ? null : <option value={u.role}>{u.roleName}</option>}
                          {roles.map((r) => (
                            <option key={r.id} value={r.id}>
                              {r.name}
                            </option>
                          ))}
                        </select>
                      ) : (
                        <span className="chip role">{u.roleName}</span>
                      )}
                      {u.leads.length ? <span className="sub">Leads {u.leads.join(", ")}</span> : null}
                    </td>
                    <td title={u.teamPath}>
                      {u.manageable ? (
                        <select className="inline-sel" title={`Move ${u.name} to another team`} value={u.teamId ?? ""} onChange={(e) => inline(u, "team", e.target.value, e.target.selectedOptions[0].textContent ?? "")}>
                          <option value="">No team</option>
                          {teams.map((t) => (
                            <option key={t.id} value={t.id}>
                              {t.path}
                            </option>
                          ))}
                        </select>
                      ) : (
                        u.team || "—"
                      )}
                      {u.manager ? <span className="sub">Reports to {u.manager}</span> : null}
                    </td>
                    <td title={`Signs in with ${u.signIn === "sso" ? "single sign-on" : "a password"}`}>
                      <span className={`chip ${kind}`}>
                        <i />
                        {label}
                      </span>
                      {u.lockedUntil ? <span className="sub">until {new Date(u.lockedUntil).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span> : null}
                    </td>
                    <td className="small">{ago(u.lastSignInAt)}</td>
                    <td className="actions">
                      {u.manageable ? (
                        <button type="button" className="btn sm" aria-label={`Manage ${u.name}`} onClick={() => setPerson(u)}>
                          Manage
                        </button>
                      ) : null}
                    </td>
                  </tr>
                );
              })}
              {!shown.length ? (
                <tr>
                  <td colSpan={manage ? 7 : 6}>
                    <div className="empty">
                      <b>Nobody matches</b>
                    </div>
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
        </div>
        {pages > 1 ? (
          <div className="flex pager">
            <span className="muted small">
              Page {current + 1} of {pages}
            </span>
            <span className="spacer" />
            <button className="sm" type="button" disabled={current === 0} onClick={() => setPage(current - 1)}>
              Previous
            </button>
            <button className="sm" type="button" disabled={current >= pages - 1} onClick={() => setPage(current + 1)}>
              Next
            </button>
          </div>
        ) : null}
      </div>
      {person ? <PersonDrawer d={d} u={person} onClose={() => setPerson(null)} reload={reload} onTemporary={(t) => setTemporary(t)} /> : null}
      {temporary ? (
        <Dialog
          title="New temporary password"
          onClose={() => setTemporary(null)}
          footer={
            <button className="primary" type="button" onClick={() => setTemporary(null)}>
              Done
            </button>
          }
        >
          <p className="small muted">For {temporary.email}. Give it to them over a channel only they read: it is shown once, and they choose their own at sign-in.</p>
          <div className="secret">{temporary.password}</div>
        </Dialog>
      ) : null}
    </>
  );
}

function AddForm({ d, onDone, onCancel }: { d: IamView; onDone: () => Promise<void>; onCancel: () => void }) {
  const roles = d.roles.filter((r) => r.grantable);
  const teams = [...d.teams].sort((a, b) => a.path.localeCompare(b.path));
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [secret, setSecret] = useState<{ email: string; temporary: string | null; welcomed: boolean; existing: boolean } | null>(null);
  const submit = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const form = e.currentTarget;
    const f = new FormData(form);
    try {
      const r = await api.iamAddPerson({ email: f.get("email"), name: f.get("name"), title: f.get("title"), role: f.get("role"), teamId: f.get("team") || null, password, sendWelcome: f.get("welcome") === "on" });
      setErr("");
      setSecret({ email: r.user.email, temporary: r.temporary, welcomed: r.welcomed, existing: r.existingAccount });
      form.reset();
      setPassword("");
      await onDone();
    } catch (error) {
      setErr(said(error));
    }
  };
  return (
    <form className="form add-form" id="add" autoComplete="off" onSubmit={submit}>
      <div className="row">
        <label className="f">
          Work email
          <input name="email" type="email" required />
        </label>
        <label className="f">
          Name
          <input name="name" maxLength={120} />
        </label>
        <label className="f">
          Title
          <input name="title" maxLength={120} placeholder="Security Analyst" />
        </label>
      </div>
      <div className="row">
        <label className="f">
          Role
          <select name="role" defaultValue={roles.some((r) => r.id === "viewer") ? "viewer" : roles[0]?.id}>
            {roles.map((r) => (
              <option key={r.id} value={r.id}>
                {r.name}
              </option>
            ))}
          </select>
        </label>
        <label className="f">
          Team
          <select name="team" defaultValue={d.me.teamId ?? ""}>
            {can(d, "scope.all") ? <option value="">No team</option> : null}
            {teams.map((t) => (
              <option key={t.id} value={t.id}>
                {t.path}
              </option>
            ))}
          </select>
        </label>
        <label className="f">
          Temporary password <span className="muted">blank: one is made</span>
          <span className="flex nowrap">
            <input name="password" autoComplete="off" spellCheck={false} placeholder="They choose their own at first sign-in" value={password} onChange={(e) => setPassword(e.target.value)} />
            <button type="button" className="sm" onClick={() => setPassword(generatePassword())}>
              Generate
            </button>
          </span>
        </label>
      </div>
      <label className="check">
        <input type="checkbox" name="welcome" defaultChecked={d.mail} disabled={!d.mail} />
        <span>
          Email them a welcome
          <small>{d.mail ? 'Where to sign in, and how to set their password with "Forgot your password?". The temporary password is never emailed.' : "Needs the email server (Settings → Sign-in)."}</small>
        </span>
      </label>
      <div className="flex">
        <button className="primary" type="submit">
          Add person
        </button>
        <button type="button" className="ghost" onClick={onCancel}>
          Cancel
        </button>
        <span className="err">{err}</span>
      </div>
      {secret ? (
        <div className="callout mt">
          {secret.temporary ? (
            <>
              <b>{secret.email} can sign in with this temporary password</b>
              <p className="small muted">
                Give it to them over a channel only they read; it is shown once and they choose their own at first sign-in.{secret.welcomed ? " A welcome email is on its way." : ""}
              </p>
              <div className="secret">{secret.temporary}</div>
            </>
          ) : (
            <b>{secret.email} already has a Hawk AI account: they sign in here with the password they have.</b>
          )}
        </div>
      ) : null}
    </form>
  );
}

function PersonDrawer({ d, u, onClose, reload, onTemporary }: { d: IamView; u: IamPerson; onClose: () => void; reload: () => Promise<void>; onTemporary: (t: { email: string; password: string }) => void }) {
  const self = u.you;
  const roles = d.roles.filter((x) => x.grantable || x.id === u.role);
  const teams = [...d.teams].sort((a, b) => a.path.localeCompare(b.path));
  const [kind, label] = STATUS[u.status] ?? STATUS.active;
  const [role, setRole] = useState(u.role);
  const [err, setErr] = useState("");
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  const save = async (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    const body: Record<string, unknown> = { title: f.get("title"), teamId: f.get("team") || null };
    if (f.get("name") !== u.name) body.name = f.get("name");
    if (String(f.get("email") || "").toLowerCase() !== u.email.toLowerCase()) body.email = f.get("email");
    if (!self && role !== u.role) body.role = role;
    if ((f.get("manager") || null) !== (u.managerId ?? null)) body.managerId = f.get("manager") || null;
    try {
      await api.iamChangePerson(u.id, body);
      toast.success(body.email ? "Saved. Both the old and the new address are told about the new sign-in email." : "Saved.");
      onClose();
      await reload();
    } catch (error) {
      setErr(said(error));
    }
  };
  const act = async (what: string) => {
    try {
      if (what === "reset") {
        if (!window.confirm(`Give ${u.name} a new temporary password? Their current one stops working and they are signed out everywhere.`)) return;
        const r = await api.iamPersonAction(u.id, "reset");
        onClose();
        onTemporary({ email: u.email, password: r.temporary ?? "" });
        await reload();
        return;
      }
      if (what === "unlock") await api.iamPersonAction(u.id, "unlock");
      if (what === "two-step") {
        if (!window.confirm(`Reset two-step sign-in for ${u.email}? They set it up again at their next sign-in.`)) return;
        await api.iamPersonAction(u.id, "two-step-reset");
      }
      if (what === "signout") {
        if (!window.confirm(`Sign ${u.name} out on every device?`)) return;
        await api.iamPersonAction(u.id, "signout");
      }
      if (what === "toggle") {
        if (u.active && !window.confirm(`Turn off ${u.name}'s access? They are signed out at once.`)) return;
        await api.iamChangePerson(u.id, { active: !u.active });
      }
      if (what === "remove") {
        if (!window.confirm(`Remove ${u.name} from this tenant?`)) return;
        await api.iamRemovePerson(u.id);
      }
      toast.success("Done.");
      onClose();
      await reload();
    } catch (error) {
      toast.error(said(error));
    }
  };
  const Action = ({ what, title, text, danger }: { what: string; title: string; text: string; danger?: boolean }) => (
    <button type="button" className={`person-act ${danger ? "danger" : ""}`} onClick={() => act(what)}>
      <b>{title}</b>
      <span>{text}</span>
    </button>
  );
  return (
    <div className="drawer-wrap" id="person-drawer">
      <div className="drawer-shade" onClick={onClose} />
      <aside className="drawer half" role="dialog" aria-modal="true" aria-label={`Manage ${u.name}`}>
        <button type="button" className="drawer-close" title="Close (Esc)" aria-label="Close" onClick={onClose}>
          ✕
        </button>
        <div className="person-head">
          <Avatar name={u.name} />
          <div>
            <h1 className="serif">
              {u.name}
              {self ? (
                <>
                  {" "}
                  <span className="chip">You</span>
                </>
              ) : null}
            </h1>
            <p className="muted">
              {u.email}
              {u.title ? ` · ${u.title}` : ""}
            </p>
            <p className="person-meta">
              <span className={`chip ${kind}`}>
                <i />
                {label}
              </span>
              <span className="chip role">{u.roleName}</span>
              <span>{u.teamPath || u.team || "No team"}</span>
              <span className="muted">
                Last sign-in {ago(u.lastSignInAt)} · {u.signIn === "sso" ? "single sign-on" : "password"} · two-step {u.twoStep ? "on" : "off"}
              </span>
            </p>
            <p className="person-meta">
              {u.manager ? (
                <span>
                  Reports to <b>{u.manager}</b>
                </span>
              ) : (
                <span className="muted">Reports to nobody yet</span>
              )}
              {u.reports.length ? (
                <span className="muted">
                  · {u.reports.length} {u.reports.length === 1 ? "person reports" : "people report"} to them: {u.reports.slice(0, 6).map((x) => x.name).join(", ")}
                  {u.reports.length > 6 ? "…" : ""}
                </span>
              ) : null}
            </p>
          </div>
        </div>
        <div className="panel mt">
          <h2>Name, email, role, team and manager</h2>
          <form className="form" id="person-form" onSubmit={save}>
            <div className="row">
              <label className="f">
                Name
                <input name="name" required maxLength={120} defaultValue={u.name} />
              </label>
              <label className="f">
                Title
                <input name="title" maxLength={120} defaultValue={u.title} placeholder="Security Analyst" />
              </label>
            </div>
            <label className="f">
              Sign-in email <span className="muted">both the old and the new address are told when it changes</span>
              <input name="email" type="email" required defaultValue={u.email} />
            </label>
            <div className="row">
              <label className="f">
                Role
                <select name="role" value={role} disabled={self} title={self ? "Your own role is changed by someone else" : undefined} onChange={(e) => setRole(e.target.value)}>
                  {roles.map((x) => (
                    <option key={x.id} value={x.id}>
                      {x.name}
                    </option>
                  ))}
                </select>
              </label>
              <label className="f">
                Team
                <select name="team" defaultValue={u.teamId ?? ""}>
                  <option value="">No team</option>
                  {teams.map((t) => (
                    <option key={t.id} value={t.id}>
                      {t.path}
                    </option>
                  ))}
                </select>
              </label>
            </div>
            <label className="f">
              Reports to <span className="muted">their manager: sets the reporting hierarchy</span>
              <select name="manager" defaultValue={u.managerId ?? ""}>
                <option value="">Nobody</option>
                {d.managers
                  .filter((m) => m.id !== u.id)
                  .map((m) => (
                    <option key={m.id} value={m.id}>
                      {m.name}
                      {m.title ? ` · ${m.title}` : ""}
                    </option>
                  ))}
              </select>
            </label>
            <p className="muted small">{roles.find((x) => x.id === role)?.description ?? ""}</p>
            <div className="flex">
              <button className="primary" type="submit">
                Save
              </button>
              <span className="err">{err}</span>
            </div>
          </form>
        </div>
        <div className="panel mt">
          <h2>Sign-in and access</h2>
          <div className="person-acts">
            <Action what="reset" title="Reset password" text="A new temporary password, shown once. Their current one stops working and they are signed out everywhere." />
            {u.status === "locked" ? <Action what="unlock" title="Unlock now" text="Locked after too many wrong passwords: let them try again at once." /> : null}
            {u.twoStep && !self ? <Action what="two-step" title="Reset two-step sign-in" text="Lost their phone and recovery codes: two-step sign-in is taken off and they set it up again." /> : null}
            <Action what="signout" title="Sign out everywhere" text="End every session they have open, on every device." />
            {self ? null : <Action what="toggle" title={u.active ? "Turn access off" : "Turn access on"} text={u.active ? "They are signed out at once and cannot sign in." : "They can sign in again, with the role and team above."} />}
            {self ? null : <Action what="remove" title="Remove" text="Take them out of this tenant. With no other tenant left, their account is turned off." danger />}
          </div>
          {can(d, "security.sso") ? (
            <p className="small muted mt">
              Single sign-on links and the rules for everyone are under <Link href="/settings/signin">Settings → Sign-in</Link>.
            </p>
          ) : null}
        </div>
      </aside>
    </div>
  );
}
