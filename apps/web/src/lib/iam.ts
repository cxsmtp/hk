/**
 * People, teams and roles for Settings → People, Teams and Roles & permissions: the shapes GET /iam/people answers
 * with (apps/api/app/api/routers/iam.py) and the small rules FTR Command Center's public/js/people.js and teams.js
 * apply in the browser (status labels, filters, "Show only the differences", the team tree).
 */

export type IamPermission = { id: string; group: string; label: string; description: string; special: boolean };

export type IamRole = {
  id: string;
  name: string;
  description: string;
  permissions: string[];
  builtin: boolean;
  locked: boolean;
  grantable?: boolean;
  holders?: number;
};

export type IamPerson = {
  id: string;
  email: string;
  name: string;
  title: string;
  role: string;
  roleName: string;
  teamId: string | null;
  team: string;
  teamPath: string;
  leads: string[];
  managerId: string | null;
  manager: string;
  reports: { id: string; name: string }[];
  active: boolean;
  status: "active" | "locked" | "disabled" | "pending";
  lockedUntil: string | null;
  twoStep: boolean;
  signIn: "sso" | "password";
  createdAt: string | null;
  lastSignInAt: string | null;
  joined: { at: string | null; role: string | null; teamId: string | null; reviewedAt: string | null; reviewedBy: string | null } | null;
  manageable: boolean;
  you: boolean;
};

export type IamTeam = {
  id: string;
  name: string;
  region: string;
  parentId: string | null;
  leaderIds: string[];
  path: string;
  leaders: { id: string; name: string }[];
  members: number;
};

export type IamView = {
  people: IamPerson[];
  roles: IamRole[];
  teams: IamTeam[];
  permissions: IamPermission[];
  groups: string[];
  managers: { id: string; name: string; title: string }[];
  mail: boolean;
  me: { id: string; role: string; teamId: string | null; permissions: string[] };
  joinersToReview: number;
};

export type IamJoinSettings = {
  enabled: boolean;
  domains: string[];
  roles: string[];
  ready: { ready: boolean; missing: string[] };
  workspace: string;
  canChange: boolean;
  allRoles: { id: string; name: string; open: boolean }[];
  twoStepRequired: boolean;
};

export type JoinLink = {
  email: string;
  name: string;
  workspace: string;
  teams: { id: string; path: string }[];
  roles: { id: string; name: string; description: string }[];
  twoStepRequired: boolean;
};

/** FTR's STATUS: chip kind and label per status. */
export const STATUS: Record<IamPerson["status"], [string, string]> = {
  active: ["ok", "Active"],
  locked: ["bad", "Locked"],
  disabled: ["bad", "Off"],
  pending: ["warn", "Must set password"],
};

export const PAGE = 25;

export const can = (view: IamView | null, permission: string): boolean => Boolean(view?.me.permissions.includes(permission));

/** "3 minutes ago", as FTR's ago(). */
export function ago(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const seconds = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000);
  if (seconds < 60) return "Just now";
  const [n, unit] = seconds < 3600 ? [seconds / 60, "minute"] : seconds < 86400 ? [seconds / 3600, "hour"] : [seconds / 86400, "day"];
  const whole = Math.floor(n);
  return `${whole} ${unit}${whole === 1 ? "" : "s"} ago`;
}

export type PeopleFilters = { q: string; role: string; team: string; status: string; boss: string };

/** FTR's peopleTable list(): search, role, team, status and "Reports to" (everyone under someone, at every level). */
export function filterPeople(people: IamPerson[], f: PeopleFilters): IamPerson[] {
  const q = f.q.trim().toLowerCase();
  const under = new Set<string>();
  if (f.boss && f.boss !== "-") {
    const add = (id: string) => {
      for (const u of people) if (u.managerId === id && !under.has(u.id)) {
        under.add(u.id);
        add(u.id);
      }
    };
    add(f.boss);
  }
  return people
    .filter((u) => !f.boss || (f.boss === "-" ? !u.managerId : under.has(u.id)))
    .filter((u) => !q || [u.name, u.email, u.title, u.team].some((s) => String(s ?? "").toLowerCase().includes(q)))
    .filter((u) => (!f.role || u.role === f.role) && (!f.team || u.teamId === f.team) && (!f.status || u.status === f.status))
    .sort((a, b) => a.name.localeCompare(b.name));
}

/** The matrix rows FTR shows: by group, matching the search, and with "Show only the differences" those where the roles differ. */
export function matrixRows(permissions: IamPermission[], roles: IamRole[], draft: Record<string, Set<string>>, q: string, diff: boolean) {
  const query = q.trim().toLowerCase();
  const groups = [...new Set(permissions.map((p) => p.group))];
  return groups
    .map((group) => ({
      group,
      rows: permissions
        .filter((p) => p.group === group)
        .filter((p) => !query || `${p.label} ${p.description}`.toLowerCase().includes(query))
        .filter((p) => !diff || new Set(roles.map((r) => draft[r.id]?.has(p.id) ?? false)).size > 1),
    }))
    .filter((g) => g.rows.length);
}

/** The roles whose ticks differ from what is saved. */
export function changedRoles(roles: IamRole[], draft: Record<string, Set<string>>): IamRole[] {
  return roles.filter((r) => {
    const a = new Set(r.permissions);
    const b = draft[r.id] ?? new Set<string>();
    return a.size !== b.size || [...a].some((x) => !b.has(x));
  });
}

/** The teams as an indented tree (FTR's viewTeams walk): each with its depth, top teams first, by name. */
export function teamTree(teams: IamTeam[]): { team: IamTeam; depth: number }[] {
  const ids = new Set(teams.map((t) => t.id));
  const kids = (id: string | null) => teams.filter((t) => (t.parentId ?? null) === id).sort((a, b) => a.name.localeCompare(b.name));
  const out: { team: IamTeam; depth: number }[] = [];
  const seen = new Set<string>();
  const walk = (t: IamTeam, depth: number) => {
    if (seen.has(t.id)) return;
    seen.add(t.id);
    out.push({ team: t, depth });
    for (const k of kids(t.id)) walk(k, depth + 1);
  };
  for (const t of teams.filter((x) => !x.parentId || !ids.has(x.parentId)).sort((a, b) => a.name.localeCompare(b.name))) walk(t, 0);
  return out;
}

/** A strong temporary password that is easy to read out: 4 groups of 5 (FTR's Generate). */
export function generatePassword(): string {
  const a = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(20));
  return ([...bytes].map((x) => a[x % a.length]).join("").match(/.{5}/g) ?? []).join("-");
}

export const csvCell = (v: unknown): string => {
  const text = String(v ?? "");
  const safe = /^[=+\-@\t\r]/.test(text) ? `'${text}` : text;
  return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
};
