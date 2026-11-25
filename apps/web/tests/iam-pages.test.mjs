import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const source = (path) => readFileSync(new URL(`../src/${path}`, import.meta.url), "utf8");

async function loadIam() {
  const result = ts.transpileModule(source("lib/iam.ts"), {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
  });
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

const person = (over) => ({ id: "x", email: "x@a.test", name: "X", title: "", role: "viewer", roleName: "Viewer", teamId: null, team: "", teamPath: "", leads: [], managerId: null, manager: "", reports: [], active: true, status: "active", lockedUntil: null, twoStep: false, signIn: "password", createdAt: null, lastSignInAt: null, joined: null, manageable: true, you: false, ...over });

test("People filters are FTR's: search, role, team, status and everyone under a manager at every level", async () => {
  const { filterPeople, STATUS } = await loadIam();
  const people = [
    person({ id: "a", name: "Ann", role: "admin" }),
    person({ id: "b", name: "Bob", managerId: "a", teamId: "t1", status: "locked" }),
    person({ id: "c", name: "Cy", managerId: "b", title: "Analyst" }),
    person({ id: "d", name: "Di" }),
  ];
  const f = { q: "", role: "", team: "", status: "", boss: "" };
  assert.deepEqual(filterPeople(people, { ...f, boss: "a" }).map((u) => u.id), ["b", "c"]);
  assert.deepEqual(filterPeople(people, { ...f, boss: "-" }).map((u) => u.id), ["a", "d"]);
  assert.deepEqual(filterPeople(people, { ...f, q: "analyst" }).map((u) => u.id), ["c"]);
  assert.deepEqual(filterPeople(people, { ...f, status: "locked", team: "t1" }).map((u) => u.id), ["b"]);
  assert.deepEqual(filterPeople(people, { ...f, role: "admin" }).map((u) => u.id), ["a"]);
  assert.deepEqual(STATUS.disabled, ["bad", "Off"]);
  assert.deepEqual(STATUS.pending, ["warn", "Must set password"]);
});

test("the roles matrix shows only the differences when asked, and knows which roles changed", async () => {
  const { matrixRows, changedRoles } = await loadIam();
  const permissions = [
    { id: "a.view", group: "A", label: "See A", description: "", special: false },
    { id: "a.manage", group: "A", label: "Manage A", description: "", special: false },
    { id: "b.view", group: "B", label: "See B", description: "", special: true },
  ];
  const roles = [
    { id: "r1", name: "One", description: "", permissions: ["a.view", "b.view"], builtin: true, locked: false },
    { id: "r2", name: "Two", description: "", permissions: ["a.view", "a.manage", "b.view"], builtin: false, locked: false },
  ];
  const draft = { r1: new Set(roles[0].permissions), r2: new Set(roles[1].permissions) };
  assert.deepEqual(matrixRows(permissions, roles, draft, "", true).map((g) => [g.group, g.rows.map((p) => p.id)]), [["A", ["a.manage"]]]);
  assert.deepEqual(matrixRows(permissions, roles, draft, "see b", false).map((g) => g.group), ["B"]);
  assert.deepEqual(changedRoles(roles, draft), []);
  draft.r1.add("a.manage");
  assert.deepEqual(changedRoles(roles, draft).map((r) => r.id), ["r1"]);
});

test("the team tree walks top teams by name, children below with their depth", async () => {
  const { teamTree } = await loadIam();
  const t = (id, name, parentId = null) => ({ id, name, parentId, region: "", leaderIds: [], path: name, leaders: [], members: 0 });
  const rows = teamTree([t("n", "North", "e"), t("e", "EMEA", "g"), t("g", "Global"), t("a", "APAC", "g"), t("o", "Orphan", "gone")]);
  assert.deepEqual(rows.map((r) => [r.team.id, r.depth]), [["g", 0], ["a", 1], ["e", 1], ["n", 2], ["o", 0]]);
});

test("People, Teams and Roles copy FTR's pages and use the shared FTR stylesheet", () => {
  const people = source("app/settings/people/page.tsx");
  const teams = source("app/settings/teams/page.tsx");
  const roles = source("app/settings/roles/page.tsx");
  for (const page of [people, teams, roles]) assert.ok(page.includes('import "../ftr-settings.css";'));
  for (const text of ["Search people, emails, titles", "Reports to: anyone", "Joined, to review", "Approve", "Turn off", "Add person", "Email them a welcome", "Reset password", "Unlock now", "Sign out everywhere", "Reset two-step sign-in", "Turn access off", "Nobody matches", "New temporary password", "Settings → Sign-in"]) {
    assert.ok(people.includes(text), `people: ${text}`);
  }
  for (const text of ["New team", "Sits below", "Leaders", "No leader yet", "Remove team", "Nothing: a top team"]) assert.ok(teams.includes(text), `teams: ${text}`);
  for (const text of ["Find a permission", "Show only the differences", "Save role changes", "Discard", "New role", "Start from", "Admin only", "Rename"]) assert.ok(roles.includes(text), `roles: ${text}`);
  const css = source("app/settings/ftr-settings.css");
  for (const cls of [".matrix tr.grp td", ".node .twig", ".bulk-f", ".person-act", ".drawer.half", ".join-review", ".secret"]) assert.ok(css.includes(cls), cls);
});

test("People, Teams and Roles & permissions are in the Administration menu; joining is offered from sign-in", () => {
  const nav = (source("lib/navigation.ts") + source("lib/settings-menu.mjs"));
  for (const [href, label] of [["/settings/people", "People"], ["/settings/teams", "Teams"], ["/settings/roles", "Roles & permissions"]]) {
    assert.ok(nav.includes(`{ href: "${href}", label: "${label}" }`), href);
  }
  const login = source("app/login/page.tsx");
  assert.match(login, /api\.joinAvailable\(workspace\)/);
  assert.match(login, /New here, or no password yet\?/);
  const join = source("app/join/page.tsx");
  assert.match(join, /Finish joining/);
  assert.match(join, /window\.history\.replaceState\(null, "", window\.location\.pathname\)/);
  const signin = source("app/settings/signin/page.tsx");
  assert.match(signin, /<JoinSettingsPanel \/>/);
  assert.match(source("components/iam/join-settings-panel.tsx"), /Joining by themselves/);
});
