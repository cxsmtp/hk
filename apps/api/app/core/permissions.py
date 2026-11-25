"""What a person may do in a tenant: the permission catalogue and the built-in roles.

Ported from FTR Command Center's server/rbac.js (PERMISSIONS, DEFAULT_ROLES, ADMIN_ONLY) and CxMissionZero's
src/iam.js (the same lineage): a role is a set of permissions; nobody hands out more than they hold; the Admin-only
permissions stay with the locked roles.

Hawk's permissions group its routers by feature the way FTR groups its own (Projections, Dashboards, Administration…).
Each permission sits at one of five *levels*, which are exactly the checks Hawk made before roles were editable
(app/core/rbac.py ``require_role``):

  view     every role                              (min_role="viewer")
  inspect  operator, auditor, admin, owner         (min_role="operator" when reading; the auditor reads what operators read)
  operate  operator, admin, owner                  (min_role="operator" when changing; never the auditor)
  review   auditor, admin, owner                   (min_role="auditor"; the auditor's own reviews and exports)
  manage   admin, owner                            (min_role="admin")

A built-in role holds every permission whose level includes it, so on upgrade nobody gains or loses anything
(tests/test_iam_equivalence.py proves it route by route against the checks recorded before the change).
"""

from __future__ import annotations

from dataclasses import dataclass


VIEW, INSPECT, OPERATE, REVIEW, MANAGE = "view", "inspect", "operate", "review", "manage"

#: The built-in roles holding each level (before anyone edits a role).
LEVEL_ROLES: dict[str, frozenset[str]] = {
    VIEW: frozenset({"viewer", "operator", "auditor", "admin", "owner"}),
    INSPECT: frozenset({"operator", "auditor", "admin", "owner"}),
    OPERATE: frozenset({"operator", "admin", "owner"}),
    REVIEW: frozenset({"auditor", "admin", "owner"}),
    MANAGE: frozenset({"admin", "owner"}),
}


@dataclass(frozen=True)
class Permission:
    id: str
    group: str
    label: str
    description: str
    level: str
    #: Held by the locked roles (Owner, Admin) alone: never by another role, whoever builds it (FTR's ``special``).
    special: bool = False

    def view(self) -> dict[str, object]:
        return {"id": self.id, "group": self.group, "label": self.label, "description": self.description, "special": self.special}


def _p(pid: str, group: str, label: str, description: str, level: str, special: bool = False) -> Permission:
    return Permission(pid, group, label, description, level, special)


PERMISSIONS: tuple[Permission, ...] = (
    # ---- Overview ---------------------------------------------------------------------------------------------------
    _p("dashboard.view", "Overview", "See the dashboards", "The command center, its recommendations and the executive posture.", VIEW),
    _p("dashboard.tune", "Overview", "Tune decision explanations", "Record a tuning action on why a decision was made (owners, admins and auditors).", REVIEW),
    # ---- Assistant --------------------------------------------------------------------------------------------------
    _p("assistant.use", "Assistant", "Use the assistant", "Ask the assistant, read the knowledge base and the executive briefings.", VIEW),
    _p("assistant.operate", "Assistant", "Run agent actions", "Start orchestrations and actions the assistant proposes.", OPERATE),
    # ---- Inventory & discovery --------------------------------------------------------------------------------------
    _p("discovery.view", "Inventory & discovery", "See the inventory", "Estate, assets, providers, relationships, unresolved AI, scans and their results.", VIEW),
    _p("discovery.scan", "Inventory & discovery", "Run safe discovery scans", "Start and stop scans that only read (auditors may run them too).", INSPECT),
    _p("discovery.operate", "Inventory & discovery", "Work on the inventory", "Register AI systems, act on discovered AI and on external risk.", OPERATE),
    _p("discovery.review", "Inventory & discovery", "Review discovered AI", "Assign owners and review shadow AI (owners, admins and auditors).", REVIEW),
    _p("discovery.manage", "Inventory & discovery", "Manage discovery", "Promote and block applications, deep scans, source connections, surface sources and the evidence graph.", MANAGE),
    # ---- Findings ---------------------------------------------------------------------------------------------------
    _p("findings.view", "Findings", "See findings", "Inventory gaps and findings.", VIEW),
    _p("findings.operate", "Findings", "Work on findings", "Act on a finding.", OPERATE),
    _p("findings.review", "Findings", "Review findings", "Triage, accept and close findings (owners, admins and auditors).", REVIEW),
    _p("findings.manage", "Findings", "Manage findings", "Change findings beyond review.", MANAGE),
    # ---- Identities & people activity -------------------------------------------------------------------------------
    _p("identities.view", "Identities", "See identities and their AI use", "Users, agents and service identities, and each person's AI usage, prompts and actions.", VIEW),
    _p("identities.operate", "Identities", "Work on identities", "Act on an identity's access.", OPERATE),
    _p("identities.manage", "Identities", "Manage identities", "Change identity access, groups and what a person's view shows.", MANAGE),
    # ---- Activity & runtime -----------------------------------------------------------------------------------------
    _p("activity.view", "Activity", "See activity", "Governed events, AI tools and usage, runtime and action context, investigations.", VIEW),
    _p("activity.inspect", "Activity", "See transaction integrity", "Banking transaction integrity records.", INSPECT),
    _p("activity.operate", "Activity", "Act on activity", "Block and enforce on users, run investigations, runtime control and transaction checks.", OPERATE),
    _p("activity.manage", "Activity", "Manage AI tools and usage", "Change how AI tools and usage are governed.", MANAGE),
    # ---- Policies ---------------------------------------------------------------------------------------------------
    _p("policies.view", "Policies", "See policies", "Policies, versions and rules, the maturity curve, policy packs and contracts.", VIEW),
    _p("policies.inspect", "Policies", "See policy pack details", "Policy pack platform details for those who work on policies.", INSPECT),
    _p("policies.operate", "Policies", "Work on policies", "Draft and simulate policies, decide enforcement approvals, roll out recommendations.", OPERATE),
    _p("policies.review", "Policies", "Review enforcement", "Enforcement events and approvals (owners, admins and auditors).", REVIEW),
    _p("policies.manage", "Policies", "Publish and approve policies", "Publish, activate and approve policies, contracts and exceptions.", MANAGE),
    _p("simulations.view", "Policies", "See simulations", "Simulations and their results.", VIEW),
    _p("simulations.operate", "Policies", "Run simulations", "Run safe control tests.", OPERATE),
    _p("simulations.manage", "Policies", "Manage simulations", "Create and change simulations and their policies.", MANAGE),
    # ---- Deployments ------------------------------------------------------------------------------------------------
    _p("deployments.view", "Deployments", "See deployments", "Control coverage, surface coverage, native controls, the extension and endpoint agents.", VIEW),
    _p("deployments.inspect", "Deployments", "See endpoint agent details", "Endpoint agent details for those who deploy them.", INSPECT),
    _p("deployments.operate", "Deployments", "Work on deployments", "Refresh coverage, set up controls, enrol endpoints and repository boundaries.", OPERATE),
    _p("deployments.review", "Deployments", "Review coverage evidence", "Executive coverage assessments and their evidence (owners, admins and auditors).", REVIEW),
    _p("deployments.manage", "Deployments", "Manage deployments", "Change control methods, native controls, the extension and endpoint agents.", MANAGE),
    # ---- Gateway and integrations -----------------------------------------------------------------------------------
    _p("gateway.view", "Gateway & integrations", "See the gateway", "The LLM gateway and its decisions.", VIEW),
    _p("gateway.inspect", "Gateway & integrations", "See gateway sessions", "MCP sessions, tool fingerprints and exposure.", INSPECT),
    _p("gateway.operate", "Gateway & integrations", "Use the gateway", "Intercept, authorise and scan through the gateway.", OPERATE),
    _p("gateway.review", "Gateway & integrations", "Review the gateway", "The guardian enforcement matrix (owners, admins and auditors).", REVIEW),
    _p("gateway.manage", "Gateway & integrations", "Manage the gateway", "Decide on tool fingerprints and remove tools.", MANAGE),
    _p("integrations.inspect", "Gateway & integrations", "See Checkmarx One", "Projects, scans, results and reports from Checkmarx One.", INSPECT),
    _p("integrations.operate", "Gateway & integrations", "Use Checkmarx One", "Enforce policy and generate reports with Checkmarx One.", OPERATE),
    _p("integrations.review", "Gateway & integrations", "Review the Checkmarx One trail", "The Checkmarx One audit trail (owners, admins and auditors).", REVIEW),
    _p("integrations.manage", "Gateway & integrations", "Manage Checkmarx One", "Trigger scans, remediate and pull all data.", MANAGE),
    # ---- Evidence ---------------------------------------------------------------------------------------------------
    _p("evidence.view", "Evidence", "See evidence", "Evidence overview, the trust center and continuous assurance.", VIEW),
    _p("evidence.export", "Evidence", "Verify and export evidence", "The automated auditor: snapshots, exports, conflicts and challenges; the trust center's maturity and audit logs.", REVIEW),
    # ---- System health ----------------------------------------------------------------------------------------------
    _p("monitoring.view", "System health", "See system health", "Platform telemetry, connectors and health.", VIEW),
    _p("monitoring.operate", "System health", "Send signals", "Ingest signals and shadow events.", OPERATE),
    _p("monitoring.review", "System health", "Review drift and jobs", "Drift alerts, operations jobs and metrics (owners, admins and auditors).", REVIEW),
    _p("monitoring.manage", "System health", "Manage connectors", "Create, bootstrap and pull monitoring connectors.", MANAGE),
    # ---- Administration (FTR's own ids) -------------------------------------------------------------------------------
    _p("users.manage", "Administration", "Manage people", "Add people into the teams in their scope, give them a role and a team, reset their password and two-step sign-in, unlock them, sign them out, turn them off; review people who joined by themselves; never beyond their own permissions.", MANAGE),
    _p("roles.manage", "Administration", "Manage roles", "Create, rename, duplicate and change roles; never with permissions they do not hold.", MANAGE),
    _p("teams.manage", "Administration", "Manage teams", "Create, rename, move and remove teams and choose their leaders.", MANAGE),
    _p("scope.all", "Administration", "See every team", "Every team and the people in it, whatever team they are in.", MANAGE),
    _p("audit.view", "Administration", "See the audit log", "Who signed in, who changed what, the user activity log and the connector API activity.", REVIEW),
    _p("audit.export", "Administration", "Export the audit log", "Download the audit log, the activity log and the connector API activity (CSV, JSON Lines).", REVIEW),
    _p("support.manage", "Administration", "Answer support cases & enhancements", "See every support case of the tenant, answer them and move them on; the support settings. Everyone can raise their own and follow them.", MANAGE),
    _p("settings.manage", "Administration", "Settings", "The platform mode. Admin only.", MANAGE, True),
    _p("security.https", "Administration", "HTTPS and certificates", "Upload and replace the server certificate and move the server to HTTPS only. Admin only.", MANAGE, True),
    _p("security.sso", "Administration", "Sign-in and single sign-on", "Who may reset a forgotten password by email, two-step sign-in for everyone, single sign-on, the email server for links. Admin only.", MANAGE, True),
    _p("system.update", "Administration", "Updates and integrity", "Install new versions (checked against their checksums), roll back, and the software integrity check. Admin only.", MANAGE, True),
    _p("backup.manage", "Administration", "Backups and restore", "Take, download and restore backups (they hold every record and key). Admin only.", MANAGE, True),
    _p("activation.manage", "Administration", "Activation codes", "Apply the activation codes that set what the installation may use. Admin only.", MANAGE, True),
    _p("network.manage", "Administration", "Network and proxy", "The proxy and the hosts the server may call. Admin only.", MANAGE, True),
)

PERMISSION_BY_ID: dict[str, Permission] = {p.id: p for p in PERMISSIONS}
PERMISSION_IDS: tuple[str, ...] = tuple(p.id for p in PERMISSIONS)
#: Held by the Owner and Admin roles alone (FTR: HTTPS, single sign-on, updates, backups, settings).
ADMIN_ONLY: frozenset[str] = frozenset(p.id for p in PERMISSIONS if p.special)
GROUPS: tuple[str, ...] = tuple(dict.fromkeys(p.group for p in PERMISSIONS))

#: The built-in roles, highest first. Owner and Admin are locked: they always hold every permission. Rank decides who
#: may hand out (and manage people holding) Owner: only an Owner.
BUILTIN_ORDER: tuple[str, ...] = ("owner", "admin", "auditor", "operator", "viewer")
LOCKED_ROLES: frozenset[str] = frozenset({"owner", "admin"})


def default_permissions(role: str) -> frozenset[str]:
    """What a built-in role holds before anyone changes it: every permission whose level includes it."""

    return frozenset(p.id for p in PERMISSIONS if role in LEVEL_ROLES[p.level])


BUILTIN_ROLES: dict[str, dict[str, object]] = {
    "owner": {"name": "Owner", "description": "Everything, in this tenant: people, teams, roles, settings and every record. Only an Owner gives or takes the Owner role.", "locked": True},
    "admin": {"name": "Admin", "description": "Everything, in this tenant: people, teams, roles, settings and every record.", "locked": True},
    "auditor": {"name": "Auditor", "description": "Reads everything an Operator reads, never changes it; reviews evidence, findings and enforcement, and exports the audit log.", "locked": False},
    "operator": {"name": "Operator", "description": "Works day to day: runs scans and simulations, acts on activity, drafts policies and deploys controls. Not the Admin settings.", "locked": False},
    "viewer": {"name": "Viewer", "description": "Read only: the dashboards, inventory, activity, policies, deployments and evidence.", "locked": False},
}


def clean_permissions(values: object) -> list[str]:
    """Known permission ids only, once each, in catalogue order (FTR's cleanPermissions)."""

    wanted = {str(v) for v in values} if isinstance(values, (list, tuple, set, frozenset)) else set()
    return [pid for pid in PERMISSION_IDS if pid in wanted]


def legacy_floor(permissions: frozenset[str] | set[str], role_key: str) -> str:
    """The highest built-in role every one of whose default permissions this role holds: what code that still reasons in
    role names (the assistant's tools, the MCP bridges) is told. Never more than the role holds. '' when it holds less
    than a Viewer."""

    if role_key in LOCKED_ROLES and set(PERMISSION_IDS) <= set(permissions):
        return role_key
    for role in ("operator", "auditor", "viewer"):
        if default_permissions(role) <= set(permissions):
            return role
    return ""
