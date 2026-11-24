export type LifecycleNavigationChild = {
  href: string;
  label: string;
  description: string;
};

export type LifecycleNavigationItem = {
  href: string;
  label: "Overview" | "Inventory" | "Activity" | "Policies" | "Deployments" | "Reports" | "Integrations";
  description: string;
  children?: readonly LifecycleNavigationChild[];
};

export const LIFECYCLE_NAV_ITEMS = [
  {
    href: "/dashboard/command-center",
    label: "Overview",
    description: "What needs attention now",
    children: [
      { href: "/dashboard/command-center", label: "Command center", description: "Recommendations and executive posture" },
    ],
  },
  {
    href: "/assets",
    label: "Inventory",
    description: "Systems, identities, and access",
    children: [
      { href: "/discovery/estate", label: "Estate overview", description: "Known, inferred and unknown estate" },
      { href: "/discovery/assets", label: "Asset records", description: "Canonical assets and evidence" },
      { href: "/discovery/ecosystems", label: "Provider relationships", description: "Providers, environments and relationships" },
      { href: "/ai-ecosystem", label: "Relationship map", description: "Visual AI footprint, policy and control context" },
      { href: "/discovery/unknown", label: "Unresolved AI", description: "Unresolved signals and hypotheses" },
      { href: "/discovery/scans", label: "Scans", description: "Scope, estimate, progress and results" },
      { href: "/ai-iam", label: "Identities & access", description: "Users, agents and service identities" },
      { href: "/users", label: "People", description: "AI usage, prompts, actions and evidence" },
      { href: "/discovery/findings", label: "Inventory gaps", description: "Unresolved discovery gaps" },
    ],
  },
  {
    href: "/observe",
    label: "Activity",
    description: "Events, decisions and evidence",
    children: [
      { href: "/observe", label: "Activity", description: "Governed events as they happen" },
      { href: "/ai-tools-usage", label: "AI Tools & Usage", description: "Provider, device, MCP and meeting control evidence" },
      { href: "/interaction-security", label: "Interaction Security", description: "Per-user and per-surface decisions" },
      { href: "/runtime-intelligence/overview", label: "Runtime Intelligence", description: "Agent and action context" },
      { href: "/monitoring", label: "Monitoring", description: "Platform telemetry and health" },
    ],
  },
  {
    href: "/protect",
    label: "Policies",
    description: "Policies, approvals and prevention",
    children: [
      { href: "/protect", label: "Policy Builder", description: "Build from business intent" },
      { href: "/maturity", label: "Maturity Curve", description: "Evidence to reviewed policy rollout" },
      { href: "/governance", label: "Governance & Approvals", description: "Review governed changes" },
      { href: "/policies", label: "Advanced Policies", description: "Inspect versions and rules" },
      { href: "/simulations", label: "Simulations", description: "Run safe control tests" },
    ],
  },
  {
    href: "/deploy",
    label: "Deployments",
    description: "Set up the four control methods",
    children: [
      { href: "/deploy", label: "Deployment Overview", description: "Control coverage and blind spots" },
      { href: "/surface-coverage", label: "Surface Coverage", description: "Inline, monitor-only and outside control" },
      { href: "/control-coverage/source-control/github-repository-boundary", label: "GitHub", description: "Connect repositories and govern AI access" },
    ],
  },
  {
    href: "/evidence",
    label: "Reports",
    description: "Proof, audit and traceability",
    children: [
      { href: "/evidence", label: "Evidence Overview", description: "Proof posture and freshness" },
      { href: "/auditor", label: "Automated Auditor", description: "Verify immutable evidence" },
      { href: "/auditor/conflicts", label: "Conflicts", description: "Resolve contradictory assertions" },
      { href: "/runtime-intelligence/activity-map", label: "Action Traces", description: "Follow identity-to-action paths" },
    ],
  },
  {
    href: "/integrations",
    label: "Integrations",
    description: "Connections and service health",
    children: [
      { href: "/integrations", label: "Integrations", description: "Connect and verify sources" },
      { href: "/monitoring", label: "System health", description: "Platform telemetry and health" },
      { href: "/ops/jobs", label: "Operations", description: "Inspect platform jobs" },
    ],
  },
] satisfies readonly LifecycleNavigationItem[];

export const SPECIALIST_WORKSPACES = [
  {
    label: "Operations",
    items: [
      { href: "/ops/jobs", label: "Operations Jobs" },
    ],
  },
  {
    label: "Administration",
    items: [
      { href: "/guided-demo", label: "Guided Demo" },
    ],
  },
] as const;

export function isLifecyclePathActive(pathname: string, href: string): boolean {
  if (href === "/dashboard/command-center") {
    return pathname === href || pathname === "/dashboard";
  }
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function isLifecycleItemActive(pathname: string, item: LifecycleNavigationItem): boolean {
  return isLifecyclePathActive(pathname, item.href)
    || Boolean(item.children?.some((child) => isLifecyclePathActive(pathname, child.href)));
}

function normalizeRole(value?: string): string {
  const role = (value || "").toLowerCase();
  if (role === "super" || role === "super_admin") return "owner";
  if (role === "user" || role === "member") return "viewer";
  return role || "viewer";
}

export function defaultRouteForRole(value?: string): string {
  const role = normalizeRole(value);
  if (role === "auditor") return "/evidence";
  if (role === "operator") return "/observe";
  if (role === "viewer") return "/assets";
  return "/dashboard/command-center";
}
