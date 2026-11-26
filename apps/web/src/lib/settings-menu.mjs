/**
 * The Settings menu, as FTR Command Center's (ftr-cc-dashboard CC-01.116.00, public/js/shell.js `settingsNav()` and
 * public/js/settings.js `ADMIN_TABS`): everything that is not a customer area, in one place, in groups. Each item is
 * shown only to those whose role allows it, as FTR filters by can(…); the System group only when one of its tabs that
 * needs a permission is allowed (About comes with it, as FTR's).
 *
 * Hawk's LICENSING group stands where FTR's PRICING does (Engines & rates and the vulnerability estimate are FTR's
 * own business); everything else is FTR's order and wording, with Hawk's own pages added where FTR has none
 * (Connector API activity for FTR's "CxOne API audit", Hands-off and Network & proxy among the System tabs, and the
 * Workflow group's AI system approvals).
 */

/** The entry in the main menu that opens Settings (FTR: "Settings" in the side menu, opening People). */
export const SETTINGS_ENTRY = { href: "/settings/people", label: "Settings" };

/** Every Settings page: its group, and the permission(s) it needs (any of them), or null for everyone. */
export const SETTINGS_GROUPS = [
  {
    label: "People",
    items: [
      { href: "/settings/people", label: "People" },
      { href: "/settings/teams", label: "Teams" },
      { href: "/settings/roles", label: "Roles & permissions" },
      { href: "/settings/signin", label: "Sign-in" },
    ],
  },
  {
    label: "Licensing",
    items: [
      { href: "/settings/activation", label: "Activation codes" },
    ],
  },
  {
    label: "Records",
    items: [
      { href: "/settings/audit", label: "Audit log" },
      { href: "/settings/connector-activity", label: "Connector API activity" },
    ],
  },
  {
    // Hawk's own: how AI systems are approved (app/api/routers/ai_system_approvals.py).
    label: "Workflow",
    items: [
      { href: "/settings/approvals", label: "AI system approvals" },
    ],
  },
  {
    label: "System",
    items: [
      { href: "/settings/general", label: "General" },
      { href: "/settings/branding", label: "Branding" },
      { href: "/settings/email", label: "Email (SMTP)" },
      { href: "/settings/sso", label: "Single sign-on" },
      { href: "/settings/https", label: "HTTPS" },
      { href: "/settings/updates", label: "Updates" },
      { href: "/settings/backups", label: "Backups & health" },
      { href: "/settings/hands-off", label: "Hands-off" },
      { href: "/settings/network", label: "Network & proxy" },
      { href: "/settings/help", label: "Get help" },
      { href: "/settings/guide", label: "Guide" },
      { href: "/settings/about", label: "About" },
    ],
  },
];

/**
 * Who may open each page: FTR's checks, with Hawk's permission for the pages FTR has none for. People is for everyone
 * (each sees the people of their teams); the System tabs are ADMIN_TABS' permissions.
 */
export const SETTINGS_PERMISSIONS = {
  "/settings/people": null,
  "/settings/teams": ["teams.manage", "dashboard.view"],
  "/settings/roles": ["users.manage", "roles.manage"],
  "/settings/signin": ["security.sso"],
  "/settings/activation": ["activation.manage"],
  "/settings/audit": ["audit.view"],
  "/settings/connector-activity": ["audit.view"],
  // The approval policy is changed by owners and admins (settings.manage); everyone who sees the inventory reads it
  // and decides the approvals their role may give.
  "/settings/approvals": ["settings.manage", "discovery.view"],
  "/settings/general": ["settings.manage"],
  "/settings/branding": ["settings.manage"],
  "/settings/email": ["settings.manage"],
  "/settings/sso": ["security.sso"],
  "/settings/https": ["security.https"],
  "/settings/updates": ["system.update"],
  "/settings/backups": ["backup.manage"],
  "/settings/hands-off": ["settings.manage"],
  "/settings/network": ["network.manage"],
  "/settings/help": ["support.manage"],
  // Hawk's administrator's guide (lib/guide): for everyone signed in, as About; Jump to lists it for everyone.
  "/settings/guide": null,
  "/settings/about": null,
};

/** May someone holding these permissions open this Settings page? */
export function mayOpen(href, permissions) {
  const needs = SETTINGS_PERMISSIONS[href];
  if (needs === undefined) return false;
  if (needs === null) return true;
  const held = new Set(permissions || []);
  return needs.some((p) => held.has(p));
}

/**
 * The menu for someone holding these permissions: the groups with the items they may open, empty groups left out.
 * The System group only when one of its tabs that needs a permission is theirs (FTR: `ADMIN_TABS.some(… p && can(p))`).
 */
export function settingsNav(permissions) {
  return SETTINGS_GROUPS.map((group) => {
    const items = group.items.filter((item) => mayOpen(item.href, permissions));
    if (group.label === "System" && !items.some((item) => SETTINGS_PERMISSIONS[item.href] !== null)) return { ...group, items: [] };
    return { ...group, items };
  }).filter((group) => group.items.length > 0);
}

/** Is this the page the menu item is for (or a page under it)? FTR: `here === href || here.startsWith(href + "/")`. */
export function isSettingsItemActive(pathname, href) {
  return pathname === href || pathname.startsWith(`${href}/`);
}

/** Jump to: every Settings page answers to "settings" and to its group's name, as well as to its own (FTR). */
export function settingsJumpEntries(permissions) {
  return settingsNav(permissions).flatMap((group) =>
    group.items.map((item) => ({ title: item.label, sub: `Settings · ${group.label}`, href: item.href })),
  );
}

/** Jump to's filter: every word typed must appear, in any order ("settings email", "audit"). */
export function jumpMatches(entries, query, limit = 40) {
  const words = String(query || "").trim().toLowerCase().split(/\s+/).filter(Boolean);
  return entries.filter((entry) => words.every((word) => `${entry.title} ${entry.sub}`.toLowerCase().includes(word))).slice(0, limit);
}
