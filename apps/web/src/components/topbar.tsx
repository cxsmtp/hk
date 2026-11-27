"use client";

import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { Bell, ChevronDown, ExternalLink, LogOut, Settings2, UserRound } from "lucide-react";

import { getSession, SESSION_CHANGE_EVENT } from "@/lib/auth";
import { api, signOut } from "@/lib/api";
import type { DashboardNotificationItem } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { JumpTo } from "@/components/jump-to";
import { ThemeSwitch } from "@/components/theme-switch";
import { WorkspaceSwitch } from "@/components/workspace-switch";
import { SETTINGS_ENTRY, SPECIALIST_WORKSPACES } from "@/lib/navigation";

const ADMINISTRATION_ITEMS = SPECIALIST_WORKSPACES.find((group) => group.label === "Administration")?.items ?? [];

const DRILLDOWN_PRIORITY = [
  "chain_graph",
  "action_graph",
  "chain_evidence",
  "evidence",
  "traceability",
  "finding_detail",
  "agent_touchpoints",
  "action_trace",
  "default",
];

const NOTIFICATION_QUICK_DRILLDOWNS = [
  "chain_graph",
  "action_graph",
  "chain_evidence",
  "evidence",
  "traceability",
  "finding_detail",
  "agent_touchpoints",
  "action_trace",
];

function formatTimeAgo(value: string): string {
  const parsed = Date.parse(value);
  if (!Number.isFinite(parsed)) return "just now";
  const diffMs = Date.now() - parsed;
  if (diffMs < 60_000) return "just now";
  const mins = Math.floor(diffMs / 60_000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function severityChipClass(value: string): string {
  const sev = String(value || "").toLowerCase();
  if (sev === "critical") return "border-red-900 bg-red-950/40 text-red-300";
  if (sev === "high") return "border-rose-900 bg-rose-950/40 text-rose-300";
  if (sev === "med") return "border-amber-900 bg-amber-950/40 text-amber-300";
  return "border-emerald-900 bg-emerald-950/40 text-emerald-300";
}

function notificationAccentClass(value: string): string {
  const sev = String(value || "").toLowerCase();
  if (sev === "critical") return "bg-red-400";
  if (sev === "high") return "bg-rose-400";
  if (sev === "med") return "bg-amber-400";
  return "bg-emerald-400";
}

function preferredNotificationHref(item: DashboardNotificationItem): string {
  if (item.primary_drilldown?.enabled !== false && item.primary_drilldown?.href) {
    return item.primary_drilldown.href;
  }
  if (item.investigation_link) {
    return item.investigation_link;
  }
  const drilldown = (item.drilldowns || [])
    .filter((entry) => entry.enabled !== false && entry.href)
    .sort((left, right) => {
      const leftIndex = DRILLDOWN_PRIORITY.indexOf(left.type);
      const rightIndex = DRILLDOWN_PRIORITY.indexOf(right.type);
      return (leftIndex === -1 ? DRILLDOWN_PRIORITY.length : leftIndex) - (rightIndex === -1 ? DRILLDOWN_PRIORITY.length : rightIndex);
    })[0];
  return drilldown?.href || item.link || "/discovery/findings";
}

function drilldownLabel(type: string, fallback: string): string {
  const labels: Record<string, string> = {
    action_graph: "Graph",
    action_trace: "Trace",
    agent_touchpoints: "Agent",
    chain_evidence: "Chain Evidence",
    chain_graph: "Chain",
    evidence: "Evidence",
    finding_detail: "Finding",
    traceability: "Traceability",
  };
  return labels[type] || fallback || type;
}

function quickNotificationDrilldowns(item: DashboardNotificationItem) {
  const seen = new Set<string>();
  return (item.drilldowns || [])
    .filter((entry) => entry.enabled !== false && entry.href && NOTIFICATION_QUICK_DRILLDOWNS.includes(entry.type))
    .sort((left, right) => {
      const leftIndex = NOTIFICATION_QUICK_DRILLDOWNS.indexOf(left.type);
      const rightIndex = NOTIFICATION_QUICK_DRILLDOWNS.indexOf(right.type);
      return leftIndex - rightIndex;
    })
    .filter((entry) => {
      const key = `${entry.type}:${entry.href}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    })
    .slice(0, 5);
}

export function Topbar({ leading }: { leading?: ReactNode } = {}) {
  const [email, setEmail] = useState<string>("");
  const [tenantId, setTenantId] = useState<string>("");
  const [role, setRole] = useState<string>("");
  const [notifications, setNotifications] = useState<DashboardNotificationItem[]>([]);
  const [notificationOpen, setNotificationOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const [lastViewedAt, setLastViewedAt] = useState<number>(0);
  const [notificationLoading, setNotificationLoading] = useState(false);
  const [tabVisible, setTabVisible] = useState<boolean>(() => (typeof document === "undefined" ? true : !document.hidden));
  const hubRef = useRef<HTMLDivElement | null>(null);
  const accountRef = useRef<HTMLDivElement | null>(null);
  const notificationsInFlightRef = useRef<Promise<void> | null>(null);
  const router = useRouter();

  const storageKey = useMemo(() => (tenantId ? `hawk.notifications.lastViewed.${tenantId}` : ""), [tenantId]);

  const refreshSessionHeader = useCallback(() => {
    const session = getSession();
    setEmail(session?.user?.email ?? "unknown");
    setTenantId(session?.tenantId ?? "no-tenant");
    setRole((session?.userRole || "viewer").toUpperCase());
  }, []);

  useEffect(() => {
    refreshSessionHeader();
    window.addEventListener(SESSION_CHANGE_EVENT, refreshSessionHeader);
    window.addEventListener("storage", refreshSessionHeader);
    return () => {
      window.removeEventListener(SESSION_CHANGE_EVENT, refreshSessionHeader);
      window.removeEventListener("storage", refreshSessionHeader);
    };
  }, [refreshSessionHeader]);

  useEffect(() => {
    if (!storageKey) {
      setLastViewedAt(0);
      return;
    }
    const raw = window.localStorage.getItem(storageKey);
    const parsed = Number(raw || 0);
    setLastViewedAt(Number.isFinite(parsed) ? parsed : 0);
  }, [storageKey]);

  const loadNotifications = useCallback(async (silent = false) => {
    if (notificationsInFlightRef.current) {
      return notificationsInFlightRef.current;
    }
    if (!silent) setNotificationLoading(true);
    const run = (async () => {
      try {
        const payload = await api.dashboardNotifications({ limit: 30, lookback_hours: 24 });
        setNotifications(payload.items || []);
      } catch {
        if (!silent) setNotifications([]);
      } finally {
        if (!silent) setNotificationLoading(false);
      }
    })();
    notificationsInFlightRef.current = run;
    try {
      await run;
    } finally {
      if (notificationsInFlightRef.current === run) {
        notificationsInFlightRef.current = null;
      }
    }
  }, []);

  useEffect(() => {
    const onVisibilityChange = () => setTabVisible(!document.hidden);
    document.addEventListener("visibilitychange", onVisibilityChange);
    return () => document.removeEventListener("visibilitychange", onVisibilityChange);
  }, []);

  useEffect(() => {
    if (!tabVisible) return undefined;
    loadNotifications().catch(() => undefined);
    const timer = window.setInterval(() => {
      if (!document.hidden) {
        loadNotifications(true).catch(() => undefined);
      }
    }, 10000);
    return () => window.clearInterval(timer);
  }, [loadNotifications, tabVisible]);

  useEffect(() => {
    if (!notificationOpen) return;
    const onClickAway = (event: MouseEvent) => {
      if (!hubRef.current) return;
      if (!hubRef.current.contains(event.target as Node)) {
        setNotificationOpen(false);
      }
    };
    window.addEventListener("mousedown", onClickAway);
    return () => window.removeEventListener("mousedown", onClickAway);
  }, [notificationOpen]);

  useEffect(() => {
    if (!accountOpen) return;
    const onClickAway = (event: MouseEvent) => {
      if (!accountRef.current?.contains(event.target as Node)) {
        setAccountOpen(false);
      }
    };
    window.addEventListener("mousedown", onClickAway);
    return () => window.removeEventListener("mousedown", onClickAway);
  }, [accountOpen]);

  const unreadCount = useMemo(
    () =>
      notifications.filter((item) => {
        const created = Date.parse(item.created_at);
        return Number.isFinite(created) && created > lastViewedAt;
      }).length,
    [notifications, lastViewedAt]
  );

  const criticalCount = useMemo(
    () => notifications.filter((item) => String(item.severity || "").toLowerCase() === "critical").length,
    [notifications]
  );

  const openNotificationHub = useCallback(() => {
    const now = Date.now();
    setNotificationOpen((current) => !current);
    setLastViewedAt(now);
    if (storageKey) {
      window.localStorage.setItem(storageKey, String(now));
    }
  }, [storageKey]);

  const openNotification = useCallback(
    (item: DashboardNotificationItem) => {
      setNotificationOpen(false);
      const now = Date.now();
      setLastViewedAt(now);
      if (storageKey) {
        window.localStorage.setItem(storageKey, String(now));
      }
      router.push(preferredNotificationHref(item));
    },
    [router, storageKey]
  );

  return (
    <header className="hawk-topbar sticky top-0 z-30 flex items-center justify-between gap-2 border-b border-[#1e2433] bg-[#0e1018]/90 px-3 py-2.5 sm:px-6 lg:py-3.5">
      <div className="flex min-w-0 flex-1 items-center gap-3">
        {leading}
        <div className="hidden min-w-0 lg:block">
          <p className="text-[10px] uppercase tracking-[0.14em] text-slate-500">Tenant</p>
          <p className="truncate font-mono text-xs text-slate-300">{tenantId}</p>
        </div>
      </div>
      <div className="flex shrink-0 items-center gap-2 sm:gap-3">
        <JumpTo />
        <div className="relative" ref={hubRef}>
          <button
            type="button"
            onClick={openNotificationHub}
            className="relative inline-flex h-10 items-center gap-2 rounded-md border border-[#2a3348] bg-transparent px-3 text-sm font-semibold text-slate-200 transition-colors hover:border-brand-500/40 hover:bg-brand-500/10"
            title="Open notification hub"
            aria-label="Alerts"
          >
            <Bell className="h-4 w-4" />
            <span className="hidden sm:inline">Alerts</span>
            {unreadCount > 0 ? (
              <span className="inline-flex h-5 min-w-5 items-center justify-center rounded-full bg-red-500 px-1 text-[11px] font-bold text-white">
                {unreadCount > 99 ? "99+" : unreadCount}
              </span>
            ) : null}
          </button>
          {notificationOpen ? (
            <div className="absolute right-0 top-12 z-50 w-[25rem] overflow-hidden max-sm:fixed max-sm:inset-x-3 max-sm:top-[3.75rem] max-sm:w-auto rounded-[22px] border border-[#263047] bg-[#0b1220] shadow-2xl">
              <div className="border-b border-[#1e2433] px-4 py-4">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">Alerts</p>
                    <p className="mt-1 text-xs text-slate-400">
                      {notificationLoading ? "Refreshing alerts..." : `${notifications.length} recent alerts`}
                    </p>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => loadNotifications().catch(() => undefined)}
                  >
                    Refresh
                  </Button>
                </div>
                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <span className="rounded-full border border-[#263047] bg-[#111827] px-2.5 py-1 text-[11px] font-medium text-slate-300">
                    {unreadCount} new
                  </span>
                  <span className="rounded-full border border-red-900/60 bg-red-950/25 px-2.5 py-1 text-[11px] font-medium text-red-300">
                    {criticalCount} critical
                  </span>
                </div>
              </div>

              <div className="max-h-[min(26rem,60dvh)] space-y-1 overflow-y-auto overscroll-contain px-2 py-2">
                {notifications.length === 0 ? (
                  <div className="m-2 rounded-xl border border-dashed border-[#334155] bg-[#0f172a] px-3 py-5 text-center text-sm text-slate-400">
                    No alerts yet for this tenant.
                  </div>
                ) : (
                  notifications.slice(0, 12).map((item) => {
                    const quickDrilldowns = quickNotificationDrilldowns(item);
                    return (
                      <div
                        key={item.notification_id}
                        className="group grid w-full grid-cols-[auto_minmax(0,1fr)_auto] items-start gap-3 rounded-2xl border border-transparent px-3 py-3 text-left transition-colors hover:border-brand-500/25 hover:bg-white/[0.03]"
                      >
                        <span className={`mt-1.5 h-2.5 w-2.5 rounded-full ${notificationAccentClass(item.severity)}`} />
                        <div className="min-w-0">
                          <button type="button" onClick={() => openNotification(item)} className="block w-full text-left">
                            <div className="flex flex-wrap items-center gap-2">
                              <span className={`rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-[0.08em] ${severityChipClass(item.severity)}`}>
                                {item.severity}
                              </span>
                              {item.source_surface ? (
                                <span className="rounded-full bg-[#111827] px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-slate-400">
                                  {item.source_surface}
                                </span>
                              ) : null}
                              {item.control_mode ? (
                                <span className="rounded-full bg-[#111827] px-2 py-0.5 text-[10px] uppercase tracking-[0.08em] text-slate-400">
                                  {item.control_mode}
                                </span>
                              ) : null}
                            </div>
                            <p className="mt-2 line-clamp-1 text-sm font-semibold text-slate-100">{item.title}</p>
                            <p className="mt-1 line-clamp-2 text-xs leading-5 text-slate-400">{item.summary}</p>
                          </button>
                          <div className="mt-2 flex flex-wrap items-center gap-1.5 text-[11px] text-slate-500">
                            {item.actor_label ? <span className="rounded-full bg-[#111827] px-2 py-0.5">{item.actor_label}</span> : null}
                            {item.endpoint_label ? <span className="rounded-full bg-[#111827] px-2 py-0.5">{item.endpoint_label}</span> : null}
                            {item.decision_badge ? <span className="rounded-full bg-[#111827] px-2 py-0.5">{item.decision_badge}</span> : null}
                          </div>
                          {quickDrilldowns.length ? (
                            <div className="mt-3 flex flex-wrap gap-1.5">
                              {item.primary_drilldown ? (
                                <button
                                  type="button"
                                  onClick={() => openNotification(item)}
                                  className="rounded-md border border-brand-500/40 bg-brand-500/10 px-2 py-1 text-[11px] font-semibold text-brand-200 transition hover:border-brand-400/70 hover:text-white"
                                  title={`Open ${drilldownLabel(item.primary_drilldown.type, item.primary_drilldown.label)}`}
                                >
                                  Open investigation
                                </button>
                              ) : null}
                              {quickDrilldowns.map((drilldown) => (
                                <button
                                  key={`${item.notification_id}-${drilldown.type}-${drilldown.href}`}
                                  type="button"
                                  onClick={() => {
                                    setNotificationOpen(false);
                                    router.push(drilldown.href);
                                  }}
                                  className="rounded-md border border-[#263047] bg-[#0f172a] px-2 py-1 text-[11px] font-semibold text-slate-300 transition hover:border-brand-500/40 hover:text-white"
                                >
                                  {drilldownLabel(drilldown.type, drilldown.label)}
                                </button>
                              ))}
                            </div>
                          ) : null}
                        </div>
                        <button type="button" onClick={() => openNotification(item)} className="flex items-center gap-3 pl-2">
                          <span className="whitespace-nowrap text-[11px] font-mono text-slate-500">{formatTimeAgo(item.created_at)}</span>
                          <ExternalLink className="h-3.5 w-3.5 text-slate-500 transition group-hover:text-slate-200" />
                        </button>
                      </div>
                    );
                  })
                )}
              </div>

              <div className="border-t border-[#1e2433] px-4 py-3">
                <div>
                  <button
                    type="button"
                    onClick={() => {
                      setNotificationOpen(false);
                      router.push("/discovery/findings");
                    }}
                    className="text-xs font-medium uppercase tracking-[0.08em] text-slate-300 transition hover:text-white"
                  >
                    Open full findings queue
                  </button>
                </div>
              </div>
            </div>
          ) : null}
        </div>
        <div className="relative" ref={accountRef}>
          <button
            type="button"
            onClick={() => setAccountOpen((current) => !current)}
            className="inline-flex h-10 items-center gap-2 rounded-md border border-[#2a3348] bg-transparent px-3 text-left text-sm text-slate-200 transition-colors hover:border-brand-500/40 hover:bg-brand-500/10"
            aria-expanded={accountOpen}
            aria-label="Account and administration"
          >
            <UserRound className="h-4 w-4" />
            <span className="hidden max-w-40 truncate lg:inline">{email}</span>
            <span className="rounded border border-brand-500/40 bg-brand-500/15 px-2 py-0.5 text-[9px] font-semibold tracking-[0.08em] text-brand-300">
              {role}
            </span>
            <ChevronDown className={`hidden h-3.5 w-3.5 text-slate-500 transition sm:block ${accountOpen ? "rotate-180" : ""}`} />
          </button>
          {accountOpen ? (
            <div className="absolute right-0 top-12 z-50 w-[min(calc(100vw-1.5rem),18rem)] overflow-hidden rounded-2xl border border-[#263047] bg-[#0b1220] shadow-2xl">
              <div className="border-b border-[#1e2433] px-4 py-3">
                <p className="truncate text-sm font-semibold text-white">{email}</p>
                <p className="mt-1 truncate font-mono text-[10px] text-slate-500">{tenantId}</p>
              </div>
              <div className="p-2">
                <p className="px-2 py-1.5 text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-600">Administration</p>
                <Link
                  href={SETTINGS_ENTRY.href}
                  onClick={() => setAccountOpen(false)}
                  className="flex items-center gap-2 rounded-lg px-2 py-2 text-xs text-slate-300 transition hover:bg-white/[0.05] hover:text-white"
                >
                  <Settings2 className="h-3.5 w-3.5 text-slate-500" />
                  {SETTINGS_ENTRY.label}
                </Link>
                {ADMINISTRATION_ITEMS.map((item) => (
                  <Link
                    key={item.href}
                    href={item.href}
                    onClick={() => setAccountOpen(false)}
                    className="flex items-center gap-2 rounded-lg px-2 py-2 text-xs text-slate-300 transition hover:bg-white/[0.05] hover:text-white"
                  >
                    <Settings2 className="h-3.5 w-3.5 text-slate-500" />
                    {item.label}
                  </Link>
                ))}
              </div>
              <WorkspaceSwitch />
              <div className="border-t border-[#1e2433] p-2">
                <ThemeSwitch />
              </div>
              <div className="border-t border-[#1e2433] p-2">
                <button
                  type="button"
                  onClick={() => {
                    void signOut().finally(() => router.push("/login"));
                  }}
                  className="flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-xs font-semibold text-slate-300 transition hover:bg-red-500/10 hover:text-red-200"
                >
                  <LogOut className="h-3.5 w-3.5" />
                  Sign out
                </button>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </header>
  );
}
