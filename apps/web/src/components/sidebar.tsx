"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  Activity,
  Boxes,
  ChevronDown,
  FileCheck2,
  Home,
  MoreHorizontal,
  PanelLeftClose,
  PanelLeftOpen,
  Plug,
  Rocket,
  Settings,
  ShieldCheck,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import { useEffect, useState } from "react";

import { cn } from "@/lib/utils";
import {
  isLifecycleItemActive,
  isLifecyclePathActive,
  LIFECYCLE_NAV_ITEMS,
  SETTINGS_ENTRY,
  SPECIALIST_WORKSPACES,
} from "@/lib/navigation";
import { brandingImage, useBranding } from "@/lib/settings-console";

const SIDEBAR_COLLAPSE_KEY = "hawk_ui_sidebar_collapsed";

const ICONS: Record<(typeof LIFECYCLE_NAV_ITEMS)[number]["label"], LucideIcon> = {
  Overview: Home,
  Inventory: Boxes,
  Activity,
  Policies: ShieldCheck,
  Deployments: Rocket,
  Reports: FileCheck2,
  Integrations: Plug,
};

export function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  // Settings → Branding: the name, the line under it and the logo (FTR brandHtml()).
  const brand = useBranding();
  const logo = brandingImage(brand.logo);
  const inSettings = pathname.startsWith("/settings/");

  useEffect(() => {
    try {
      setCollapsed(window.localStorage.getItem(SIDEBAR_COLLAPSE_KEY) === "1");
    } catch {
      setCollapsed(false);
    }
  }, []);

  function setSidebarCollapsed(next: boolean) {
    setCollapsed(next);
    try {
      window.localStorage.setItem(SIDEBAR_COLLAPSE_KEY, next ? "1" : "0");
    } catch {
      // Local preference only. Navigation remains fully usable without storage.
    }
  }

  return (
    <aside
      className={cn(
        "sticky top-0 hidden h-screen shrink-0 border-r border-white/[0.07] bg-[#090c11]/95 px-3 py-4 backdrop-blur-xl lg:flex lg:flex-col",
        "transition-[width] duration-200",
        collapsed ? "w-[5.25rem]" : "w-[17.5rem]",
      )}
      aria-label="Primary navigation"
    >
      <div className={cn("flex items-center", collapsed ? "justify-center" : "justify-between px-2")}>
        <Link href="/dashboard/command-center" className="flex min-w-0 items-center gap-3" aria-label={`${brand.appName} home`}>
          <span className="grid h-9 w-9 shrink-0 place-items-center overflow-hidden rounded-xl border border-orange-400/30 bg-orange-400/10 shadow-[0_0_28px_rgba(251,146,60,0.12)]">
            {logo ? (
              // eslint-disable-next-line @next/next/no-img-element -- the organisation's own logo, kept on the API
              <img src={logo} alt="" className="h-full w-full object-contain" />
            ) : (
              <ShieldCheck className="h-[18px] w-[18px] text-orange-300" />
            )}
          </span>
          {!collapsed ? (
            <span className="min-w-0">
              <span className="block truncate text-[15px] font-semibold tracking-[-0.02em] text-white">{brand.appName}</span>
              {brand.tagline ? <span className="block truncate text-[10px] uppercase tracking-[0.16em] text-slate-500">{brand.tagline}</span> : null}
            </span>
          ) : null}
        </Link>
        {!collapsed ? (
          <button
            type="button"
            onClick={() => setSidebarCollapsed(true)}
            className="grid h-8 w-8 place-items-center rounded-lg text-slate-500 transition hover:bg-white/5 hover:text-white"
            aria-label="Collapse navigation"
          >
            <PanelLeftClose className="h-4 w-4" />
          </button>
        ) : null}
      </div>

      {collapsed ? (
        <button
          type="button"
          onClick={() => setSidebarCollapsed(false)}
          className="mx-auto mt-3 grid h-8 w-8 place-items-center rounded-lg text-slate-500 transition hover:bg-white/5 hover:text-white"
          aria-label="Expand navigation"
        >
          <PanelLeftOpen className="h-4 w-4" />
        </button>
      ) : (
        <div className="mx-2 mt-5 rounded-xl border border-white/[0.06] bg-white/[0.025] px-3 py-2.5">
          <p className="text-[10px] font-semibold uppercase tracking-[0.14em] text-slate-500">Customer controls</p>
          <p className="mt-1 text-xs text-slate-300">Overview → Activity → Policies → Evidence</p>
        </div>
      )}

      <nav className="mt-5 space-y-1" aria-label="Customer areas">
        {LIFECYCLE_NAV_ITEMS.map((item) => {
          const Icon = ICONS[item.label];
          const active = isLifecycleItemActive(pathname, item);
          const parentCurrent = isLifecyclePathActive(pathname, item.href);
          return (
            <div key={item.href}>
              <Link
                href={item.href}
                title={collapsed ? `${item.label} — ${item.description}` : undefined}
                aria-current={parentCurrent ? "page" : undefined}
                aria-expanded={item.children?.length ? active && !collapsed : undefined}
                className={cn(
                  "group flex items-center rounded-xl transition",
                  collapsed ? "mx-auto h-11 w-11 justify-center" : "gap-3 px-3 py-2.5",
                  active
                    ? "bg-orange-400/[0.11] text-orange-200 shadow-[inset_0_0_0_1px_rgba(251,146,60,0.15)]"
                    : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-100",
                )}
              >
                <Icon className={cn("h-[18px] w-[18px] shrink-0", active && "text-orange-300")} strokeWidth={1.8} />
                {!collapsed ? (
                  <span className="min-w-0">
                    <span className="block text-sm font-medium">{item.label}</span>
                    <span className={cn("mt-0.5 block truncate text-[11px]", active ? "text-orange-200/60" : "text-slate-600 group-hover:text-slate-500")}>{item.description}</span>
                  </span>
                ) : null}
              </Link>

              {active && !collapsed && item.children?.length ? (
                <div
                  aria-label={`${item.label} workspace navigation`}
                  className="ml-[1.3rem] mt-1 space-y-0.5 border-l border-orange-300/15 pl-4"
                >
                  {item.children.map((child) => {
                    const childActive = isLifecyclePathActive(pathname, child.href);
                    return (
                      <Link
                        key={child.href}
                        href={child.href}
                        aria-current={childActive ? "page" : undefined}
                        title={child.description}
                        className={cn(
                          "relative block rounded-lg px-3 py-2 text-xs transition",
                          childActive
                            ? "bg-white/[0.05] font-semibold text-orange-100"
                            : "text-slate-500 hover:bg-white/[0.035] hover:text-slate-200",
                        )}
                      >
                        {childActive ? <span className="absolute -left-[1.08rem] top-1/2 h-1.5 w-1.5 -translate-y-1/2 rounded-full bg-orange-300" /> : null}
                        {child.label}
                      </Link>
                    );
                  })}
                </div>
              ) : null}
            </div>
          );
        })}
        {/* FTR: Settings in the main menu, after the areas; open (and marked) on every Settings page. */}
        <Link
          href={SETTINGS_ENTRY.href}
          title={collapsed ? SETTINGS_ENTRY.label : undefined}
          aria-current={inSettings ? "page" : undefined}
          className={cn(
            "group flex items-center rounded-xl transition",
            collapsed ? "mx-auto h-11 w-11 justify-center" : "gap-3 px-3 py-2.5",
            inSettings
              ? "bg-orange-400/[0.11] text-orange-200 shadow-[inset_0_0_0_1px_rgba(251,146,60,0.15)]"
              : "text-slate-400 hover:bg-white/[0.04] hover:text-slate-100",
          )}
        >
          <Settings className={cn("h-[18px] w-[18px] shrink-0", inSettings && "text-orange-300")} strokeWidth={1.8} />
          {!collapsed ? (
            <span className="min-w-0">
              <span className="block text-sm font-medium">{SETTINGS_ENTRY.label}</span>
              <span className={cn("mt-0.5 block truncate text-[11px]", inSettings ? "text-orange-200/60" : "text-slate-600 group-hover:text-slate-500")}>People, records and the system</span>
            </span>
          ) : null}
        </Link>
      </nav>

      <div className="mt-auto pt-4">
        <div className="border-t border-white/[0.06] pt-4">
          <button
            type="button"
            onClick={() => setMoreOpen((current) => !current)}
            className={cn(
              "flex w-full items-center rounded-xl text-slate-400 transition hover:bg-white/[0.04] hover:text-white",
              collapsed ? "h-11 justify-center" : "justify-between px-3 py-2.5",
            )}
            aria-expanded={moreOpen}
          >
            <span className="flex items-center gap-3">
              <MoreHorizontal className="h-[18px] w-[18px]" />
              {!collapsed ? <span className="text-sm font-medium">Specialist tools</span> : null}
            </span>
            {!collapsed ? <ChevronDown className={cn("h-4 w-4 transition", moreOpen && "rotate-180")} /> : null}
          </button>
          {moreOpen ? (
            <div className={cn("mt-2 overflow-y-auto rounded-xl border border-white/[0.07] bg-[#0d1118] p-2 shadow-2xl", collapsed && "absolute bottom-4 left-[4.75rem] z-50 w-72")}>
              {SPECIALIST_WORKSPACES.map((group) => (
                <div key={group.label} className="mb-3 last:mb-0">
                  <p className="px-2 py-1 text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-600">{group.label}</p>
                  {group.items.map((item) => (
                    <Link key={item.href} href={item.href} className="block rounded-lg px-2 py-1.5 text-xs text-slate-400 transition hover:bg-white/5 hover:text-white">
                      {item.label}
                    </Link>
                  ))}
                </div>
              ))}
            </div>
          ) : null}
        </div>
      </div>
    </aside>
  );
}
