"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { ChevronDown, Menu, MoreHorizontal, Settings, ShieldCheck, X } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { createPortal } from "react-dom";

import { NAV_ICONS } from "@/components/sidebar";
import {
  isLifecycleItemActive,
  isLifecyclePathActive,
  LIFECYCLE_NAV_ITEMS,
  SETTINGS_ENTRY,
  SPECIALIST_WORKSPACES,
} from "@/lib/navigation";
import { brandingImage, useBranding } from "@/lib/settings-console";
import { cn } from "@/lib/utils";

/**
 * The main menu below the desktop width (lg, 1024 px): a menu button in the top bar that opens the same areas as a
 * drawer from the left, one under the other (never a strip that scrolls sideways), with the open area's own pages
 * listed under it. Closes on a choice, on Escape and on a tap outside; the page behind does not scroll while open.
 */
export function MobileLifecycleNav() {
  const pathname = usePathname() || "";
  const [open, setOpen] = useState(false);
  const [moreOpen, setMoreOpen] = useState(false);
  // The drawer is put on <body>: inside the top bar (backdrop-filter) a fixed box would be placed against the bar.
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);
  const brand = useBranding();
  const logo = brandingImage(brand.logo);
  const closeRef = useRef<HTMLButtonElement | null>(null);
  const triggerRef = useRef<HTMLButtonElement | null>(null);
  const activeItem = LIFECYCLE_NAV_ITEMS.find((item) => isLifecycleItemActive(pathname, item));
  const inSettings = pathname.startsWith("/settings/");
  const here = inSettings ? SETTINGS_ENTRY.label : activeItem?.label;

  // A new page: the drawer has done its job.
  useEffect(() => setOpen(false), [pathname]);

  useEffect(() => {
    if (!open) return undefined;
    const root = document.documentElement;
    const previous = root.style.overflow;
    root.style.overflow = "hidden";
    closeRef.current?.focus();
    const onKey = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    window.addEventListener("keydown", onKey);
    const trigger = triggerRef.current;
    return () => {
      root.style.overflow = previous;
      window.removeEventListener("keydown", onKey);
      trigger?.focus();
    };
  }, [open]);

  return (
    <div className="flex min-w-0 items-center gap-2 lg:hidden">
      <button
        ref={triggerRef}
        type="button"
        onClick={() => setOpen(true)}
        className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-[#2a3348] text-slate-200 transition-colors hover:border-brand-500/40 hover:bg-brand-500/10"
        aria-label="Open the main menu"
        aria-expanded={open}
        aria-controls="hawk-mobile-menu"
      >
        <Menu className="h-5 w-5" />
      </button>
      <Link href="/dashboard/command-center" className="flex min-w-0 items-center gap-2" aria-label={`${brand.appName} home`}>
        <span className="grid h-8 w-8 shrink-0 place-items-center overflow-hidden rounded-lg border border-orange-400/30 bg-orange-400/10">
          {logo ? (
            // eslint-disable-next-line @next/next/no-img-element -- the organisation's own logo, kept on the API
            <img src={logo} alt="" className="h-full w-full object-contain" />
          ) : (
            <ShieldCheck className="h-4 w-4 text-orange-300" />
          )}
        </span>
        <span className="min-w-0">
          <span className="block truncate text-sm font-semibold leading-tight text-white">{brand.appName}</span>
          {here ? <span className="block truncate text-[11px] leading-tight text-slate-400">{here}</span> : null}
        </span>
      </Link>

      {mounted ? createPortal(<>
      <div
        className={cn(
          "fixed inset-0 z-[70] bg-[#030612]/70 backdrop-blur-sm transition-opacity duration-200",
          open ? "opacity-100" : "pointer-events-none invisible opacity-0",
        )}
        onClick={() => setOpen(false)}
        aria-hidden="true"
      />
      <div
        id="hawk-mobile-menu"
        role="dialog"
        aria-modal="true"
        aria-label="Main menu"
        className={cn(
          "hawk-drawer fixed inset-y-0 left-0 z-[71] flex w-[min(88vw,22rem)] flex-col border-r border-white/[0.08] bg-[#090c11] shadow-2xl transition-transform duration-200 ease-out",
          open ? "translate-x-0" : "invisible -translate-x-full",
        )}
      >
        <div className="flex items-center justify-between gap-3 border-b border-white/[0.07] px-4 py-3">
          <span className="truncate text-[15px] font-semibold text-white">{brand.appName}</span>
          <button
            ref={closeRef}
            type="button"
            onClick={() => setOpen(false)}
            className="inline-flex h-10 w-10 shrink-0 items-center justify-center rounded-lg text-slate-400 transition hover:bg-white/5 hover:text-white"
            aria-label="Close the main menu"
          >
            <X className="h-5 w-5" />
          </button>
        </div>
        <nav aria-label="Mobile lifecycle navigation" className="flex-1 overflow-y-auto overscroll-contain px-3 py-3">
          <ul className="space-y-1">
            {LIFECYCLE_NAV_ITEMS.map((item) => {
              const Icon = NAV_ICONS[item.label];
              const active = isLifecycleItemActive(pathname, item);
              return (
                <li key={item.href}>
                  <Link
                    href={item.href}
                    aria-current={isLifecyclePathActive(pathname, item.href) ? "page" : undefined}
                    className={cn(
                      "flex items-center gap-3 rounded-xl px-3 py-2.5 transition",
                      active
                        ? "bg-orange-400/[0.11] text-orange-200 shadow-[inset_0_0_0_1px_rgba(251,146,60,0.15)]"
                        : "text-slate-300 hover:bg-white/[0.04] hover:text-white",
                    )}
                  >
                    <Icon className={cn("h-[18px] w-[18px] shrink-0", active && "text-orange-300")} strokeWidth={1.8} />
                    <span className="min-w-0">
                      <span className="block text-sm font-medium">{item.label}</span>
                      <span className={cn("block truncate text-xs", active ? "text-orange-200/70" : "text-slate-500")}>{item.description}</span>
                    </span>
                  </Link>
                  {active && activeItem?.children?.length ? (
                    <div role="navigation" aria-label="Mobile contextual navigation" className="ml-[1.4rem] mt-1 space-y-0.5 border-l border-orange-300/15 pl-3">
                      {activeItem.children.map((child) => {
                        const current = isLifecyclePathActive(pathname, child.href);
                        return (
                          <Link
                            key={child.href}
                            href={child.href}
                            aria-current={current ? "page" : undefined}
                            className={cn(
                              "block rounded-lg px-3 py-2 text-[13px] transition",
                              current ? "bg-white/[0.06] font-semibold text-orange-100" : "text-slate-400 hover:bg-white/[0.035] hover:text-slate-100",
                            )}
                          >
                            {child.label}
                          </Link>
                        );
                      })}
                    </div>
                  ) : null}
                </li>
              );
            })}
            <li>
              <Link
                href={SETTINGS_ENTRY.href}
                aria-current={inSettings ? "page" : undefined}
                className={cn(
                  "flex items-center gap-3 rounded-xl px-3 py-2.5 transition",
                  inSettings
                    ? "bg-orange-400/[0.11] text-orange-200 shadow-[inset_0_0_0_1px_rgba(251,146,60,0.15)]"
                    : "text-slate-300 hover:bg-white/[0.04] hover:text-white",
                )}
              >
                <Settings className={cn("h-[18px] w-[18px] shrink-0", inSettings && "text-orange-300")} strokeWidth={1.8} />
                <span className="min-w-0">
                  <span className="block text-sm font-medium">{SETTINGS_ENTRY.label}</span>
                  <span className="block truncate text-xs text-slate-500">People, records and the system</span>
                </span>
              </Link>
            </li>
          </ul>
          <div className="mt-4 border-t border-white/[0.06] pt-3">
            <button
              type="button"
              onClick={() => setMoreOpen((current) => !current)}
              className="flex w-full items-center justify-between rounded-xl px-3 py-2.5 text-slate-400 transition hover:bg-white/[0.04] hover:text-white"
              aria-expanded={moreOpen}
            >
              <span className="flex items-center gap-3">
                <MoreHorizontal className="h-[18px] w-[18px]" />
                <span className="text-sm font-medium">Specialist tools</span>
              </span>
              <ChevronDown className={cn("h-4 w-4 transition", moreOpen && "rotate-180")} />
            </button>
            {moreOpen ? (
              <div className="mt-1 space-y-3 px-1">
                {SPECIALIST_WORKSPACES.map((group) => (
                  <div key={group.label}>
                    <p className="px-2 py-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-500">{group.label}</p>
                    {group.items.map((item) => (
                      <Link key={item.href} href={item.href} className="block rounded-lg px-2 py-2 text-[13px] text-slate-400 transition hover:bg-white/5 hover:text-white">
                        {item.label}
                      </Link>
                    ))}
                  </div>
                ))}
              </div>
            ) : null}
          </div>
        </nav>
      </div>
      </>, document.body) : null}
    </div>
  );
}
