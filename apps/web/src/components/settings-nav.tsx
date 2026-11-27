"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";

import { useMyPermissions } from "@/lib/settings-console";
import { isSettingsItemActive, settingsNav } from "@/lib/settings-menu";

/**
 * Settings' own menu beside the page, as FTR Command Center's (public/js/shell.js: `<nav class="set-nav">`, one
 * `.set-group` per group with its `.set-label`, the page open marked `on`). Only the pages the person's role allows.
 * Up to 900 px wide it folds into one button naming the page open (.set-toggle), which opens the menu as a list.
 */
export function SettingsNav() {
  const pathname = usePathname() || "";
  const permissions = useMyPermissions();
  const groups = permissions ? settingsNav(permissions) : [];
  const [open, setOpen] = useState(false);
  useEffect(() => setOpen(false), [pathname]);
  const current = groups.flatMap((group) => group.items).find((item) => isSettingsItemActive(pathname, item.href));
  return (
    <>
      <button
        type="button"
        className="set-toggle"
        aria-expanded={open}
        aria-controls="settings-menu"
        onClick={() => setOpen((value) => !value)}
      >
        <span className="set-toggle-k">Settings</span>
        <span className="set-toggle-v">{current?.label ?? "Menu"}</span>
        <svg aria-hidden="true" viewBox="0 0 16 16" width="16" height="16" className="set-toggle-i">
          <path d="M4 6l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </button>
      <nav className="set-nav" aria-label="Settings" aria-busy={permissions === null} id="settings-menu" data-open={open ? "true" : "false"}>
        {groups.map((group) => (
          <div className="set-group" key={group.label}>
            <span className="set-label">{group.label}</span>
            {group.items.map((item) => {
              const on = isSettingsItemActive(pathname, item.href);
              return (
                <Link key={item.href} href={item.href} className={on ? "on" : undefined} aria-current={on ? "page" : undefined}>
                  {item.label}
                </Link>
              );
            })}
          </div>
        ))}
      </nav>
    </>
  );
}
