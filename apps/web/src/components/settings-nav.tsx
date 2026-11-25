"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { useMyPermissions } from "@/lib/settings-console";
import { isSettingsItemActive, settingsNav } from "@/lib/settings-menu";

/**
 * Settings' own menu beside the page, as FTR Command Center's (public/js/shell.js: `<nav class="set-nav">`, one
 * `.set-group` per group with its `.set-label`, the page open marked `on`). Only the pages the person's role allows.
 */
export function SettingsNav() {
  const pathname = usePathname() || "";
  const permissions = useMyPermissions();
  const groups = permissions ? settingsNav(permissions) : [];
  return (
    <nav className="set-nav" aria-label="Settings" aria-busy={permissions === null}>
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
  );
}
