"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { isLifecycleItemActive, isLifecyclePathActive, LIFECYCLE_NAV_ITEMS, SETTINGS_ENTRY } from "@/lib/navigation";
import { cn } from "@/lib/utils";

export function MobileLifecycleNav() {
  const pathname = usePathname() || "";
  const activeItem = LIFECYCLE_NAV_ITEMS.find((item) => isLifecycleItemActive(pathname, item));

  return (
    <nav
      aria-label="Mobile lifecycle navigation"
      className="border-b border-white/[0.07] bg-[#090c11]/95 px-4 py-2 backdrop-blur-xl lg:hidden"
    >
      <div className="flex gap-1 overflow-x-auto pb-1 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {LIFECYCLE_NAV_ITEMS.map((item) => {
          const active = isLifecycleItemActive(pathname, item);
          return (
            <Link
              key={item.href}
              href={item.href}
              aria-current={isLifecyclePathActive(pathname, item.href) ? "page" : undefined}
              className={cn(
                "shrink-0 rounded-lg px-3 py-2 text-xs font-semibold transition",
                active
                  ? "bg-orange-400/[0.12] text-orange-200 shadow-[inset_0_0_0_1px_rgba(251,146,60,0.16)]"
                  : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200",
              )}
            >
              {item.label}
            </Link>
          );
        })}
        <Link
          href={SETTINGS_ENTRY.href}
          aria-current={pathname.startsWith("/settings/") ? "page" : undefined}
          className={cn(
            "shrink-0 rounded-lg px-3 py-2 text-xs font-semibold transition",
            pathname.startsWith("/settings/")
              ? "bg-orange-400/[0.12] text-orange-200 shadow-[inset_0_0_0_1px_rgba(251,146,60,0.16)]"
              : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200",
          )}
        >
          {SETTINGS_ENTRY.label}
        </Link>
      </div>
      {activeItem?.children?.length ? (
        <div
          role="navigation"
          aria-label="Mobile contextual navigation"
          className="mt-1 flex gap-1 overflow-x-auto border-t border-white/[0.06] pt-2 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden"
        >
          {activeItem.children.map((child) => {
            const active = isLifecyclePathActive(pathname, child.href);
            return (
              <Link
                key={child.href}
                href={child.href}
                aria-current={active ? "page" : undefined}
                className={cn(
                  "shrink-0 rounded-md px-2.5 py-1.5 text-[11px] transition",
                  active ? "bg-white/[0.06] font-semibold text-orange-100" : "text-slate-500 hover:text-slate-200",
                )}
              >
                {child.label}
              </Link>
            );
          })}
        </div>
      ) : null}
    </nav>
  );
}
