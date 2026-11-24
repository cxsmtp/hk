"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import type { ReactNode } from "react";

import { cn } from "@/lib/utils";

type OperationsConsoleTab = {
  label: string;
  href: string;
  matchPrefix?: boolean;
};

export function OperationsConsoleTabs({
  tabs,
  rightSlot,
}: {
  tabs: OperationsConsoleTab[];
  rightSlot?: ReactNode;
}) {
  const pathname = usePathname();

  function isActive(tab: OperationsConsoleTab): boolean {
    if (tab.matchPrefix) return pathname === tab.href || pathname.startsWith(`${tab.href}/`);
    return pathname === tab.href;
  }

  return (
    <div className="-mx-4 -mt-6 mb-6 border-b border-[#1b2131] bg-[#0a0d16]/95 px-4 py-3 backdrop-blur sm:-mx-6 sm:px-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <nav className="flex flex-wrap items-center gap-2">
          {tabs.map((tab) => {
            const active = isActive(tab);
            return (
              <Link
                key={tab.href}
                href={tab.href}
                className={cn(
                  "rounded-2xl px-4 py-2 text-sm font-medium transition",
                  active
                    ? "bg-[#1a2030] text-slate-50 shadow-[inset_0_1px_0_rgba(255,255,255,0.04)]"
                    : "text-slate-500 hover:bg-white/[0.04] hover:text-slate-200"
                )}
              >
                {tab.label}
              </Link>
            );
          })}
        </nav>
        {rightSlot ? <div className="flex flex-wrap items-center gap-2">{rightSlot}</div> : null}
      </div>
    </div>
  );
}
