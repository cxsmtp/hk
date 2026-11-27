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
    <div className="-mx-4 -mt-4 mb-5 border-b border-[#1b2131] bg-[#0a0d16]/95 px-4 py-2.5 sm:-mx-6 sm:-mt-6 sm:mb-6 sm:px-6 sm:py-3">
      <div className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2">
        {/* On a phone the tabs share the row equally (never a second row, never a sideways scroll). */}
        <nav className="grid w-full auto-cols-fr grid-flow-col gap-1 sm:flex sm:w-auto sm:flex-wrap sm:items-center sm:gap-2">
          {tabs.map((tab) => {
            const active = isActive(tab);
            return (
              <Link
                key={tab.href}
                href={tab.href}
                className={cn(
                  "truncate rounded-xl px-2 py-2 text-center text-[13px] font-medium transition sm:rounded-2xl sm:px-4 sm:text-sm",
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
