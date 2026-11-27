"use client";

import { Search } from "lucide-react";
import { useRouter } from "next/navigation";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { guideJumpEntries } from "@/lib/guide";
import { LIFECYCLE_NAV_ITEMS, SPECIALIST_WORKSPACES } from "@/lib/navigation";
import { useMyPermissions } from "@/lib/settings-console";
import { jumpMatches, settingsJumpEntries } from "@/lib/settings-menu";

type Entry = { title: string; sub: string; href: string };

/**
 * Jump to (Ctrl K), as FTR Command Center's (public/js/shell.js `jumpTo()`): pages as you type, every word in any
 * order; arrows and Enter; Esc closes. Every Settings page answers to "settings" and to its group's name; the guide's
 * topics (lib/guide) are listed for everyone signed in.
 */
export function JumpTo() {
  const router = useRouter();
  const permissions = useMyPermissions();
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [sel, setSel] = useState(0);
  const input = useRef<HTMLInputElement | null>(null);

  const pages = useMemo<Entry[]>(() => {
    const areas = LIFECYCLE_NAV_ITEMS.flatMap((area) =>
      (area.children?.length ? area.children : [{ href: area.href, label: area.label }]).map((child) => ({ title: child.label, sub: area.label, href: child.href })),
    );
    const tools = SPECIALIST_WORKSPACES.flatMap((group) => group.items.map((item) => ({ title: item.label, sub: group.label, href: item.href })));
    const seen = new Set<string>();
    return [...areas, ...settingsJumpEntries(permissions ?? []), ...guideJumpEntries(), ...tools].filter((entry) => (seen.has(`${entry.href}|${entry.title}`) ? false : (seen.add(`${entry.href}|${entry.title}`), true)));
  }, [permissions]);
  const items = jumpMatches(pages, query);

  const close = useCallback(() => {
    setOpen(false);
    setQuery("");
    setSel(0);
  }, []);
  const go = useCallback(
    (entry: Entry | undefined) => {
      if (!entry) return;
      close();
      router.push(entry.href);
    },
    [close, router],
  );

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        setOpen(true);
      }
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, []);
  useEffect(() => {
    if (open) input.current?.focus();
  }, [open]);

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title="Jump to a page"
        aria-label="Jump to a page"
        className="inline-flex h-10 w-10 shrink-0 items-center justify-center gap-2 rounded-md border border-[#2a3348] text-sm text-slate-400 transition-colors hover:border-brand-500/40 hover:text-slate-200 md:w-auto md:justify-start md:px-3"
      >
        <Search className="h-4 w-4" />
        <span className="hidden md:inline">Jump to…</span>
        <kbd className="hidden rounded border border-[#2a3348] px-1.5 py-0.5 font-mono text-[10px] text-slate-500 xl:inline">Ctrl K</kbd>
      </button>
      {open ? (
        <div className="hawk-overlay fixed inset-0 z-[80] flex items-start justify-center bg-[#030612]/60 px-4 pt-[max(12vh,env(safe-area-inset-top))] backdrop-blur-sm" onMouseDown={(event) => event.target === event.currentTarget && close()}>
          <div role="dialog" aria-label="Jump to" className="w-[min(620px,94vw)] overflow-hidden rounded-2xl border border-[#263047] bg-[#0b1220] shadow-2xl">
            <div className="flex items-center gap-2 border-b border-[#1e2433] px-4 py-3">
              <Search className="h-4 w-4 text-slate-500" />
              <input
                ref={input}
                value={query}
                onChange={(event) => {
                  setQuery(event.target.value);
                  setSel(0);
                }}
                onKeyDown={(event) => {
                  if (event.key === "Escape") close();
                  else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
                    event.preventDefault();
                    setSel((current) => (current + (event.key === "ArrowDown" ? 1 : items.length - 1)) % Math.max(1, items.length));
                  } else if (event.key === "Enter") go(items[sel]);
                }}
                placeholder="Jump to a page…"
                autoComplete="off"
                className="w-full bg-transparent text-sm text-slate-100 outline-none placeholder:text-slate-500"
              />
              <kbd className="rounded border border-[#2a3348] px-1.5 py-0.5 font-mono text-[10px] text-slate-500">Esc</kbd>
            </div>
            <div role="listbox" className="max-h-[50vh] overflow-y-auto p-2">
              {items.length ? (
                items.map((entry, index) => (
                  <button
                    key={`${entry.href}|${entry.title}`}
                    type="button"
                    role="option"
                    aria-selected={index === sel}
                    onMouseEnter={() => setSel(index)}
                    onClick={() => go(entry)}
                    className={`flex w-full flex-col rounded-lg px-3 py-2 text-left ${index === sel ? "bg-white/[0.06]" : ""}`}
                  >
                    <b className="text-sm font-semibold text-slate-100">{entry.title}</b>
                    <small className="text-xs text-slate-500">{entry.sub}</small>
                  </button>
                ))
              ) : (
                <p className="px-3 py-2 text-xs text-slate-500">Nothing matches.</p>
              )}
            </div>
          </div>
        </div>
      ) : null}
    </>
  );
}
