"use client";

import { useEffect } from "react";
import type { ReactNode } from "react";

import { errorMessageFrom } from "@/lib/licence";

/** The sentence the API refused with (its {error} or {detail}), or a fallback. */
export const said = (error: unknown, fallback = "Something went wrong."): string =>
  errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), fallback);

/** FTR's avatar(): the person's initials. */
export function Avatar({ name }: { name: string }) {
  const initials = name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]?.toUpperCase() ?? "")
    .join("");
  return (
    <span className="avatar" aria-hidden="true">
      {initials || "?"}
    </span>
  );
}

/** FTR's <dialog> (dh / db / df), as an overlay inside the page so it keeps the page's look. Esc closes it. */
export function Dialog({ title, sub, children, footer, onClose, wide }: { title: string; sub?: ReactNode; children: ReactNode; footer: ReactNode; onClose: () => void; wide?: boolean }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="ftr-dialog-wrap" onClick={(e) => e.target === e.currentTarget && onClose()}>
      <div className="ftr-dialog" role="dialog" aria-modal="true" aria-label={title} style={wide ? { width: "min(1100px, 96vw)" } : undefined}>
        <div className="dh">
          <h2>{title}</h2>
          {sub ? <p className="small muted">{sub}</p> : null}
        </div>
        <div className="db form">{children}</div>
        <div className="df">{footer}</div>
      </div>
    </div>
  );
}

export function Icon({ name }: { name: "search" | "plus" | "download" }) {
  return (
    <svg viewBox="0 0 24 24" width="16" height="16" aria-hidden="true" fill="none" stroke="currentColor" strokeWidth="2">
      {name === "search" ? <path d="m21 21-4.3-4.3M11 18a7 7 0 1 1 0-14 7 7 0 0 1 0 14Z" /> : name === "plus" ? <path d="M12 5v14M5 12h14" /> : <path d="M12 3v12m0 0-4-4m4 4 4-4M5 21h14" />}
    </svg>
  );
}
