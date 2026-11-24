"use client";

import { X } from "lucide-react";
import { useEffect, useId, useRef } from "react";
import type { ReactNode } from "react";

import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

type DetailDrawerProps = {
  open: boolean;
  title: string;
  subtitle?: string;
  onClose: () => void;
  children: ReactNode;
  size?: "default" | "wide";
};

export function DetailDrawer({ open, title, subtitle, onClose, children, size = "default" }: DetailDrawerProps) {
  const titleId = useId();
  const subtitleId = useId();
  const panelRef = useRef<HTMLElement>(null);
  const closeButtonRef = useRef<HTMLButtonElement>(null);
  const previousFocusRef = useRef<HTMLElement | null>(null);
  const onCloseRef = useRef(onClose);

  useEffect(() => {
    onCloseRef.current = onClose;
  }, [onClose]);

  useEffect(() => {
    if (!open) return;

    previousFocusRef.current = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";

    const focusTimer = window.requestAnimationFrame(() => closeButtonRef.current?.focus());

    function handleKeyDown(event: KeyboardEvent) {
      if (event.key === "Escape") {
        event.preventDefault();
        onCloseRef.current();
        return;
      }

      if (event.key === "Tab") {
        const focusable = Array.from(
          panelRef.current?.querySelectorAll<HTMLElement>(
            'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex="-1"])',
          ) || [],
        ).filter((element) => !element.hasAttribute("hidden"));

        if (!focusable.length) {
          event.preventDefault();
          panelRef.current?.focus();
          return;
        }

        const first = focusable[0];
        const last = focusable[focusable.length - 1];
        if (event.shiftKey && (document.activeElement === first || !panelRef.current?.contains(document.activeElement))) {
          event.preventDefault();
          last.focus();
        } else if (!event.shiftKey && (document.activeElement === last || !panelRef.current?.contains(document.activeElement))) {
          event.preventDefault();
          first.focus();
        }
      }
    }

    document.addEventListener("keydown", handleKeyDown);
    return () => {
      window.cancelAnimationFrame(focusTimer);
      document.removeEventListener("keydown", handleKeyDown);
      document.body.style.overflow = previousOverflow;
      previousFocusRef.current?.focus({ preventScroll: true });
    };
  }, [open]);

  if (!open) return null;

  return (
    <>
      <button
        type="button"
        tabIndex={-1}
        aria-label="Close investigation overlay"
        className="fixed inset-0 z-30 cursor-default bg-black/60 backdrop-blur-[2px]"
        onClick={onClose}
      />
      <aside
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        aria-describedby={subtitle ? subtitleId : undefined}
        tabIndex={-1}
        className={cn(
          "fixed right-0 top-0 z-40 h-full w-full overflow-y-auto border-l border-[#263047] bg-[#0b1018] p-4 shadow-2xl sm:p-6",
          size === "wide" ? "max-w-5xl" : "max-w-2xl",
        )}
      >
        <div className="mb-6 flex items-start justify-between gap-4 border-b border-[#263047] pb-5">
          <div>
            <p className="font-mono text-[10px] uppercase tracking-[0.2em] text-orange-300">Investigation</p>
            <h3 id={titleId} className="mt-2 text-2xl font-semibold text-slate-100">{title}</h3>
            {subtitle ? <p id={subtitleId} className="mt-1 text-sm text-slate-400">{subtitle}</p> : null}
          </div>
          <Button ref={closeButtonRef} variant="outline" size="sm" onClick={onClose} aria-label="Close investigation">
            <X className="h-4 w-4" aria-hidden="true" />
            <span className="sr-only">Close</span>
          </Button>
        </div>
        {children}
      </aside>
    </>
  );
}
