"use client";

import { Monitor, Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";

import { readThemeChoice, saveThemeChoice, THEME_EVENT, type ThemeChoice } from "@/lib/theme";
import { cn } from "@/lib/utils";

const OPTIONS: Array<{ value: ThemeChoice; label: string; Icon: typeof Sun }> = [
  { value: "light", label: "Light", Icon: Sun },
  { value: "dark", label: "Dark", Icon: Moon },
  { value: "system", label: "System", Icon: Monitor },
];

/** Light, dark or the device's own look, for this browser (lib/theme.ts); in the account menu. */
export function ThemeSwitch() {
  const [choice, setChoice] = useState<ThemeChoice | null>(null);
  useEffect(() => {
    setChoice(readThemeChoice() ?? (document.documentElement.dataset.theme === "dark" ? "dark" : "light"));
    const on = (event: Event) => setChoice((event as CustomEvent<ThemeChoice>).detail);
    window.addEventListener(THEME_EVENT, on);
    return () => window.removeEventListener(THEME_EVENT, on);
  }, []);
  return (
    <div className="px-2 pb-1 pt-1.5">
      <p className="px-0 pb-1.5 text-[9px] font-semibold uppercase tracking-[0.16em] text-slate-600" id="theme-switch-label">
        Appearance
      </p>
      <div role="radiogroup" aria-labelledby="theme-switch-label" className="grid grid-cols-3 gap-1 rounded-lg border border-[#263047] bg-[#0d1320] p-1" data-ui="theme-switch">
        {OPTIONS.map(({ value, label, Icon }) => {
          const on = choice === value;
          return (
            <button
              key={value}
              type="button"
              role="radio"
              aria-checked={on}
              onClick={() => {
                saveThemeChoice(value);
                setChoice(value);
              }}
              className={cn(
                "flex min-h-9 flex-col items-center justify-center gap-0.5 rounded-md px-1 py-1 text-[11px] font-medium transition",
                on ? "bg-brand-500 text-black" : "text-slate-400 hover:bg-white/[0.05] hover:text-white",
              )}
            >
              <Icon className="h-3.5 w-3.5" aria-hidden="true" />
              {label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
