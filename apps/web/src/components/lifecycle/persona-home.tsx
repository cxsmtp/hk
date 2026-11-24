"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { ArrowRight, BriefcaseBusiness, Code2, Eye, Scale, SlidersHorizontal } from "lucide-react";

import { cn } from "@/lib/utils";

const PERSONAS = [
  { id: "ciso", label: "CISO", icon: BriefcaseBusiness, description: "Coverage, blind spots and priority decisions", href: "/dashboard/command-center" },
  { id: "operator", label: "Operator", icon: Eye, description: "Live actions, blocks and approvals", href: "/observe" },
  { id: "auditor", label: "Auditor", icon: Scale, description: "Evidence freshness and control proof", href: "/evidence" },
  { id: "developer", label: "Developer", icon: Code2, description: "Agents, MCP tools and guardrails", href: "/protect" },
] as const;

const SURFACES = ["All", "Browser", "Endpoint", "MCP", "LLM", "Microsoft"] as const;
const STORAGE_KEY = "hawk_home_persona";

export function PersonaHome() {
  const [persona, setPersona] = useState<(typeof PERSONAS)[number]["id"]>("ciso");
  const [surface, setSurface] = useState<(typeof SURFACES)[number]>("All");
  const activePersona = PERSONAS.find((item) => item.id === persona) ?? PERSONAS[0];

  useEffect(() => {
    try {
      const stored = window.localStorage.getItem(STORAGE_KEY);
      if (PERSONAS.some((item) => item.id === stored)) setPersona(stored as (typeof PERSONAS)[number]["id"]);
    } catch {
      // Preference is optional and must not affect tenant data.
    }
  }, []);

  function choosePersona(id: (typeof PERSONAS)[number]["id"]) {
    setPersona(id);
    try {
      window.localStorage.setItem(STORAGE_KEY, id);
    } catch {
      // Preference is optional and must not affect tenant data.
    }
  }

  return (
    <section className="rounded-[22px] border border-white/[0.07] bg-[#0c1016] p-4 sm:p-5">
      <div className="flex flex-col gap-4 xl:flex-row xl:items-center xl:justify-between">
        <div className="flex min-w-0 items-center gap-3">
          <span className="grid h-9 w-9 shrink-0 place-items-center rounded-xl border border-orange-400/20 bg-orange-400/[0.08] text-orange-300">
            <SlidersHorizontal className="h-4 w-4" />
          </span>
          <div>
            <p className="text-sm font-semibold text-slate-100">Your operational lens</p>
            <p className="mt-0.5 text-xs text-slate-500">The view changes; tenant evidence and control assertions do not.</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-1.5 rounded-xl border border-white/[0.06] bg-black/20 p-1">
          {SURFACES.map((item) => (
            <button key={item} type="button" onClick={() => setSurface(item)} className={cn("rounded-lg px-3 py-1.5 text-[11px] font-medium transition", surface === item ? "bg-white/[0.09] text-white" : "text-slate-500 hover:text-slate-200")}>
              {item}
            </button>
          ))}
        </div>
      </div>
      <div className="mt-4 grid gap-2 sm:grid-cols-2 xl:grid-cols-4">
        {PERSONAS.map((item) => {
          const Icon = item.icon;
          const selected = item.id === persona;
          return (
            <button key={item.id} type="button" onClick={() => choosePersona(item.id)} className={cn("rounded-2xl border p-3.5 text-left transition", selected ? "border-orange-400/25 bg-orange-400/[0.07]" : "border-white/[0.055] bg-white/[0.018] hover:bg-white/[0.035]")}>
              <div className="flex items-center gap-2">
                <Icon className={cn("h-4 w-4", selected ? "text-orange-300" : "text-slate-500")} />
                <span className="text-sm font-semibold text-slate-100">{item.label}</span>
              </div>
              <p className="mt-2 text-[11px] leading-5 text-slate-500">{item.description}</p>
              {selected ? <span className="mt-2 block text-[11px] font-semibold text-orange-300">Selected operational lens</span> : null}
            </button>
          );
        })}
      </div>
      <div className="mt-3 flex flex-col gap-3 border-t border-white/[0.06] pt-3 sm:flex-row sm:items-center sm:justify-between">
        <p className="text-[10px] uppercase tracking-[0.14em] text-slate-600">Surface focus: {surface}</p>
        <Link
          href={activePersona.href}
          className="inline-flex items-center gap-2 text-xs font-semibold text-orange-300 transition hover:text-orange-200"
        >
          Open workspace
          <ArrowRight className="h-3.5 w-3.5" />
        </Link>
      </div>
    </section>
  );
}
