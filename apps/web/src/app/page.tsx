import Image from "next/image";
import Link from "next/link";
import {
  Activity,
  ArrowRight,
  BarChart3,
  Bell,
  ChevronDown,
  CircleDot,
  Eye,
  FileText,
  Gauge,
  Lock,
  Radar,
  Satellite,
  Search,
  Settings,
  ShieldCheck,
  Telescope,
  TriangleAlert,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";

const navItems = ["Platform", "Solutions", "Resources", "Company"];

const sideItems: Array<[string, LucideIcon]> = [
  ["Observatory", Eye],
  ["Observations", Activity],
  ["Signals", Radar],
  ["Events", Bell],
  ["Evidence", FileText],
  ["Coverage", ShieldCheck],
  ["Reports", BarChart3],
  ["Settings", Settings],
];

const metrics = [
  { label: "Observations", value: "2.1M", tone: "text-sky-200" },
  { label: "Events (24h)", value: "9.3K", tone: "text-cyan-100" },
  { label: "Control Coverage", value: "76%", tone: "text-emerald-300" },
  { label: "Signals Detected", value: "43", tone: "text-sky-300" },
];

const signals = [
  ["Unusual Data Access", "High", "text-rose-400"],
  ["Shadow AI Detected", "High", "text-rose-400"],
  ["Policy Violation", "Medium", "text-amber-300"],
  ["Excessive Permissions", "Medium", "text-amber-300"],
];

const observations = [
  ["10:34 AM", "Shadow AI Tool Detected", "Unverified Tool", "High", "text-rose-400"],
  ["10:32 AM", "Large Data Exfiltration", "Unknown Agent", "High", "text-rose-400"],
  ["10:30 AM", "New MCP Server Found", "Dev Environment", "Medium", "text-amber-300"],
  ["10:26 AM", "Model Inference Spike", "Production", "Low", "text-emerald-300"],
  ["10:18 AM", "New API Integration", "SaaS Connector", "Low", "text-emerald-300"],
  ["10:15 AM", "Unusual Access Pattern", "User Behavior", "Medium", "text-amber-300"],
];

const palette = ["bg-violet-500", "bg-blue-400", "bg-sky-500", "bg-emerald-400"];

function LogoMark() {
  return (
    <span className="grid h-5 w-5 place-items-center rounded-full border border-cyan-200/40 bg-cyan-300/10">
      <Satellite className="h-3 w-3 text-cyan-200" aria-hidden="true" />
    </span>
  );
}

export default function HomePage() {
  return (
    <main className="min-h-screen overflow-hidden bg-[#030913] text-slate-100">
      <section className="grid min-h-screen grid-cols-1 lg:grid-cols-[220px_minmax(0,1fr)_minmax(0,1.15fr)] xl:grid-cols-[260px_minmax(0,1fr)_minmax(0,1.15fr)]">
        <aside className="border-b border-cyan-200/10 bg-[#07131e] px-7 py-8 lg:border-b-0 lg:border-r">
          <Telescope className="h-11 w-11 text-slate-100" strokeWidth={1.8} aria-hidden="true" />
          <p className="mt-10 text-sm font-semibold uppercase tracking-[0.22em] text-slate-500">3. Observatory</p>
          <h1 className="mt-3 text-2xl font-semibold tracking-normal text-white">Observe everything AI.</h1>
          <p className="mt-4 max-w-[14rem] text-sm leading-6 text-slate-300">
            Understand every autonomous decision before it becomes business risk.
          </p>
          <div className="mt-7 flex gap-4" aria-label="Observatory palette">
            {palette.map((color) => (
              <span key={color} className={`h-6 w-6 rounded-full ${color} shadow-[0_0_22px_rgba(14,165,233,0.35)]`} />
            ))}
          </div>
        </aside>

        <section className="relative min-h-[560px] overflow-hidden border-b border-cyan-200/10 bg-[#03111d] lg:border-b-0 lg:border-r">
          <Image
            src="/hawk-ai/observatory-hero.png"
            alt=""
            fill
            priority
            sizes="(max-width: 1024px) 100vw, 42vw"
            className="object-cover"
          />
          <div className="absolute inset-0 bg-[linear-gradient(90deg,rgba(3,9,19,0.95)_0%,rgba(3,9,19,0.78)_38%,rgba(3,9,19,0.15)_100%)]" />
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_20%_20%,rgba(34,211,238,0.18),transparent_34%),linear-gradient(180deg,transparent_0%,rgba(3,9,19,0.75)_100%)]" />

          <div className="relative z-10 flex min-h-[560px] flex-col px-7 py-6 sm:px-9">
            <nav className="flex items-center justify-between gap-4">
              <Link href="/" className="flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.08em] text-white" aria-label="Hawk AI home">
                <LogoMark />
                Hawk AI
              </Link>
              <div className="hidden items-center gap-8 text-xs font-medium text-slate-300 xl:flex">
                {navItems.map((item) => (
                  <button key={item} className="inline-flex items-center gap-1 transition hover:text-white">
                    {item}
                    <ChevronDown className="h-3 w-3" aria-hidden="true" />
                  </button>
                ))}
              </div>
              <Link href="/login" className="rounded-md bg-cyan-400 px-4 py-2 text-xs font-semibold text-slate-950 shadow-[0_0_24px_rgba(34,211,238,0.3)] transition hover:bg-cyan-300">
                Get a Demo
              </Link>
            </nav>

            <div className="mt-auto max-w-[34rem] pb-5">
              <p className="text-xs font-semibold uppercase tracking-[0.24em] text-cyan-200">Enterprise AI Observatory</p>
              <h2 className="mt-4 text-5xl font-semibold leading-[1.02] tracking-normal text-white sm:text-6xl">
                From Observation To Assurance
              </h2>
              <p className="mt-5 max-w-md text-sm leading-7 text-slate-200">
                Hawk AI gives you clarity into your AI universe: agents, actions, tools, prompts, policies, and evidence in one control plane.
              </p>
              <div className="mt-7 flex flex-wrap gap-3">
                <Link href="/guided-demo" className="inline-flex items-center gap-2 rounded-md bg-cyan-300 px-5 py-3 text-sm font-semibold text-slate-950 transition hover:bg-cyan-200">
                  Start Observing
                  <ArrowRight className="h-4 w-4" aria-hidden="true" />
                </Link>
                <Link href="/login" className="inline-flex items-center rounded-md border border-cyan-200/20 bg-slate-950/45 px-5 py-3 text-sm font-semibold text-slate-100 backdrop-blur transition hover:border-cyan-200/50">
                  Get a Demo
                </Link>
              </div>
            </div>
          </div>
        </section>

        <p role="note" className="border-b border-cyan-200/10 bg-[#07131e] px-7 py-3 text-sm font-semibold text-cyan-100 lg:col-span-3">
          Illustrative product preview — sample data, not your workspace.
        </p>

        <section className="min-w-0 bg-[#050b14] p-3 sm:p-4">
          <div className="grid min-h-full gap-3 xl:grid-cols-[150px_minmax(360px,1fr)_minmax(320px,0.95fr)]">
            <aside className="rounded-lg border border-cyan-200/10 bg-[#08131f] p-3">
              <div className="mb-4 flex items-center gap-2 px-1 text-sm font-semibold text-white">
                <LogoMark />
                Hawk
              </div>
              <div className="space-y-1">
                {sideItems.map(([label, Icon], index) => (
                  <Link
                    key={label}
                    href={index === 0 ? "/" : "/dashboard"}
                    className={`flex items-center gap-2 rounded-md px-3 py-2 text-xs font-medium transition ${
                      index === 0 ? "bg-sky-400/10 text-sky-200" : "text-slate-400 hover:bg-white/5 hover:text-slate-100"
                    }`}
                  >
                    <Icon className="h-3.5 w-3.5" aria-hidden="true" />
                    {label}
                  </Link>
                ))}
              </div>
            </aside>

            <div className="space-y-3">
              <header className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-cyan-200/10 bg-[#08131f] px-4 py-3">
                <div>
                  <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Observatory Overview</p>
                  <h2 className="mt-1 text-lg font-semibold text-white">AI Surface Intelligence</h2>
                </div>
                <div className="flex items-center gap-2">
                  <button className="inline-flex items-center gap-2 rounded-md border border-cyan-200/10 px-3 py-2 text-xs text-slate-300">
                    Last 24h
                    <ChevronDown className="h-3 w-3" aria-hidden="true" />
                  </button>
                  <button className="grid h-8 w-8 place-items-center rounded-md border border-cyan-200/10 text-slate-400">
                    <Search className="h-4 w-4" aria-hidden="true" />
                  </button>
                </div>
              </header>

              <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
                {metrics.map((metric) => (
                  <div key={metric.label} className="rounded-lg border border-cyan-200/10 bg-[#08131f] p-4 text-center">
                    <p className="text-[11px] font-medium text-slate-500">{metric.label}</p>
                    <p className={`mt-2 text-3xl font-semibold ${metric.tone}`}>{metric.value}</p>
                  </div>
                ))}
              </div>

              <div className="grid gap-3 lg:grid-cols-[1.1fr_0.9fr]">
                <article className="rounded-lg border border-cyan-200/10 bg-[#08131f] p-4">
                  <div className="mb-3 flex items-center justify-between">
                    <h3 className="text-sm font-semibold text-white">Observation Trend</h3>
                    <Gauge className="h-4 w-4 text-cyan-300" aria-hidden="true" />
                  </div>
                  <div className="relative h-40 overflow-hidden rounded-md border border-cyan-200/5 bg-[#06101b] p-4">
                    <div className="absolute inset-x-4 bottom-8 top-6 bg-[linear-gradient(180deg,rgba(255,255,255,0.05)_1px,transparent_1px)] bg-[size:100%_33%]" />
                    <div className="absolute inset-x-5 bottom-7 h-24 rounded-[50%] border-t-2 border-cyan-300/80 shadow-[0_-16px_30px_rgba(34,211,238,0.18)]" />
                    <div className="absolute bottom-7 left-[18%] h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_18px_rgba(34,211,238,0.9)]" />
                    <div className="absolute bottom-12 left-[48%] h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_18px_rgba(34,211,238,0.9)]" />
                    <div className="absolute bottom-20 right-[14%] h-2 w-2 rounded-full bg-cyan-300 shadow-[0_0_18px_rgba(34,211,238,0.9)]" />
                    <div className="absolute bottom-3 left-5 right-5 flex justify-between text-[10px] text-slate-500">
                      <span>May 1</span>
                      <span>May 8</span>
                      <span>May 15</span>
                      <span>May 22</span>
                      <span>May 29</span>
                    </div>
                  </div>
                </article>

                <article className="rounded-lg border border-cyan-200/10 bg-[#08131f] p-4">
                  <h3 className="mb-3 text-sm font-semibold text-white">Top Signals</h3>
                  <div className="space-y-3">
                    {signals.map(([label, severity, color]) => (
                      <div key={label} className="flex items-center justify-between gap-3 text-xs">
                        <span className="flex items-center gap-2 text-slate-300">
                          <CircleDot className="h-3.5 w-3.5 text-orange-400" aria-hidden="true" />
                          {label}
                        </span>
                        <span className={`font-semibold ${color}`}>{severity}</span>
                      </div>
                    ))}
                  </div>
                </article>
              </div>

              <article className="rounded-lg border border-cyan-200/10 bg-[#08131f] p-4">
                <div className="mb-3 flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-white">AI Constellations</h3>
                  <Lock className="h-4 w-4 text-slate-500" aria-hidden="true" />
                </div>
                <div className="relative min-h-[245px] overflow-hidden rounded-md border border-cyan-200/10 bg-[#030913]">
                  <Image
                    src="/hawk-ai/ai-constellations.png"
                    alt="Glowing AI constellations connecting departments and agent systems"
                    fill
                    sizes="(max-width: 1024px) 100vw, 32vw"
                    className="object-cover"
                  />
                  <div className="absolute inset-0 bg-[linear-gradient(180deg,rgba(3,9,19,0.05),rgba(3,9,19,0.28))]" />
                </div>
              </article>
            </div>

            <aside className="rounded-lg border border-cyan-200/10 bg-[#08131f] p-4">
              <div className="mb-4 flex items-center justify-between gap-3">
                <h3 className="text-sm font-semibold text-white">Recent Observations</h3>
                <button className="rounded-md border border-cyan-200/10 px-3 py-1.5 text-[11px] font-medium text-slate-300">
                  All Sources
                </button>
              </div>
              <div className="space-y-1.5">
                {observations.map(([time, event, source, severity, color]) => (
                  <div key={`${time}-${event}`} className="grid grid-cols-[3.7rem_1fr_auto] items-center gap-3 rounded-md border border-transparent px-2 py-2 text-xs transition hover:border-cyan-200/10 hover:bg-white/[0.03]">
                    <span className="text-slate-500">{time}</span>
                    <span className="min-w-0">
                      <span className="flex items-center gap-2 font-medium text-slate-200">
                        <TriangleAlert className="h-3.5 w-3.5 shrink-0 text-rose-400" aria-hidden="true" />
                        <span className="truncate">{event}</span>
                      </span>
                      <span className="mt-1 block truncate pl-5 text-slate-500">{source}</span>
                    </span>
                    <span className={`font-semibold ${color}`}>{severity}</span>
                  </div>
                ))}
              </div>
              <Link href="/dashboard" className="mt-4 inline-flex w-full justify-end text-xs font-semibold text-sky-300 hover:text-sky-200">
                View all observations
              </Link>
            </aside>
          </div>
        </section>
      </section>
    </main>
  );
}
