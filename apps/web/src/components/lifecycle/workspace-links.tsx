import Link from "next/link";
import { ArrowUpRight } from "lucide-react";

export function WorkspaceLinks({
  title = "Open specialist tools",
  links,
}: {
  title?: string;
  links: Array<{ href: string; label: string; description: string }>;
}) {
  return (
    <details data-ui="specialist-links" className="group rounded-xl border border-white/[0.07] bg-[#0a0f16]">
      <summary className="flex cursor-pointer list-none items-center justify-between gap-4 px-4 py-3.5 text-sm font-semibold text-slate-300 marker:content-none">
        <span>{title}</span>
        <span className="text-[10px] font-medium uppercase tracking-[0.14em] text-slate-600 group-open:text-orange-300">{links.length} tools</span>
      </summary>
      <div className="grid gap-2 border-t border-white/[0.07] p-3 md:grid-cols-2 xl:grid-cols-3">
        {links.map((link) => (
          <Link key={link.href} href={link.href} className="group/link rounded-lg border border-white/[0.055] bg-white/[0.018] p-3 transition hover:border-orange-400/20 hover:bg-orange-400/[0.035]">
            <div className="flex items-start justify-between gap-3">
              <div>
                <p className="text-sm font-semibold text-slate-100">{link.label}</p>
                <p className="mt-1 text-[11px] leading-4 text-slate-500">{link.description}</p>
              </div>
              <ArrowUpRight className="mt-0.5 h-4 w-4 shrink-0 text-slate-600 transition group-hover/link:text-orange-300" />
            </div>
          </Link>
        ))}
      </div>
    </details>
  );
}
