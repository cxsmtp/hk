import type { ReactNode } from "react";

export function WorkspaceHeader({
  eyebrow,
  title,
  description,
  actions,
}: {
  eyebrow: string;
  title: string;
  description: string;
  actions?: ReactNode;
}) {
  return (
    <header data-ui="workspace-header" className="border-b border-white/[0.08] pb-5">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
        <div className="max-w-3xl">
          <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-orange-300">{eyebrow}</p>
          <h1 className="mt-1.5 text-2xl font-semibold tracking-[-0.025em] text-white sm:text-[1.8rem]">{title}</h1>
          <p className="mt-1 max-w-2xl text-sm leading-5 text-slate-500">{description}</p>
        </div>
        {actions ? <div className="flex flex-wrap items-center gap-2">{actions}</div> : null}
      </div>
    </header>
  );
}
