export function PageSection({
  title,
  description,
  children,
}: {
  title: string;
  description?: string;
  children: React.ReactNode;
}) {
  return (
    <section data-ui="operational-section" className="overflow-hidden rounded-xl border border-white/[0.08] bg-[#0a0f16]">
      <header className="border-b border-white/[0.07] px-4 py-3.5 sm:px-5">
        <h2 className="text-sm font-semibold text-slate-100">{title}</h2>
        {description ? <p className="mt-1 text-xs leading-5 text-slate-500">{description}</p> : null}
      </header>
      <div className="p-4 sm:p-5">{children}</div>
    </section>
  );
}
