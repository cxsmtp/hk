import type { ReactNode } from "react";

import { Input } from "@/components/ui/input";

export function TableFilters({ children, actions }: { children: ReactNode; actions?: ReactNode }) {
  return (
    <div className="rounded-lg border border-[#1e2433] bg-[#13161f] p-3">
      <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">{children}</div>
      {actions ? <div className="mt-3 flex justify-end gap-2">{actions}</div> : null}
    </div>
  );
}

export function FilterLabel({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="space-y-1 text-xs font-medium text-slate-400">
      {label}
      {children}
    </label>
  );
}

export function FilterSelect({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (next: string) => void;
  options: Array<{ value: string; label: string }>;
}) {
  return (
    <select
      className="h-10 w-full rounded-md border border-[#1e2433] bg-[#0e1018] px-3 text-sm text-slate-100"
      value={value}
      onChange={(event) => onChange(event.target.value)}
    >
      {options.map((option) => (
        <option key={option.value} value={option.value}>
          {option.label}
        </option>
      ))}
    </select>
  );
}

export function FilterInput({
  value,
  onChange,
  placeholder,
}: {
  value: string;
  onChange: (next: string) => void;
  placeholder: string;
}) {
  return <Input value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} />;
}
