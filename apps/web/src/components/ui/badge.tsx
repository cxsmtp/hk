import * as React from "react";

import { cn } from "@/lib/utils";

export function Badge({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn(
        "inline-flex max-w-full items-center rounded-full border border-brand-500/40 bg-brand-500/15 px-2.5 py-0.5 text-xs font-semibold text-brand-300 whitespace-normal break-words",
        className
      )}
      {...props}
    />
  );
}
