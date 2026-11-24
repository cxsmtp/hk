import { useMemo } from "react";

import { SimpleTable } from "@/components/simple-table";
import { Badge } from "@/components/ui/badge";
import { severityBadgeClass } from "@/components/runtime-intelligence/utils";
import type { RuntimePattern } from "@/lib/types";

function prettyName(value: string): string {
  return String(value || "policy_violation")
    .split("_")
    .map((part) => `${part.slice(0, 1).toUpperCase()}${part.slice(1)}`)
    .join(" ");
}

export function TopViolationsTable({ patterns }: { patterns: RuntimePattern[] }) {
  const rows = useMemo(
    () =>
      [...patterns]
        .sort((a, b) => b.frequency - a.frequency)
        .slice(0, 12)
        .map((pattern) => [
          prettyName(pattern.type),
          pattern.frequency,
          <Badge key={`${pattern.pattern_id}-severity`} className={severityBadgeClass(pattern.severity)}>
            {pattern.severity}
          </Badge>,
        ]),
    [patterns]
  );

  return <SimpleTable columns={["Policy", "Count", "Severity"]} rows={rows} />;
}
