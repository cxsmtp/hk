"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { Button } from "@/components/ui/button";

const tabs = [
  { href: "/runtime-intelligence/overview", label: "Overview" },
  { href: "/runtime-intelligence/activity-map", label: "Activity Map" },
  { href: "/runtime-intelligence/agent-flows", label: "Agent Flows" },
  { href: "/runtime-intelligence/context-graph", label: "Context Graph" },
  { href: "/runtime-intelligence/patterns-anomalies", label: "Patterns & Anomalies" },
  { href: "/runtime-intelligence/recommendations", label: "Recommendations" },
];

export function RuntimeIntelligenceTabs() {
  const pathname = usePathname();

  return (
    <div className="flex flex-wrap gap-2">
      {tabs.map((tab) => {
        const active = pathname === tab.href;
        return (
          <Button key={tab.href} asChild size="sm" variant={active ? "default" : "outline"}>
            <Link href={tab.href}>{tab.label}</Link>
          </Button>
        );
      })}
    </div>
  );
}
