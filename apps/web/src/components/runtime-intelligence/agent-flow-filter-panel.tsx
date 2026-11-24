"use client";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export type AgentFlowAgentOption = {
  id: string;
  label: string;
  count: number;
};

export function AgentFlowFilterPanel({
  chainIdInput,
  onChainIdInputChange,
  onLoadChain,
  busy,
  chainSuggestions,
  agentOptions,
  agentFilter,
  onAgentFilterChange,
  decisionFilter,
  onDecisionFilterChange,
  timeFilter,
  onTimeFilterChange,
  visibleSteps,
  totalSteps,
  onResetFilters,
}: {
  chainIdInput: string;
  onChainIdInputChange: (value: string) => void;
  onLoadChain: () => void;
  busy: boolean;
  chainSuggestions: string[];
  agentOptions: AgentFlowAgentOption[];
  agentFilter: string;
  onAgentFilterChange: (value: string) => void;
  decisionFilter: string;
  onDecisionFilterChange: (value: string) => void;
  timeFilter: string;
  onTimeFilterChange: (value: string) => void;
  visibleSteps: number;
  totalSteps: number;
  onResetFilters: () => void;
}) {
  return (
    <div className="space-y-3 rounded-lg border border-[#2a3348] bg-[#101524] p-4">
      <div>
        <p className="text-xs uppercase tracking-[0.2em] text-slate-500">Chain Loader</p>
        <div className="mt-2 flex flex-wrap gap-2">
          <Input
            value={chainIdInput}
            onChange={(event) => onChainIdInputChange(event.target.value)}
            placeholder="Enter chain_id"
          />
          <Button type="button" disabled={busy} onClick={onLoadChain}>
            {busy ? "Loading..." : "Load Flow"}
          </Button>
        </div>
        {chainSuggestions.length ? (
          <div className="mt-2 flex flex-wrap gap-2">
            {chainSuggestions.map((suggestion) => (
              <button
                key={suggestion}
                type="button"
                className="rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-1 text-xs text-slate-300 hover:border-brand-500/40 hover:text-brand-200"
                onClick={() => onChainIdInputChange(suggestion)}
              >
                {suggestion}
              </button>
            ))}
          </div>
        ) : null}
      </div>

      <div className="grid gap-2 md:grid-cols-3">
        <label className="text-xs text-slate-400">
          Agent
          <select
            className="mt-1 w-full rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-2 text-sm text-slate-100"
            value={agentFilter}
            onChange={(event) => onAgentFilterChange(event.target.value)}
          >
            <option value="all">All agents</option>
            {agentOptions.map((option) => (
              <option key={option.id} value={option.id}>
                {`${option.label} (${option.count})`}
              </option>
            ))}
          </select>
        </label>

        <label className="text-xs text-slate-400">
          Decision
          <select
            className="mt-1 w-full rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-2 text-sm text-slate-100"
            value={decisionFilter}
            onChange={(event) => onDecisionFilterChange(event.target.value)}
          >
            <option value="all">All decisions</option>
            <option value="allow">Allow</option>
            <option value="warn">Warn / Hold</option>
            <option value="block">Block</option>
            <option value="unknown">Unknown</option>
          </select>
        </label>

        <label className="text-xs text-slate-400">
          Time Window
          <select
            className="mt-1 w-full rounded-md border border-[#2a3348] bg-[#0f1218] px-2 py-2 text-sm text-slate-100"
            value={timeFilter}
            onChange={(event) => onTimeFilterChange(event.target.value)}
          >
            <option value="all">All time</option>
            <option value="15m">Last 15 min</option>
            <option value="1h">Last 1 hour</option>
            <option value="6h">Last 6 hours</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
          </select>
        </label>
      </div>

      <div className="flex items-center justify-between text-xs text-slate-400">
        <span>{`Showing ${visibleSteps}/${totalSteps} steps`}</span>
        <Button variant="outline" size="sm" onClick={onResetFilters}>
          Reset Filters
        </Button>
      </div>
    </div>
  );
}

