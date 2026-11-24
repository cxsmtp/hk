import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { decisionBadgeClass, decisionLabel, formatDateTime } from "@/components/runtime-intelligence/utils";
import type { RuntimeTimelineEvent } from "@/lib/types";

function eventDecision(event: RuntimeTimelineEvent): string {
  return String(event.decision || "unknown").toLowerCase();
}

function eventAction(event: RuntimeTimelineEvent): string {
  return event.event_type || "runtime_action";
}

function eventActor(event: RuntimeTimelineEvent): string {
  if (event.agent_id) return `agent:${event.agent_id}`;
  if (event.user_id) return `user:${event.user_id}`;
  return "unknown-actor";
}

export function LiveActivityFeed({
  events,
  loading,
  onSelectEvent,
  onBlockUser,
  onEnforcePolicy,
  onDisableAgent,
  onRevokeToken,
  busyAction,
}: {
  events: RuntimeTimelineEvent[];
  loading?: boolean;
  onSelectEvent?: (event: RuntimeTimelineEvent) => void;
  onBlockUser?: (userId: string, event: RuntimeTimelineEvent) => void;
  onEnforcePolicy?: (userId: string, event: RuntimeTimelineEvent) => void;
  onDisableAgent?: (agentId: string, event: RuntimeTimelineEvent) => void;
  onRevokeToken?: (event: RuntimeTimelineEvent) => void;
  busyAction?: string;
}) {
  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between text-xs text-slate-400">
        <span>Streaming actions</span>
        <span>{loading ? "refreshing..." : `${events.length} events`}</span>
      </div>
      <div className="max-h-[560px] space-y-2 overflow-auto pr-1">
        {events.length ? (
          events.map((event) => (
            <div key={event.event_id} className="rounded-lg border border-[#2a3348] bg-[#0f1218] p-3">
              <div className="mb-1 flex items-center justify-between gap-2">
                <p className="truncate text-xs text-slate-400">{formatDateTime(event.created_at)}</p>
                <Badge className={decisionBadgeClass(eventDecision(event))}>{decisionLabel(eventDecision(event))}</Badge>
              </div>
              <p className="truncate text-sm font-semibold text-slate-100">{eventActor(event)}</p>
              <p className="truncate text-xs text-slate-400">{eventAction(event)}</p>
              <p className="truncate text-xs text-slate-500">
                {event.application || event.tool_name || event.api_endpoint || "unknown-app"}
                {" · "}
                {event.model || "unknown-model"}
                {" · "}
                {event.machine_id || "unknown-machine"}
              </p>
              <div className="mt-2 flex flex-wrap items-center gap-2">
                <Button size="sm" variant="outline" onClick={() => onSelectEvent?.(event)}>
                  Trace
                </Button>
                {event.user_id ? (
                  <>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busyAction === `block-user:${event.user_id}`}
                      onClick={() => onBlockUser?.(event.user_id as string, event)}
                    >
                      {busyAction === `block-user:${event.user_id}` ? "Blocking..." : "Block User"}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busyAction === `enforce-user:${event.user_id}`}
                      onClick={() => onEnforcePolicy?.(event.user_id as string, event)}
                    >
                      {busyAction === `enforce-user:${event.user_id}` ? "Applying..." : "Enforce Policy"}
                    </Button>
                  </>
                ) : null}
                {event.agent_id ? (
                  <>
                    <Button
                      size="sm"
                      variant="destructive"
                      disabled={busyAction === `disable-agent:${event.agent_id}`}
                      onClick={() => onDisableAgent?.(event.agent_id as string, event)}
                    >
                      {busyAction === `disable-agent:${event.agent_id}` ? "Disabling..." : "Disable Agent"}
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={busyAction === `revoke-token:${event.event_id}`}
                      onClick={() => onRevokeToken?.(event)}
                    >
                      {busyAction === `revoke-token:${event.event_id}` ? "Revoking..." : "Revoke Token"}
                    </Button>
                  </>
                ) : null}
              </div>
            </div>
          ))
        ) : (
          <p className="text-sm text-slate-500">No runtime actions available.</p>
        )}
      </div>
    </div>
  );
}
