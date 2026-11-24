export type ContextValidityState =
  | "UNINITIALIZED"
  | "APP_DETECTED"
  | "INPUT_BOUND"
  | "ACTION_OBSERVED"
  | "POLICY_SYNCED"
  | "CONTEXT_VALID"
  | "CONTEXT_STALE"
  | "CONTEXT_INVALID"
  | "RECOVERING"
  | "DISABLED_FOR_PAGE";

export type ContextTransition = {
  from: ContextValidityState;
  to: ContextValidityState;
  timestamp: string;
  reason?: string;
  metadata?: Record<string, unknown>;
};

export type ContextValiditySnapshot = {
  state: ContextValidityState;
  last_transition_at: string;
  previous_state: ContextValidityState | null;
  last_reason: string | null;
};

export class ContextValidityStateMachine {
  private state: ContextValidityState;
  private previousState: ContextValidityState | null;
  private lastTransitionAt: string;
  private lastReason: string | null;
  private readonly transitions: ContextTransition[];

  constructor(initialState: ContextValidityState = "UNINITIALIZED") {
    this.state = initialState;
    this.previousState = null;
    this.lastTransitionAt = new Date().toISOString();
    this.lastReason = null;
    this.transitions = [];
  }

  getState(): ContextValidityState {
    return this.state;
  }

  getSnapshot(): ContextValiditySnapshot {
    return {
      state: this.state,
      last_transition_at: this.lastTransitionAt,
      previous_state: this.previousState,
      last_reason: this.lastReason,
    };
  }

  getTransitionHistory(limit = 30): ContextTransition[] {
    if (limit <= 0) return [];
    return this.transitions.slice(-limit);
  }

  transition(
    next: ContextValidityState,
    options?: { reason?: string; metadata?: Record<string, unknown> },
  ): boolean {
    if (next === this.state && !options?.reason) return false;
    const from = this.state;
    const to = next;
    const timestamp = new Date().toISOString();
    this.previousState = from;
    this.state = to;
    this.lastTransitionAt = timestamp;
    this.lastReason = options?.reason ? String(options.reason) : null;
    this.transitions.push({
      from,
      to,
      timestamp,
      reason: this.lastReason || undefined,
      metadata: options?.metadata,
    });
    if (this.transitions.length > 200) {
      this.transitions.splice(0, this.transitions.length - 200);
    }
    return true;
  }

  markAppDetected(metadata?: Record<string, unknown>): boolean {
    return this.transition("APP_DETECTED", {
      reason: "app_detected",
      metadata,
    });
  }

  markInputBound(metadata?: Record<string, unknown>): boolean {
    return this.transition("INPUT_BOUND", {
      reason: "input_bound",
      metadata,
    });
  }

  markActionObserved(metadata?: Record<string, unknown>): boolean {
    return this.transition("ACTION_OBSERVED", {
      reason: "action_observed",
      metadata,
    });
  }

  markPolicySynced(metadata?: Record<string, unknown>): boolean {
    return this.transition("POLICY_SYNCED", {
      reason: "policy_synced",
      metadata,
    });
  }

  markValid(metadata?: Record<string, unknown>): boolean {
    return this.transition("CONTEXT_VALID", {
      reason: "context_valid",
      metadata,
    });
  }

  markStale(reason: string, metadata?: Record<string, unknown>): boolean {
    return this.transition("CONTEXT_STALE", {
      reason: String(reason || "context_stale"),
      metadata,
    });
  }

  markInvalid(reason: string, metadata?: Record<string, unknown>): boolean {
    return this.transition("CONTEXT_INVALID", {
      reason: String(reason || "context_invalid"),
      metadata,
    });
  }

  markRecovering(reason: string, metadata?: Record<string, unknown>): boolean {
    return this.transition("RECOVERING", {
      reason: String(reason || "recovering"),
      metadata,
    });
  }

  markRecovered(metadata?: Record<string, unknown>): boolean {
    return this.transition("CONTEXT_VALID", {
      reason: "context_recovered",
      metadata,
    });
  }

  markDisabled(reason: string, metadata?: Record<string, unknown>): boolean {
    return this.transition("DISABLED_FOR_PAGE", {
      reason: String(reason || "disabled_for_page"),
      metadata,
    });
  }

  isValidForEnforcement(): boolean {
    return this.state === "CONTEXT_VALID" || this.state === "ACTION_OBSERVED" || this.state === "INPUT_BOUND";
  }
}
