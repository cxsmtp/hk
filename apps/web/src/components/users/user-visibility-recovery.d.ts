export type VisibilityRecoverySession = {
  user: { id: string };
  userRole?: string;
} | null | undefined;

export type VisibilityRecoveryPayload = {
  user_id: string;
  capabilities: ["view_aggregates", "view_user_metadata", "view_action_details"];
  department_scope: [];
  reason: string;
};

export function isVisibilityRecoveryRole(session: VisibilityRecoverySession): boolean;
export function isVisibilityRecoveryReasonValid(reason: string): boolean;
export function buildVisibilityRecoveryPayload(session: VisibilityRecoverySession, reason: string): VisibilityRecoveryPayload | null;
export function canSubmitVisibilityRecovery(input: {
  session: VisibilityRecoverySession;
  reason: string;
  isSubmitting: boolean;
}): boolean;
export function submitVisibilityRecovery(input: {
  session: VisibilityRecoverySession;
  reason: string;
  createGrant: (payload: VisibilityRecoveryPayload) => Promise<unknown>;
}): Promise<{ ok: true } | { ok: false; error: Error }>;
export function loadUserVisibilityData<TUsers, TSummary>(input: {
  loadUsers: () => Promise<TUsers>;
  loadDirectorySummary: () => Promise<TSummary>;
}): Promise<{
  users: PromiseSettledResult<TUsers>;
  directorySummary: PromiseSettledResult<TSummary>;
  allSucceeded: boolean;
  capabilityRequired: boolean;
  firstError: Error | null;
}>;
