const SAFE_VISIBILITY_CAPABILITIES = [
  "view_aggregates",
  "view_user_metadata",
  "view_action_details",
];

export function isVisibilityRecoveryRole(session) {
  return ["owner", "admin"].includes(String(session?.userRole || "").trim().toLowerCase());
}

export function isVisibilityRecoveryReasonValid(reason) {
  const length = reason.trim().length;
  return length >= 3 && length <= 1000;
}

export function buildVisibilityRecoveryPayload(session, reason) {
  if (!session || !isVisibilityRecoveryRole(session) || !isVisibilityRecoveryReasonValid(reason)) return null;
  return {
    user_id: session.user.id,
    capabilities: [...SAFE_VISIBILITY_CAPABILITIES],
    department_scope: [],
    reason: reason.trim(),
  };
}

export function canSubmitVisibilityRecovery({ session, reason, isSubmitting }) {
  return !isSubmitting && buildVisibilityRecoveryPayload(session, reason) !== null;
}

export async function submitVisibilityRecovery({ session, reason, createGrant }) {
  const payload = buildVisibilityRecoveryPayload(session, reason);
  if (!payload) return { ok: false, error: new Error("visibility_recovery_not_permitted") };
  try {
    await createGrant(payload);
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error instanceof Error ? error : new Error(String(error || "visibility_recovery_failed")) };
  }
}

function asError(value) {
  return value instanceof Error ? value : new Error(String(value || "Unknown request failure"));
}

export async function loadUserVisibilityData({ loadUsers, loadDirectorySummary }) {
  const [users, directorySummary] = await Promise.allSettled([loadUsers(), loadDirectorySummary()]);
  const failures = [users, directorySummary].filter((result) => result.status === "rejected");
  const firstError = failures.length ? asError(failures[0].reason) : null;
  return {
    users,
    directorySummary,
    allSucceeded: failures.length === 0,
    capabilityRequired: failures.some((failure) => asError(failure.reason).message.includes("visibility_capability_required")),
    firstError,
  };
}
