export const APPROVAL_STATUSES = ["pending", "approved", "denied", "expired", "revoked"];

export function approvalStatusFilters(statusFilter) {
  return APPROVAL_STATUSES.includes(statusFilter) ? [statusFilter] : APPROVAL_STATUSES;
}

export function mergeApprovalStatusResults(results) {
  const approvalsById = new Map();
  for (const result of results) {
    for (const approval of result?.items || []) {
      if (approval?.id && !approvalsById.has(approval.id)) approvalsById.set(approval.id, approval);
    }
  }
  return [...approvalsById.values()];
}

export function approvalIsV2(approval) {
  return approval?.authority_schema_version === "2.0" || approval?.request_payload?.schema_version === "2.0";
}

export function createDecisionIdempotencyKey(approvalId, nonce = globalThis.crypto?.randomUUID?.()) {
  const safeApprovalId = String(approvalId || "approval").replace(/[^A-Za-z0-9._:-]/g, "-").slice(0, 72);
  const safeNonce = String(nonce || "").replace(/[^A-Za-z0-9._:-]/g, "-").slice(0, 48);
  const key = `approval:${safeApprovalId}:${safeNonce}`.slice(0, 128);
  if (key.length < 16 || !safeNonce) throw new Error("Unable to create a bounded idempotency key");
  return key;
}

export function buildApprovalDecisionPayload(approval, decision, reason, idempotencyKey) {
  if (!approvalIsV2(approval)) return { decision };

  // The API projection may expose the stored version directly or retain it in
  // the immutable request payload. A present top-level value always wins; an
  // invalid top-level value must not be bypassed by a payload fallback.
  const expectedVersion = approval?.expected_version === undefined || approval?.expected_version === null
    ? approval?.request_payload?.expected_version
    : approval.expected_version;
  if (!Number.isInteger(expectedVersion) || expectedVersion <= 0) {
    throw new Error("The stored approval does not include a valid expected version");
  }
  const trimmedReason = String(reason || "").trim();
  if (!trimmedReason) throw new Error("A nonempty reason is required for a V2 approval decision");
  if (typeof idempotencyKey !== "string" || idempotencyKey.length < 16 || idempotencyKey.length > 128) {
    throw new Error("A bounded idempotency key is required for a V2 approval decision");
  }
  return {
    schema_version: "2.0",
    decision,
    expected_version: expectedVersion,
    idempotency_key: idempotencyKey,
    reason: trimmedReason,
  };
}
