export type ApprovalStatus = "pending" | "approved" | "denied" | "expired" | "revoked";

export const APPROVAL_STATUSES: ApprovalStatus[];

export type ApprovalWorkflowRequest = {
  id?: string;
  authority_schema_version?: string | null;
  expected_version?: number | null;
  request_payload?: { schema_version?: string | null; expected_version?: number | null } | null;
};

export function approvalStatusFilters(statusFilter: string): ApprovalStatus[];
export function mergeApprovalStatusResults<T extends { id?: string }>(results: Array<{ items?: T[] } | null | undefined>): T[];
export function approvalIsV2(approval: ApprovalWorkflowRequest): boolean;
export function createDecisionIdempotencyKey(approvalId: string, nonce?: string): string;
export function buildApprovalDecisionPayload(
  approval: ApprovalWorkflowRequest,
  decision: "approve" | "deny",
  reason: string,
  idempotencyKey: string,
):
  | { decision: "approve" | "deny" }
  | {
      schema_version: "2.0";
      decision: "approve" | "deny";
      expected_version: number;
      idempotency_key: string;
      reason: string;
    };
