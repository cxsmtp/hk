export type GmailBrowserPresentation = {
  mode: "Unknown" | "Telemetry-only" | "Inline when Chrome-routed";
  isInline: boolean;
  isBlocked: boolean;
  isTelemetryOnly: boolean;
};

const INLINE_MODES = new Set(["inline_prevented", "inline_allowed"]);
const TELEMETRY_ONLY_MODES = new Set([
  "telemetry_only",
  "detected_only",
  "review_required",
  "warned",
]);

export function deriveGmailBrowserPresentation(
  controlMode?: string | null,
): GmailBrowserPresentation {
  const mode = String(controlMode || "").trim().toLowerCase();
  if (INLINE_MODES.has(mode)) {
    return {
      mode: "Inline when Chrome-routed",
      isInline: true,
      isBlocked: mode === "inline_prevented",
      isTelemetryOnly: false,
    };
  }
  if (TELEMETRY_ONLY_MODES.has(mode)) {
    return {
      mode: "Telemetry-only",
      isInline: false,
      isBlocked: false,
      isTelemetryOnly: true,
    };
  }
  return {
    mode: "Unknown",
    isInline: false,
    isBlocked: false,
    isTelemetryOnly: false,
  };
}

export function selectMatchingEvaluation<T extends { connector: { id: string } }>(
  selectedConnectorId: string | null,
  evaluation: T | null,
): T | null {
  if (!selectedConnectorId || evaluation?.connector.id !== selectedConnectorId) return null;
  return evaluation;
}

export function canLinkVerifiedEvidence(
  evidenceId?: string | null,
  integrityStatus?: string | null,
): evidenceId is string {
  return Boolean(String(evidenceId || "").trim()) && integrityStatus === "valid";
}

export type ConnectorOperationState = {
  operationId: number;
  currentOperationId: number;
  requestedConnectorId: string;
  selectedConnectorId: string | null;
  responseConnectorId: string;
};

export function shouldApplyConnectorOperation(state: ConnectorOperationState): boolean {
  return state.operationId === state.currentOperationId
    && state.requestedConnectorId === state.selectedConnectorId
    && state.responseConnectorId === state.requestedConnectorId;
}
