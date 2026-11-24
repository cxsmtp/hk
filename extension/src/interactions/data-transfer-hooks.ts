import type { ExtensionPolicy } from "../policy-sync";

type DataTransferWarnInput = {
  domain: string;
  reasons: string[];
  recommendation: string;
};

type DataTransferBlockInput = {
  domain: string;
  reason: string;
};

type CopyContextPayload = {
  source_url: string;
  source_domain: string;
  source_app_name?: string;
  source_surface_type: "ai_tool" | "internal_app" | "email" | "slack" | "document" | "unknown";
  source_classification_hint: "protected" | "unknown" | "public";
  copied_text_hash: string;
  copied_text_preview_redacted: string;
  timestamp: string;
};

type PasteContextPayload = {
  destination_url: string;
  destination_domain: string;
  destination_app_name?: string;
  destination_surface_type: "email" | "slack" | "ai_tool" | "saas" | "unknown";
  destination_input_context: "compose_box" | "chat_box" | "form_field" | "unknown";
  timestamp: string;
};

type DataTransferDecisionResponse = {
  decision: "allow" | "warn" | "block" | "require_justification";
  reason_code: string;
  explanation: string;
  recommended_action: string;
  justification_required: boolean;
  policy_version: string;
  platform_mode: string;
};

type DataTransferJustificationResponse = {
  decision: "allow" | "block";
  reason_code: string;
  explanation: string;
  recommended_action: string;
};

type DataTransferHookOptions = {
  domain: string;
  policy: ExtensionPolicy;
  onTelemetry: (payload: Record<string, unknown>) => Promise<void>;
  onWarn: (input: DataTransferWarnInput) => Promise<"continue" | "cancel">;
  onBlock: (input: DataTransferBlockInput) => Promise<void>;
  onRequireJustification: (input: {
    domain: string;
    reason: string;
    recommendation: string;
  }) => Promise<JustificationSubmitResult | { action: "cancel" }>;
  onDataTransferCheck: (payload: {
    correlation_id?: string;
    copy_context: CopyContextPayload;
    paste_context: PasteContextPayload;
    file_meta?: Array<Record<string, unknown>>;
    policy_version: string;
    platform_mode: "discovery" | "enforce";
  }) => Promise<DataTransferDecisionResponse>;
  onDataTransferJustify: (payload: {
    correlation_id?: string;
    justification: string;
    submitter_name?: string;
    submitter_email?: string;
    submitter_role?: string;
    submitter_department?: string;
    actor_role?: string;
    actor_department?: string;
    user_email?: string;
    copy_context: CopyContextPayload;
    paste_context: PasteContextPayload;
    file_meta?: Array<Record<string, unknown>>;
    policy_decision: {
      decision: "allow" | "warn" | "block" | "require_justification";
      reason_code?: string;
      policy_version?: string;
      platform_mode?: "discovery" | "enforce";
    };
    policy_version: string;
    platform_mode: "discovery" | "enforce";
  }) => Promise<DataTransferJustificationResponse>;
};

type DataTransferTimeoutFallbackDecision = "block" | "require_justification" | "warn";
type JustificationSubmitResult = {
  action: "submit";
  justification: string;
  submitter_name?: string;
  submitter_email?: string;
  submitter_role?: string;
  submitter_department?: string;
};
type SpreadsheetUploadClassification = {
  isSpreadsheet: boolean;
  businessRelated: boolean;
  containsSecret: boolean;
  containsHighRiskPii: boolean;
  signalTypes: string[];
  decision: "allow" | "require_justification" | "block";
  reasonCode: string;
  explanation: string;
};
export type DroppedFileTransferDecision = {
  decision: "allow" | "warn" | "block" | "require_justification";
  reasonCode: string;
  explanation: string;
  signalTypes: string[];
  recommendedAction: string;
};

export async function emitNonBlockingDataTransferTelemetry(
  onTelemetry: (payload: Record<string, unknown>) => Promise<void>,
  payload: Record<string, unknown>,
): Promise<boolean> {
  try {
    await onTelemetry(payload);
    return true;
  } catch {
    return false;
  }
}

type TextPasteClassification = {
  businessRelated: boolean;
  containsSecret: boolean;
  containsHighRiskPii: boolean;
  containsOperationalCommand: boolean;
  hasSqlDatabaseContext: boolean;
  hasEngineeringBoqContext: boolean;
  hasBusinessEmail: boolean;
  signalTypes: string[];
  decision: "allow" | "require_justification" | "block";
  reasonCode: string;
  explanation: string;
};

function justificationPayloadFields(result: JustificationSubmitResult): {
  justification: string;
  submitter_name?: string;
  submitter_email?: string;
  submitter_role?: string;
  submitter_department?: string;
  actor_role?: string;
  actor_department?: string;
  user_email?: string;
} {
  return {
    justification: result.justification,
    submitter_name: result.submitter_name,
    submitter_email: result.submitter_email,
    submitter_role: result.submitter_role,
    submitter_department: result.submitter_department,
    actor_role: result.submitter_role,
    actor_department: result.submitter_department,
    user_email: result.submitter_email,
  };
}

const SENSITIVE_FILE_NAME_HINTS = [
  ".env",
  ".pem",
  ".key",
  ".p12",
  ".pfx",
  ".jks",
  ".kdbx",
  "secret",
  "credential",
  "private",
  "emirates",
  "eid",
  "national_id",
  "nationalid",
  "passport",
  "id_card",
  "idcard",
  "bank",
  "iban",
  "account",
  "statement",
  "salary",
  "payroll",
  "card",
];

const SENSITIVE_FILE_NAME_PATTERN =
  /\b(?:emirates|eid|national[_-]?id|passport|id[_-]?card|bank|iban|account|statement|salary|payroll|credit[_-]?card|debit[_-]?card|ssn)\b/i;

const COPY_CONTEXT_TTL_MS = 120_000;
const COPY_CONTEXT_STORAGE_KEY = "runtime_control_last_copy_context";
const UAE_EMIRATES_ID_STRICT_PATTERN = /(?<!\d)784-?\d{4}-?\d{7}-?\d(?!\d)/;
const UAE_EMIRATES_ID_CONTEXT_PATTERN =
  /\b(?:emirates\s*id|uae\s*(?:id|national\s*id)|eid)\b[^\n\r]{0,40}\b\d{10,18}\b/i;
const BLOCKED_ARTIFACT_CLEANUP_DELAYS_MS = [0, 120, 500, 1500];
const DROP_OVERLAY_RELEASE_DELAYS_MS = [0, 50, 150, 500];
const OCR_INLINE_FILE_MAX_BYTES = 350_000;
const TEXT_INLINE_FILE_MAX_BYTES = 64_000;
const SPREADSHEET_INLINE_FILE_MAX_BYTES = 500_000;
const TEXT_INLINE_PREVIEW_MAX_CHARS = 16_000;
const BUSINESS_EMAIL_PATTERN = /\b[\w.+-]+@([\w.-]+\.\w+)\b/gi;
const PUBLIC_EMAIL_DOMAINS = new Set(["gmail.com", "outlook.com", "hotmail.com", "yahoo.com", "icloud.com", "proton.me", "protonmail.com"]);
const HIGH_CONFIDENCE_SECRET_PATTERNS = [
  /\b(?:api[_\s-]?key|secret|token|password)\b\s*[:=]\s*[A-Za-z0-9][A-Za-z0-9_\-./+=]{8,}/i,
  /\b(?:sk|pk|ghp|xox[baprs])[_-][A-Za-z0-9_\-]{16,}\b/,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
];
const BUSINESS_CONTENT_PATTERNS = [
  /\b(contact|contacts|customer|customers|account|accounts|client|clients|crm|lead|leads|prospect|prospects)\b/i,
  /\b(company|companies|renewal|contract|revenue|arr|mrr|deal|pipeline|opportunity|opportunities)\b/i,
  /\b(email|e-mail|phone|mobile|title|owner|sales|account owner)\b/i,
];
const SQL_DATABASE_CONTEXT_PATTERNS = [
  /\b(?:sql\s*server|management\s+studio|database|databases|schema|schemas|table|tables|dbo\.|stored\s+procedure|query|index|join|where|insert\s+into|select\s+.+\s+from)\b/i,
  /\b(?:explain|optimi[sz]e|debug|review)\b[^\n\r]{0,120}\b(?:sql|query|schema|database|table|dbo\.)\b/i,
  /\b(?:from|join|update|into)\s+(?:\[[^\]]+\]\.)?(?:dbo|app|public)\.[A-Za-z_][\w$]*\b/i,
];
const DESTRUCTIVE_SQL_PATTERNS = [
  /\b(?:drop\s+(?:table|database|schema)|truncate\s+table|delete\s+from|alter\s+(?:login|user|role|database|server)|grant\s+|revoke\s+|xp_cmdshell|backup\s+database|restore\s+database)\b/i,
];
const ENGINEERING_BOQ_CONTEXT_PATTERNS = [
  /\b(?:boq|bill\s+of\s+quantities|scope\s+of\s+work|sow|part\s*number|qty|quantity|line\s*item|hardware\s+order|premium\s+support|solution\s+design|implementation\s+scope|appliance|firewall|switch|router|license|licence|support\s+renewal)\b/i,
  /\b(?:fortimanager|fortigate|forticare|cisco|juniper|palo\s+alto|checkpoint|aruba|meraki|sonicwall)\b/i,
  /\b(?:FMG|FGT|FC|SKU|OHC|OHF)-?[A-Z0-9][A-Z0-9-]{2,}\b/i,
];

function classifySensitiveBusinessText(text: string): {
  containsSecret: boolean;
  containsHighRiskPii: boolean;
  containsOperationalCommand: boolean;
  hasSqlDatabaseContext: boolean;
  hasEngineeringBoqContext: boolean;
  businessRelated: boolean;
  hasBusinessEmail: boolean;
  signalTypes: string[];
} {
  const signalTypes = new Set<string>();
  const containsSecret = HIGH_CONFIDENCE_SECRET_PATTERNS.some((pattern) => pattern.test(text));
  if (containsSecret) signalTypes.add("contains_secret");
  const containsHighRiskPii = containsHighRiskPiiText(text);
  if (containsHighRiskPii) signalTypes.add("contains_high_risk_pii");
  const hasBusinessEmail = Array.from(text.matchAll(BUSINESS_EMAIL_PATTERN))
    .some((match) => !PUBLIC_EMAIL_DOMAINS.has(toLower(match[1] || "")));
  if (hasBusinessEmail) signalTypes.add("contains_business_email");
  const hasSqlDatabaseContext = SQL_DATABASE_CONTEXT_PATTERNS.some((pattern) => pattern.test(text));
  if (hasSqlDatabaseContext) signalTypes.add("sql_database_context");
  const containsOperationalCommand = hasSqlDatabaseContext
    && DESTRUCTIVE_SQL_PATTERNS.some((pattern) => pattern.test(text));
  if (containsOperationalCommand) signalTypes.add("contains_operational_command");
  const hasEngineeringBoqContext = ENGINEERING_BOQ_CONTEXT_PATTERNS.some((pattern) => pattern.test(text));
  if (hasEngineeringBoqContext) signalTypes.add("engineering_boq_context");
  const businessRelated = containsHighRiskPii
    || hasBusinessEmail
    || hasSqlDatabaseContext
    || hasEngineeringBoqContext
    || BUSINESS_CONTENT_PATTERNS.some((pattern) => pattern.test(text));
  if (businessRelated) signalTypes.add("business_content");
  return {
    containsSecret,
    containsHighRiskPii,
    containsOperationalCommand,
    hasSqlDatabaseContext,
    hasEngineeringBoqContext,
    businessRelated,
    hasBusinessEmail,
    signalTypes: Array.from(signalTypes),
  };
}

function luhnCheck(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19) return false;
  let sum = 0;
  let shouldDouble = false;
  for (let idx = digits.length - 1; idx >= 0; idx -= 1) {
    let digit = Number(digits[idx]);
    if (shouldDouble) {
      digit *= 2;
      if (digit > 9) digit -= 9;
    }
    sum += digit;
    shouldDouble = !shouldDouble;
  }
  return sum % 10 === 0;
}

function containsHighRiskPiiText(text: string): boolean {
  const normalized = String(text || "");
  if (!normalized.trim()) return false;
  const cardCandidates = normalized.match(/\b(?:\d[ -]?){13,19}\b/g) || [];
  if (cardCandidates.some((candidate) => luhnCheck(candidate))) return true;
  return [
    UAE_EMIRATES_ID_STRICT_PATTERN,
    UAE_EMIRATES_ID_CONTEXT_PATTERN,
    /\b(?:ssn|social\s+security)\b[^\n\r]{0,30}\d{3}[- ]?\d{2}[- ]?\d{4}\b/i,
    /\b(?:passport|passport\s+number)\b[^\n\r]{0,30}[A-Z0-9]{6,12}\b/i,
    /\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b/i,
  ].some((pattern) => pattern.test(normalized));
}

function containsProtectedCodeContext(text: string): boolean {
  const normalized = String(text || "");
  if (!normalized.trim()) return false;
  const hasCodeShape = [
    /\bexport\s+(?:async\s+)?function\b/i,
    /\b(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(/,
    /\bclass\s+[A-Za-z_$][\w$]*\b/,
    /\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=/,
    /\bdef\s+[A-Za-z_][\w]*\s*\(/,
    /\b(?:public|private|protected)\s+(?:class|static|async|void|Task|String|int)\b/,
    /\bSELECT\b[\s\S]{0,120}\bFROM\b/i,
    /\b(?:import\s+.+\s+from|require\s*\(|module\.exports)\b/i,
  ].some((pattern) => pattern.test(normalized));
  if (!hasCodeShape) return false;
  return [
    /\b(?:internal|proprietary|private|production|repo|repository|source\s+code|patch)\b/i,
    /\b(?:auth|authentication|authorization|rbac|iam|tenant|jwt|session|middleware|payment|encryption|token)\b/i,
    /\b(?:x-tenant-id|checkRbac|verifyTenant|validateToken|accessToken|refreshToken)\b/i,
    /\b(?:src\/|app\/|server\/|middleware|\.ts|\.tsx|\.py|\.java|\.go|\.cs|package\.json|Dockerfile)\b/i,
  ].some((pattern) => pattern.test(normalized));
}

export function isAttachmentRemovalControlLabel(label: string): boolean {
  const normalized = toLower(label).replace(/\s+/g, " ").trim();
  if (!normalized) return false;
  const removeIntent = /\b(remove|delete|dismiss|cancel|clear|close)\b/.test(normalized)
    || /^(?:x|×)(?:\b|\s)/.test(normalized);
  const artifactContext =
    /\b(file|attachment|attached|image|photo|screenshot|screen shot|upload|document|pdf|spreadsheet|excel)\b/.test(normalized)
    || /\.(?:png|jpe?g|webp|gif|bmp|tiff?|pdf|csv|tsv|xlsx?|docx?|pptx?)\b/.test(normalized);
  return removeIntent && artifactContext;
}

export function classifyPasteTimeoutFallback(input: {
  destination_surface_type: PasteContextPayload["destination_surface_type"];
  source_classification_hint: CopyContextPayload["source_classification_hint"];
  sensitive: boolean;
  platform_mode: ExtensionPolicy["platform_mode"];
}): DataTransferTimeoutFallbackDecision {
  const governedDestination =
    input.destination_surface_type === "email" || input.destination_surface_type === "slack";
  const publicAiDestination = input.destination_surface_type === "ai_tool";
  const protectedMovement = input.sensitive || input.source_classification_hint === "protected";

  if (input.platform_mode === "enforce" && publicAiDestination && protectedMovement) {
    return "block";
  }
  if (governedDestination && protectedMovement) {
    return "require_justification";
  }
  return "warn";
}

export function classifySpreadsheetUploadForAi(fileMeta: Array<Record<string, unknown>>): SpreadsheetUploadClassification {
  const spreadsheetItems = fileMeta.filter((item) => {
    const name = toLower(String(item.name || ""));
    const type = toLower(String(item.type || item.mime_type || ""));
    return /\.(?:csv|tsv|xlsx?|ods)\b/.test(name)
      || type.includes("spreadsheet")
      || type.includes("excel")
      || type.includes("csv");
  });
  const signalTypes = new Set<string>();
  if (spreadsheetItems.length > 0) signalTypes.add("spreadsheet_upload");

  const combined = spreadsheetItems
    .map((item) => [
      item.name,
      item.type,
      item.mime_type,
      item.text_preview,
      item.ocr_text_preview,
    ].map((value) => String(value || "")).join(" "))
    .join("\n");
  const normalized = toLower(combined);
  const contentClassification = classifySensitiveBusinessText(combined);
  const containsSecret = contentClassification.containsSecret;
  if (containsSecret) signalTypes.add("spreadsheet_contains_secret");
  const containsHighRiskPii = contentClassification.containsHighRiskPii;
  if (containsHighRiskPii) signalTypes.add("spreadsheet_contains_high_risk_pii");

  const hasBusinessEmail = contentClassification.hasBusinessEmail;
  if (hasBusinessEmail) signalTypes.add("spreadsheet_contains_business_email");
  if (contentClassification.hasEngineeringBoqContext) signalTypes.add("engineering_boq_context");
  if (contentClassification.hasSqlDatabaseContext) signalTypes.add("sql_database_context");
  const businessRelated = contentClassification.businessRelated;
  if (businessRelated) signalTypes.add("business_spreadsheet_upload");

  if (!spreadsheetItems.length) {
    return {
      isSpreadsheet: false,
      businessRelated: false,
      containsSecret: false,
      containsHighRiskPii: false,
      signalTypes: [],
      decision: "allow",
      reasonCode: "not_spreadsheet_upload",
      explanation: "No spreadsheet upload detected.",
    };
  }
  if (containsSecret || containsHighRiskPii) {
    return {
      isSpreadsheet: true,
      businessRelated,
      containsSecret,
      containsHighRiskPii,
      signalTypes: Array.from(signalTypes),
      decision: "block",
      reasonCode: containsSecret ? "spreadsheet_contains_secret" : "spreadsheet_contains_high_risk_pii",
      explanation: containsSecret
        ? "Spreadsheet contains a high-confidence secret or credential and cannot be uploaded to public AI."
        : "Spreadsheet contains high-risk personal or payment data and cannot be uploaded to public AI.",
    };
  }
  if (businessRelated) {
    return {
      isSpreadsheet: true,
      businessRelated: true,
      containsSecret: false,
      containsHighRiskPii: false,
      signalTypes: Array.from(signalTypes),
      decision: "require_justification",
      reasonCode: "business_spreadsheet_to_public_ai",
      explanation: "Business contact/account spreadsheet upload to public AI requires a business justification.",
    };
  }
  return {
    isSpreadsheet: true,
    businessRelated: false,
    containsSecret: false,
    containsHighRiskPii: false,
    signalTypes: Array.from(signalTypes),
    decision: "allow",
    reasonCode: "generic_spreadsheet_upload",
    explanation: "Generic spreadsheet upload is not classified as business sensitive.",
  };
}

export function classifyTextPasteForAi(text: string): TextPasteClassification {
  const classification = classifySensitiveBusinessText(text);
  const signalTypes = new Set<string>(["clipboard_paste", ...classification.signalTypes]);
  if (classification.hasBusinessEmail) signalTypes.add("paste_contains_business_email");
  if (classification.businessRelated) signalTypes.add("business_text_paste");
  if (classification.containsSecret) signalTypes.add("paste_contains_secret");
  if (classification.containsHighRiskPii) signalTypes.add("paste_contains_high_risk_pii");
  if (classification.containsOperationalCommand) signalTypes.add("paste_contains_operational_command");

  if (classification.containsOperationalCommand) {
    return {
      businessRelated: true,
      containsSecret: false,
      containsHighRiskPii: false,
      containsOperationalCommand: true,
      hasSqlDatabaseContext: classification.hasSqlDatabaseContext,
      hasEngineeringBoqContext: classification.hasEngineeringBoqContext,
      hasBusinessEmail: classification.hasBusinessEmail,
      signalTypes: Array.from(signalTypes),
      decision: "block",
      reasonCode: "text_paste_contains_operational_command",
      explanation: "Pasted SQL/database text contains destructive or privileged operations and cannot be sent to public AI.",
    };
  }

  if (classification.containsSecret || classification.containsHighRiskPii) {
    return {
      businessRelated: classification.businessRelated,
      containsSecret: classification.containsSecret,
      containsHighRiskPii: classification.containsHighRiskPii,
      containsOperationalCommand: classification.containsOperationalCommand,
      hasSqlDatabaseContext: classification.hasSqlDatabaseContext,
      hasEngineeringBoqContext: classification.hasEngineeringBoqContext,
      hasBusinessEmail: classification.hasBusinessEmail,
      signalTypes: Array.from(signalTypes),
      decision: "block",
      reasonCode: classification.containsSecret ? "text_paste_contains_secret" : "text_paste_contains_high_risk_pii",
      explanation: classification.containsSecret
        ? "Pasted text contains a high-confidence secret or credential and cannot be sent to public AI."
        : "Pasted text contains high-risk personal or payment data and cannot be sent to public AI.",
    };
  }

  if (classification.businessRelated) {
    return {
      businessRelated: true,
      containsSecret: false,
      containsHighRiskPii: false,
      containsOperationalCommand: false,
      hasSqlDatabaseContext: classification.hasSqlDatabaseContext,
      hasEngineeringBoqContext: classification.hasEngineeringBoqContext,
      hasBusinessEmail: classification.hasBusinessEmail,
      signalTypes: Array.from(signalTypes),
      decision: "require_justification",
      reasonCode: "business_text_paste_to_public_ai",
      explanation: "Business/customer text pasted to public AI requires a business justification.",
    };
  }

  return {
    businessRelated: false,
    containsSecret: false,
    containsHighRiskPii: false,
    containsOperationalCommand: false,
    hasSqlDatabaseContext: false,
    hasEngineeringBoqContext: false,
    hasBusinessEmail: false,
    signalTypes: Array.from(signalTypes),
    decision: "allow",
    reasonCode: "generic_text_paste",
    explanation: "Pasted text is not classified as business sensitive.",
  };
}

function elementLabel(element: Element): string {
  const values = [
    element.getAttribute("aria-label"),
    element.getAttribute("title"),
    element.getAttribute("data-testid"),
    element.getAttribute("data-test-id"),
    element.getAttribute("data-name"),
    element.getAttribute("name"),
    element.textContent,
  ];
  const parent = element.parentElement;
  if (parent) {
    values.push(
      parent.getAttribute("aria-label"),
      parent.getAttribute("title"),
      parent.getAttribute("data-testid"),
      parent.textContent,
    );
  }
  return values.filter(Boolean).join(" ");
}

export function isPromptSubmitControlLabel(label: string): boolean {
  const normalized = toLower(label).replace(/[_-]+/g, " ");
  if (/\b(upload|attach|attachment|file|cancel|dismiss|close|stop|voice|microphone|mic)\b/.test(normalized)) {
    return false;
  }
  return /\b(send|submit)\b/.test(normalized) && /\b(prompt|message|button|chat|query|request)?\b/.test(normalized);
}

function isBlockedArtifactContainer(element: Element): boolean {
  const label = toLower(elementLabel(element));
  const explicitAttachmentContainer =
    label.includes("attachment")
    || label.includes("attached file")
    || label.includes("uploaded file")
    || label.includes("file preview")
    || label.includes("screenshot")
    || label.includes("screen shot");
  const filenameLike = /\.(?:png|jpe?g|webp|gif|bmp|tiff?|pdf|csv|tsv|xlsx?|docx?|pptx?)\b/.test(label);
  return explicitAttachmentContainer || filenameLike;
}

export function clickAttachmentRemovalControl(control: Element): boolean {
  const click = (control as { click?: unknown }).click;
  if (typeof click !== "function") return false;
  click.call(control);
  return true;
}

function rootForArtifactCleanup(target: EventTarget | null | undefined): ParentNode {
  if (target instanceof Element) {
    const composer = target.closest(
      "form, [role='form'], [data-testid*='composer'], [data-testid*='prompt'], [data-testid*='conversation'], main"
    );
    if (composer) return composer;
  }
  return document;
}

export function clearBlockedAttachmentArtifacts(root: ParentNode = document): number {
  if (typeof document === "undefined") return 0;
  let cleared = 0;

  const scope = root || document;
  for (const input of Array.from(scope.querySelectorAll<HTMLInputElement>("input[type='file']"))) {
    if (input.value || (input.files && input.files.length > 0)) {
      input.value = "";
      input.dispatchEvent(new Event("input", { bubbles: true }));
      input.dispatchEvent(new Event("change", { bubbles: true }));
      cleared += 1;
    }
  }

  const removalControls = Array.from(
    scope.querySelectorAll<Element>(
      "button, [role='button'], [aria-label], [title], [data-testid], [data-test-id]"
    )
  );
  for (const control of removalControls) {
    if (!isAttachmentRemovalControlLabel(elementLabel(control))) continue;
    if (clickAttachmentRemovalControl(control)) {
      cleared += 1;
    }
  }

  const staleContainers = Array.from(
    scope.querySelectorAll<HTMLElement>(
      "[data-testid*='attachment'], [data-testid*='upload'], [data-testid*='file'], [aria-label*='attachment'], [aria-label*='file']"
    )
  );
  for (const container of staleContainers) {
    if (!isBlockedArtifactContainer(container)) continue;
    if (container.querySelector("textarea, input:not([type='file']), [contenteditable='true']")) continue;
    container.remove();
    cleared += 1;
  }

  return cleared;
}

function scheduleBlockedArtifactCleanup(target: EventTarget | null | undefined): void {
  if (typeof window === "undefined" || typeof document === "undefined") return;
  const root = rootForArtifactCleanup(target);
  for (const delay of BLOCKED_ARTIFACT_CLEANUP_DELAYS_MS) {
    window.setTimeout(() => {
      clearBlockedAttachmentArtifacts(root);
      if (root !== document) {
        clearBlockedAttachmentArtifacts(document);
      }
    }, delay);
  }
}

function dragReleaseEvent(type: string): Event {
  const dragEventCtor = (globalThis as { DragEvent?: typeof DragEvent }).DragEvent;
  if (typeof dragEventCtor === "function") {
    try {
      return new dragEventCtor(type, { bubbles: true, cancelable: true });
    } catch {
      // Fall back to a plain event in older browser/test runtimes.
    }
  }
  return new Event(type, { bubbles: true, cancelable: true });
}

export function releaseNativeDropOverlay(target: EventTarget | null | undefined): number {
  const documentRef = typeof document !== "undefined" ? document : undefined;
  const windowRef = typeof window !== "undefined" ? window : undefined;
  const targets: EventTarget[] = [];
  const addTarget = (candidate: EventTarget | null | undefined): void => {
    if (!candidate || typeof candidate.dispatchEvent !== "function") return;
    if (targets.includes(candidate)) return;
    targets.push(candidate);
  };

  addTarget(target);
  addTarget(documentRef?.body);
  addTarget(documentRef);
  addTarget(windowRef);

  let dispatched = 0;
  for (const candidate of targets) {
    for (const eventType of ["dragleave", "dragend"]) {
      candidate.dispatchEvent(dragReleaseEvent(eventType));
      dispatched += 1;
    }
  }
  dispatched += clearNativeDropOverlays(documentRef);
  return dispatched;
}

function scheduleNativeDropOverlayRelease(target: EventTarget | null | undefined): void {
  releaseNativeDropOverlay(target);
  if (typeof window === "undefined") return;
  for (const delay of DROP_OVERLAY_RELEASE_DELAYS_MS) {
    window.setTimeout(() => releaseNativeDropOverlay(target), delay);
  }
}

type DropOverlayDocumentLike = {
  querySelectorAll?: (selector: string) => ArrayLike<unknown>;
};

function isElementNode(candidate: unknown): candidate is Element {
  const elementCtor = (globalThis as { Element?: typeof Element }).Element;
  return typeof elementCtor === "function" && candidate instanceof elementCtor;
}

function isStructuralPageElement(candidate: unknown): boolean {
  if (!isElementNode(candidate)) return false;
  const documentRef = typeof document !== "undefined" ? document : undefined;
  if (candidate === documentRef?.documentElement || candidate === documentRef?.body) return true;

  const tag = String(candidate.tagName || "").toLowerCase();
  if (["html", "body", "head", "main", "form", "nav", "aside"].includes(tag)) return true;

  const id = String(candidate.id || "").toLowerCase();
  if (["root", "app", "__next", "__nuxt"].includes(id)) return true;

  const label = toLower(
    [
      candidate.getAttribute("id"),
      candidate.getAttribute("data-testid"),
      candidate.getAttribute("data-test-id"),
      candidate.getAttribute("role"),
      candidate.getAttribute("class"),
    ].filter(Boolean).join(" ")
  );
  if (/\b(root|app-shell|application|layout|composer|conversation|thread|main)\b/.test(label)) return true;

  return false;
}

function isLikelyWholeApplicationContainer(candidate: unknown, text: string): boolean {
  if (!isElementNode(candidate)) return false;
  if (text.length > 420) return true;
  if (candidate.children.length > 8) return true;
  return !!candidate.querySelector(
    "main, nav, aside, form, textarea, [contenteditable='true'], [contenteditable='plaintext-only'], [role='textbox']"
  );
}

function isNativeDropOverlayCandidate(candidate: unknown): candidate is {
  textContent?: string | null;
  remove?: () => void;
  style?: Partial<CSSStyleDeclaration>;
} {
  const text = toLower(String((candidate as { textContent?: unknown } | null)?.textContent || ""))
    .replace(/\s+/g, " ")
    .trim();
  if (!text) return false;
  if (isStructuralPageElement(candidate)) return false;
  if (isLikelyWholeApplicationContainer(candidate, text)) return false;
  return text.includes("drop any file here")
    || (text.includes("add anything") && text.includes("drop"))
    || (text.includes("drop") && text.includes("file") && text.includes("conversation"));
}

export function clearNativeDropOverlays(root: DropOverlayDocumentLike | null | undefined = typeof document !== "undefined" ? document : undefined): number {
  if (!root || typeof root.querySelectorAll !== "function") return 0;
  const candidates = Array.from(root.querySelectorAll(
    "div, section, aside, [role='dialog'], [data-testid], [class]"
  ));
  let cleared = 0;
  for (const candidate of candidates) {
    if (!isNativeDropOverlayCandidate(candidate)) continue;
    const overlay = candidate as {
      textContent?: string | null;
      remove?: () => void;
      style?: Partial<CSSStyleDeclaration>;
    };
    if (overlay.style) {
      overlay.style.pointerEvents = "none";
      overlay.style.opacity = "0";
      overlay.style.display = "none";
    }
    if (typeof overlay.remove === "function") {
      overlay.remove();
    } else {
      overlay.textContent = "";
    }
    cleared += 1;
  }
  return cleared;
}

export type VisibleOutputCopyControlResult = {
  decision: "allow" | "block";
  reasonCode: string;
  explanation: string;
  outputSensitivity: "none" | "low" | "medium" | "high" | "critical";
  signalTypes: string[];
};

export type VisibleOutputActionType =
  | "copy_output"
  | "download_output"
  | "export_output"
  | "share_output"
  | "send_message"
  | "send_email"
  | "submit_form";

export type VisualUploadControlResult = {
  decision: "allow" | "require_justification" | "block";
  reasonCode: string;
  explanation: string;
  signalTypes: string[];
};

type RuntimeControlTransferItemLike = {
  kind?: string;
  type?: string;
  getAsFile?: () => File | null;
};

type RuntimeControlTransferLike = {
  files?: ArrayLike<File> | null;
  items?: ArrayLike<RuntimeControlTransferItemLike> | null;
  types?: ArrayLike<string> | null;
};

function normalizeDomain(raw: string): string {
  return String(raw || "").trim().toLowerCase().replace(/^www\./, "");
}

function domainMatches(candidate: string, expected: string): boolean {
  const c = normalizeDomain(candidate);
  const e = normalizeDomain(expected);
  if (!c || !e) return false;
  return c === e || c.endsWith(`.${e}`);
}

function domainStatus(domain: string, policy: ExtensionPolicy): "approved" | "blocked" | "warn" | "critical" | "unknown" {
  if (policy.critical_domains.some((item) => domainMatches(domain, item))) return "critical";
  if (policy.blocked_domains.some((item) => domainMatches(domain, item))) return "blocked";
  if (policy.warn_domains.some((item) => domainMatches(domain, item))) return "warn";
  if (policy.approved_domains.some((item) => domainMatches(domain, item))) return "approved";
  return "unknown";
}

function redact(value: string): string {
  return String(value || "")
    .replace(/\b[\w.+-]+@[\w.-]+\.\w+\b/g, "[email]")
    .replace(/\b(?:\d[ -]?){10,19}\b/g, "[number]")
    .replace(/\b(sk|api|token|secret)[-_a-z0-9]{8,}\b/gi, "[secret]")
    .slice(0, 240);
}

function hasStorageApi(): boolean {
  return typeof chrome !== "undefined" && !!chrome.storage?.local;
}

async function persistCopyContext(context: CopyContextPayload | null): Promise<void> {
  if (!hasStorageApi()) return;
  try {
    if (!context) {
      await chrome.storage.local.remove(COPY_CONTEXT_STORAGE_KEY);
      return;
    }
    await chrome.storage.local.set({ [COPY_CONTEXT_STORAGE_KEY]: context });
  } catch {
    // Non-blocking best effort.
  }
}

async function loadStoredCopyContext(): Promise<CopyContextPayload | null> {
  if (!hasStorageApi()) return null;
  try {
    const stored = await chrome.storage.local.get([COPY_CONTEXT_STORAGE_KEY]);
    const value = stored?.[COPY_CONTEXT_STORAGE_KEY];
    if (!value || typeof value !== "object") return null;
    const context = value as CopyContextPayload;
    const sourceDomain = normalizeDomain(context.source_domain);
    const ts = String(context.timestamp || "");
    if (!sourceDomain || !ts) {
      await persistCopyContext(null);
      return null;
    }
    const age = Date.now() - new Date(ts).getTime();
    if (!Number.isFinite(age) || age > COPY_CONTEXT_TTL_MS) {
      await persistCopyContext(null);
      return null;
    }
    return {
      source_url: String(context.source_url || ""),
      source_domain: sourceDomain,
      source_app_name: context.source_app_name ? String(context.source_app_name) : undefined,
      source_surface_type: context.source_surface_type || "unknown",
      source_classification_hint: context.source_classification_hint || "unknown",
      copied_text_hash: String(context.copied_text_hash || ""),
      copied_text_preview_redacted: String(context.copied_text_preview_redacted || ""),
      timestamp: ts,
    };
  } catch {
    return null;
  }
}

function toLower(value: string): string {
  return String(value || "").toLowerCase();
}

function compilePattern(pattern: string): RegExp | null {
  let source = String(pattern || "").trim();
  if (!source) return null;
  let flags = "";
  const inlineFlagMatch = source.match(/^\(\?([a-z]+)\)/i);
  if (inlineFlagMatch) {
    flags = inlineFlagMatch[1].toLowerCase();
    source = source.slice(inlineFlagMatch[0].length);
  }
  try {
    return new RegExp(source, flags);
  } catch {
    try {
      return new RegExp(source);
    } catch {
      return null;
    }
  }
}

function isPromptField(target: EventTarget | null): target is HTMLElement {
  const candidate = target as { matches?: (selector: string) => boolean } | null;
  return !!(
    candidate
    && typeof candidate.matches === "function"
    && candidate.matches(
      "textarea, [contenteditable='true'], [contenteditable='plaintext-only'], [role='textbox'], input[type='text'], input:not([type])"
    )
  );
}

const PROMPT_FIELD_SELECTOR =
  "textarea, [contenteditable='true'], [contenteditable='plaintext-only'], [role='textbox'], input[type='text'], input:not([type]), .ProseMirror";

function nearestPromptField(node: unknown): HTMLElement | null {
  const candidate = node as {
    matches?: (selector: string) => boolean;
    closest?: (selector: string) => Element | null;
    parentElement?: HTMLElement | null;
  } | null;
  if (!candidate) return null;
  if (typeof candidate.matches === "function") {
    if (isPromptField(candidate as unknown as EventTarget) || candidate.matches(".ProseMirror")) {
      return candidate as HTMLElement;
    }
    const nearestEditable = typeof candidate.closest === "function" ? candidate.closest(PROMPT_FIELD_SELECTOR) : null;
    if (nearestEditable) return nearestEditable as HTMLElement;
  }
  if (candidate.parentElement) return nearestPromptField(candidate.parentElement);
  return null;
}

function resolvePromptFieldTarget(event: Event): HTMLElement | null {
  const directTarget = nearestPromptField(event.target);
  if (directTarget) return directTarget;

  const path = typeof event.composedPath === "function" ? event.composedPath() : [];
  for (const node of path) {
    const editable = nearestPromptField(node);
    if (editable) return editable;
  }
  const activeTarget = nearestPromptField(document.activeElement);
  if (activeTarget) return activeTarget;
  const selectionAnchor = window.getSelection()?.anchorNode;
  const selectionTarget = nearestPromptField(selectionAnchor);
  if (selectionTarget) return selectionTarget;
  if (selectionAnchor?.parentElement) return nearestPromptField(selectionAnchor.parentElement);
  return document.querySelector<HTMLElement>(PROMPT_FIELD_SELECTOR);
}

function promptTargetIsConnected(target: EventTarget | null): boolean {
  const candidate = target as { isConnected?: unknown } | null;
  return candidate?.isConnected !== false;
}

function resolveApprovedPromptReplayTarget(target: EventTarget | null): EventTarget | null {
  if (promptTargetIsConnected(target) && nearestPromptField(target)) return target;
  if (typeof document === "undefined") return target;
  const activeTarget = nearestPromptField(document.activeElement);
  if (activeTarget) return activeTarget;
  const selectedTarget = typeof window !== "undefined" ? nearestPromptField(window.getSelection?.()?.anchorNode) : null;
  if (selectedTarget) return selectedTarget;
  const queriedTarget = typeof document.querySelector === "function"
    ? document.querySelector<HTMLElement>(PROMPT_FIELD_SELECTOR)
    : null;
  return queriedTarget || target;
}

function selectedText(target: EventTarget | null): string {
  const field = target as {
    value?: string;
    selectionStart?: number | null;
    selectionEnd?: number | null;
  } | null;
  if (field && typeof field.value === "string") {
    const from = field.selectionStart ?? 0;
    const to = field.selectionEnd ?? 0;
    return String(field.value || "").slice(from, to);
  }
  const selection = window.getSelection();
  return String(selection?.toString() || "");
}

function fileIsSensitive(name: string): boolean {
  const lower = toLower(name);
  return SENSITIVE_FILE_NAME_HINTS.some((hint) => lower.includes(hint)) || SENSITIVE_FILE_NAME_PATTERN.test(name);
}

function sensitivePatternHit(text: string, policy: ExtensionPolicy): boolean {
  if (UAE_EMIRATES_ID_STRICT_PATTERN.test(text) || UAE_EMIRATES_ID_CONTEXT_PATTERN.test(text)) {
    return true;
  }
  return policy.interaction_rules.sensitive_patterns.some((pattern) => {
    const compiled = compilePattern(pattern);
    if (!compiled) return false;
    return compiled.test(text);
  });
}

function businessEmailCount(text: string): number {
  let count = 0;
  for (const match of String(text || "").matchAll(BUSINESS_EMAIL_PATTERN)) {
    const domain = normalizeDomain(String(match[1] || ""));
    if (domain && !PUBLIC_EMAIL_DOMAINS.has(domain)) {
      count += 1;
    }
  }
  return count;
}

function outputCopyPolicyEnabled(policy: ExtensionPolicy): boolean {
  const intentPolicy = policy.intent_aware_action_control;
  if (!intentPolicy) return true;
  if (!intentPolicy.enabled) return false;
  return intentPolicy.mode !== "monitor";
}

export function classifyVisibleOutputCopyControl(
  text: string,
  policy: ExtensionPolicy,
): VisibleOutputCopyControlResult {
  return classifyVisibleOutputActionControl(text, policy, "copy_output");
}

export function classifyVisibleOutputActionControl(
  text: string,
  policy: ExtensionPolicy,
  action: VisibleOutputActionType,
): VisibleOutputCopyControlResult {
  const value = String(text || "");
  const businessEmails = businessEmailCount(value);
  const containsSecret = HIGH_CONFIDENCE_SECRET_PATTERNS.some((pattern) => pattern.test(value)) || sensitivePatternHit(value, policy);
  const containsHighRiskPii = containsHighRiskPiiText(value);
  const containsProtectedCode = containsProtectedCodeContext(value);
  const signalTypes = action === "copy_output" ? ["clipboard_copy", "copy_output"] : [`visible_${action}`, action];
  let outputSensitivity: VisibleOutputCopyControlResult["outputSensitivity"] = value.trim() ? "low" : "none";
  if (businessEmails > 0) {
    signalTypes.push("output_contains_business_email");
    outputSensitivity = businessEmails >= 3 ? "high" : "medium";
  }
  if (containsProtectedCode) {
    signalTypes.push("output_contains_protected_code");
    outputSensitivity = "high";
  }
  if (containsHighRiskPii) {
    signalTypes.push("output_contains_high_risk_pii");
    outputSensitivity = "critical";
  }
  if (containsSecret) {
    signalTypes.push("output_contains_secret");
    outputSensitivity = "critical";
  }

  if (!outputCopyPolicyEnabled(policy)) {
    return {
      decision: "allow",
      reasonCode: "output_copy_policy_monitor_only",
      explanation: "Visible output copy controls are monitor-only.",
      outputSensitivity,
      signalTypes,
    };
  }
  if (containsSecret) {
    return {
      decision: "block",
      reasonCode: action === "copy_output" ? "ai_output_copy_contains_secret" : "ai_output_action_contains_secret",
      explanation: "Blocked: this generated output contains a secret-like value and cannot be copied or exported.",
      outputSensitivity,
      signalTypes,
    };
  }
  if (containsHighRiskPii) {
    return {
      decision: "block",
      reasonCode: action === "copy_output" ? "ai_output_copy_contains_high_risk_pii" : "ai_output_action_contains_high_risk_pii",
      explanation: "Blocked: this generated output contains high-risk personal or payment data and cannot be copied or exported.",
      outputSensitivity,
      signalTypes,
    };
  }
  if (containsProtectedCode) {
    return {
      decision: "block",
      reasonCode: action === "copy_output" ? "ai_output_copy_contains_protected_code" : "ai_output_action_contains_protected_code",
      explanation: "Blocked: this generated output appears to contain protected internal code context and cannot be copied or exported.",
      outputSensitivity,
      signalTypes,
    };
  }
  if (businessEmails > 0) {
    return {
      decision: "block",
      reasonCode: action === "copy_output" ? "ai_output_copy_contains_business_email" : "ai_output_action_contains_business_email",
      explanation: "Blocked: this generated output contains customer/business emails and cannot be copied or exported.",
      outputSensitivity,
      signalTypes,
    };
  }
  return {
    decision: "allow",
    reasonCode: action === "copy_output" ? "visible_output_copy_allowed" : "visible_output_action_allowed",
    explanation: "Allowed: visible output action did not contain protected business data.",
    outputSensitivity,
    signalTypes,
  };
}

function shouldIncludeInlineOcrPayload(file: File): boolean {
  const type = toLower(file.type || "");
  const name = toLower(file.name || "");
  const ocrCandidate = type.startsWith("image/") || type.includes("pdf") || name.endsWith(".pdf");
  return ocrCandidate && Number(file.size || 0) > 0 && Number(file.size || 0) <= OCR_INLINE_FILE_MAX_BYTES;
}

function shouldIncludeInlineTextPreview(file: File): boolean {
  const type = toLower(file.type || "");
  const name = toLower(file.name || "");
  const textCandidate = (
    type.startsWith("text/")
    || type.includes("csv")
    || type.includes("json")
    || name.endsWith(".csv")
    || name.endsWith(".tsv")
    || name.endsWith(".txt")
    || name.endsWith(".json")
    || name.endsWith(".md")
  );
  return textCandidate && Number(file.size || 0) > 0 && Number(file.size || 0) <= TEXT_INLINE_FILE_MAX_BYTES;
}

function isVisualUploadMeta(item: Record<string, unknown>): boolean {
  const name = toLower(String(item.name || ""));
  const type = toLower(String(item.mime_type || item.type || ""));
  return (
    type.startsWith("image/")
    || type.includes("pdf")
    || name.endsWith(".pdf")
    || name.endsWith(".png")
    || name.endsWith(".jpg")
    || name.endsWith(".jpeg")
    || name.endsWith(".webp")
    || name.endsWith(".tiff")
    || name.endsWith(".bmp")
  );
}

function isVisualRuntimeControlFile(file: File): boolean {
  return isVisualUploadMeta({
    name: file.name,
    type: file.type,
    mime_type: file.type,
  });
}

function isScreenshotLikeMeta(item: Record<string, unknown>): boolean {
  const name = toLower(String(item.name || ""));
  return (
    name.includes("screenshot")
    || name.includes("screen shot")
    || name.includes("screen_shot")
    || name.includes("capture")
  );
}

function hasVerifiedExtractedText(item: Record<string, unknown>): boolean {
  return ["ocr_text", "extracted_text", "text", "text_preview"].some((field) =>
    String(item[field] || "").trim().length > 0
  );
}

function extractedTextFromMeta(items: Array<Record<string, unknown>>): string {
  return items.map((item) => [
    item.ocr_text,
    item.ocr_text_preview,
    item.extracted_text,
    item.text,
    item.text_preview,
  ].map((value) => String(value || "")).join(" ")).join("\n");
}

export function classifyVisualUploadControl(
  fileMeta: Array<Record<string, unknown>>,
  policy: ExtensionPolicy,
  destinationSurface: "email" | "slack" | "ai_tool" | "saas" | "unknown",
): VisualUploadControlResult {
  const visualFiles = fileMeta.filter((item) => isVisualUploadMeta(item));
  if (!visualFiles.length || policy.platform_mode !== "enforce") {
    return {
      decision: "allow",
      reasonCode: "visual_upload_not_applicable",
      explanation: "No enforce-mode visual upload control applied.",
      signalTypes: [],
    };
  }
  const highRiskDestination = ["ai_tool", "email", "slack"].includes(destinationSurface);
  const unverifiedVisual = visualFiles.some((item) => !hasVerifiedExtractedText(item));
  const textClassification = classifySensitiveBusinessText(extractedTextFromMeta(visualFiles));
  if (highRiskDestination && textClassification.containsSecret) {
    return {
      decision: "block",
      reasonCode: "visual_contains_secret",
      explanation: "Screenshot/image/PDF contains a high-confidence secret or credential and cannot be transferred to this destination.",
      signalTypes: ["visual_content_upload", "visual_contains_secret"],
    };
  }
  if (highRiskDestination && textClassification.containsHighRiskPii) {
    return {
      decision: "block",
      reasonCode: "visual_contains_high_risk_pii",
      explanation: "Screenshot/image/PDF contains high-risk personal or payment data and cannot be transferred to this destination.",
      signalTypes: ["visual_content_upload", "visual_contains_high_risk_pii"],
    };
  }
  if (highRiskDestination && destinationSurface === "ai_tool" && textClassification.businessRelated) {
    const signalTypes = ["visual_content_upload", "visual_business_content"];
    if (textClassification.hasBusinessEmail) signalTypes.push("visual_contains_business_email");
    if (textClassification.hasSqlDatabaseContext || textClassification.hasEngineeringBoqContext) {
      signalTypes.push("visual_engineering_context");
    }
    return {
      decision: "require_justification",
      reasonCode: "visual_business_content_to_public_ai",
      explanation: "Screenshot/image/PDF appears to contain business or engineering context and requires a business justification before uploading to public AI.",
      signalTypes,
    };
  }
  if (!highRiskDestination || !unverifiedVisual) {
    return {
      decision: "allow",
      reasonCode: "visual_upload_verified_or_low_risk",
      explanation: "Visual upload has extracted text or destination is lower risk.",
      signalTypes: ["visual_content_upload"],
    };
  }
  const signalTypes = ["visual_content_upload", "unverified_visual_content"];
  if (visualFiles.some((item) => isScreenshotLikeMeta(item))) {
    signalTypes.push("screenshot_upload");
  }
  return {
    decision: "block",
    reasonCode: "unverified_visual_content_upload",
    explanation: "Screenshot/image/PDF uploads to AI or collaboration tools are blocked until OCR inspection is verified.",
    signalTypes,
  };
}

export function attachVisualClassificationEvidence(
  fileMeta: Array<Record<string, unknown>>,
  decision: VisualUploadControlResult,
): Array<Record<string, unknown>> {
  const isClassifiedVisualDecision = [
    "visual_business_content_to_public_ai",
    "visual_contains_secret",
    "visual_contains_high_risk_pii",
  ].includes(decision.reasonCode);
  return fileMeta.map((item) => ({
    ...item,
    visual_classification: isVisualUploadMeta(item) && isClassifiedVisualDecision
      ? {
        business_related: decision.reasonCode === "visual_business_content_to_public_ai",
        contains_secret: decision.reasonCode === "visual_contains_secret",
        contains_high_risk_pii: decision.reasonCode === "visual_contains_high_risk_pii",
        decision: decision.decision,
        reason_code: decision.reasonCode,
        signal_types: decision.signalTypes,
      }
      : undefined,
  }));
}

export function classifyDroppedFileTransferForDestination(
  fileMeta: Array<Record<string, unknown>>,
  policy: ExtensionPolicy,
  destinationSurface: PasteContextPayload["destination_surface_type"],
): DroppedFileTransferDecision {
  const signalTypes = ["drag_drop_file_upload"];
  const visualDecision = classifyVisualUploadControl(fileMeta, policy, destinationSurface);
  signalTypes.push(...visualDecision.signalTypes);
  if (visualDecision.decision !== "allow") {
    return {
      decision: visualDecision.decision,
      reasonCode: visualDecision.reasonCode,
      explanation: visualDecision.explanation,
      signalTypes,
      recommendedAction: visualDecision.decision === "require_justification"
        ? "capture_business_justification"
        : "route_to_governance",
    };
  }

  const spreadsheetDecision = destinationSurface === "ai_tool"
    ? classifySpreadsheetUploadForAi(fileMeta)
    : classifySpreadsheetUploadForAi([]);
  signalTypes.push(...spreadsheetDecision.signalTypes);
  if (spreadsheetDecision.decision !== "allow") {
    return {
      decision: spreadsheetDecision.decision,
      reasonCode: spreadsheetDecision.reasonCode,
      explanation: spreadsheetDecision.explanation,
      signalTypes,
      recommendedAction: spreadsheetDecision.decision === "require_justification"
        ? "capture_business_justification"
        : "route_to_governance",
    };
  }

  const sensitiveFileName = fileMeta.some((item) => fileIsSensitive(String(item.name || "")));
  if (policy.platform_mode === "enforce" && sensitiveFileName) {
    return {
      decision: "block",
      reasonCode: "sensitive_file_upload",
      explanation: "Sensitive file upload blocked by runtime policy.",
      signalTypes: [...signalTypes, "sensitive_file_name_hint"],
      recommendedAction: "route_to_governance",
    };
  }

  return {
    decision: "allow",
    reasonCode: "drag_drop_file_upload_review",
    explanation: "Dropped file upload must be reviewed before the destination application receives the file.",
    signalTypes,
    recommendedAction: "use_controlled_file_picker_after_review",
  };
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunkSize = 0x8000;
  for (let idx = 0; idx < bytes.length; idx += chunkSize) {
    binary += String.fromCharCode(...bytes.subarray(idx, idx + chunkSize));
  }
  return btoa(binary);
}

function readUint16(bytes: Uint8Array, offset: number): number {
  return bytes[offset] | (bytes[offset + 1] << 8);
}

function readUint32(bytes: Uint8Array, offset: number): number {
  return (
    bytes[offset]
    | (bytes[offset + 1] << 8)
    | (bytes[offset + 2] << 16)
    | (bytes[offset + 3] << 24)
  ) >>> 0;
}

async function inflateRaw(bytes: Uint8Array): Promise<Uint8Array | null> {
  const Decompression = globalThis.DecompressionStream;
  if (typeof Decompression !== "function") return null;
  try {
    const stream = new Blob([new Uint8Array(bytes).buffer]).stream().pipeThrough(new Decompression("deflate-raw"));
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}

async function readZipEntries(bytes: Uint8Array, wanted: (name: string) => boolean): Promise<Map<string, Uint8Array>> {
  const entries = new Map<string, Uint8Array>();
  const decoder = new TextDecoder();
  let offset = 0;
  while (offset + 30 <= bytes.length && readUint32(bytes, offset) === 0x04034b50) {
    const flags = readUint16(bytes, offset + 6);
    const method = readUint16(bytes, offset + 8);
    const compressedSize = readUint32(bytes, offset + 18);
    const uncompressedSize = readUint32(bytes, offset + 22);
    const nameLength = readUint16(bytes, offset + 26);
    const extraLength = readUint16(bytes, offset + 28);
    const nameStart = offset + 30;
    const dataStart = nameStart + nameLength + extraLength;
    const name = decoder.decode(bytes.slice(nameStart, nameStart + nameLength));

    if ((flags & 0x08) !== 0 || compressedSize <= 0 || dataStart + compressedSize > bytes.length) {
      break;
    }
    const compressed = bytes.slice(dataStart, dataStart + compressedSize);
    if (wanted(name)) {
      if (method === 0) {
        entries.set(name, compressed);
      } else if (method === 8) {
        const inflated = await inflateRaw(compressed);
        if (inflated && (!uncompressedSize || inflated.length === uncompressedSize)) {
          entries.set(name, inflated);
        }
      }
    }
    offset = dataStart + compressedSize;
  }
  return entries;
}

function xmlToText(xml: string): string {
  return xml
    .replace(/<[^>]+>/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/\s+/g, " ")
    .trim();
}

async function extractSpreadsheetTextPreview(file: File): Promise<string> {
  const type = toLower(file.type || "");
  const name = toLower(file.name || "");
  const xlsxCandidate = name.endsWith(".xlsx") || type.includes("spreadsheetml.sheet");
  if (!xlsxCandidate || Number(file.size || 0) <= 0 || Number(file.size || 0) > SPREADSHEET_INLINE_FILE_MAX_BYTES) {
    return "";
  }
  const bytes = new Uint8Array(await file.arrayBuffer());
  const decoder = new TextDecoder();
  const entries = await readZipEntries(bytes, (entryName) =>
    entryName === "xl/sharedStrings.xml"
    || /^xl\/worksheets\/sheet\d+\.xml$/i.test(entryName)
  );
  const parts: string[] = [];
  const shared = entries.get("xl/sharedStrings.xml");
  if (shared) parts.push(xmlToText(decoder.decode(shared)));
  for (const [entryName, value] of entries) {
    if (!/^xl\/worksheets\/sheet\d+\.xml$/i.test(entryName)) continue;
    parts.push(xmlToText(decoder.decode(value)));
  }
  return parts.join(" ").replace(/\s+/g, " ").trim().slice(0, TEXT_INLINE_PREVIEW_MAX_CHARS);
}

async function fileMeta(input: HTMLInputElement): Promise<Array<Record<string, unknown>>> {
  const files = input.files ? Array.from(input.files) : [];
  return buildRuntimeControlFileMeta(files);
}

export async function buildRuntimeControlFileMeta(files: File[]): Promise<Array<Record<string, unknown>>> {
  const mapped = await Promise.all(files.map(async (file) => {
    const entry: Record<string, unknown> = {
      name: file.name,
      size: file.size,
      type: file.type,
      mime_type: file.type,
    };
    if (shouldIncludeInlineTextPreview(file)) {
      try {
        const text = await file.text();
        entry.text_preview = String(text || "").slice(0, TEXT_INLINE_PREVIEW_MAX_CHARS);
        entry.text_preview_truncated = String(text || "").length > TEXT_INLINE_PREVIEW_MAX_CHARS;
        entry.inline_text_preview = true;
      } catch {
        // Fall through with metadata-only payload.
      }
      return entry;
    }
    try {
      const spreadsheetText = await extractSpreadsheetTextPreview(file);
      if (spreadsheetText) {
        entry.text_preview = spreadsheetText;
        entry.text_preview_truncated = spreadsheetText.length >= TEXT_INLINE_PREVIEW_MAX_CHARS;
        entry.inline_text_preview = true;
        entry.inline_text_source = "xlsx";
        return entry;
      }
    } catch {
      // Fall through with metadata-only payload.
    }
    if (!shouldIncludeInlineOcrPayload(file)) return entry;
    try {
      const buffer = await file.arrayBuffer();
      entry.content_b64 = bytesToBase64(new Uint8Array(buffer));
      entry.content_encoding = "base64";
      entry.inline_ocr_payload = true;
    } catch {
      // Fall through with metadata-only payload.
    }
    return entry;
  }));
  return mapped;
}

function arrayLikeValues<T>(items: ArrayLike<T> | null | undefined): T[] {
  if (!items) return [];
  const values: T[] = [];
  for (let idx = 0; idx < Number(items.length || 0); idx += 1) {
    const item = items[idx];
    if (item) values.push(item);
  }
  return values;
}

function runtimeControlFilesFromTransfer(transfer: RuntimeControlTransferLike | null | undefined): File[] {
  const files: File[] = [];
  const seen = new Set<File>();
  const addFile = (file: File | null | undefined): void => {
    if (!file || seen.has(file)) return;
    seen.add(file);
    files.push(file);
  };
  for (const file of arrayLikeValues(transfer?.files)) {
    addFile(file);
  }
  for (const item of arrayLikeValues(transfer?.items)) {
    if (String(item.kind || "").toLowerCase() !== "file") continue;
    if (typeof item.getAsFile !== "function") continue;
    addFile(item.getAsFile());
  }
  return files;
}

function transferLooksLikeFileDrag(transfer: RuntimeControlTransferLike | null | undefined): boolean {
  if (!transfer) return false;
  if (runtimeControlFilesFromTransfer(transfer).length > 0) return true;
  for (const type of arrayLikeValues(transfer.types)) {
    if (String(type || "").toLowerCase() === "files") return true;
  }
  return false;
}

export function suppressNativeFileDragOverlay(event: DragEvent): boolean {
  if (!transferLooksLikeFileDrag(event.dataTransfer)) return false;
  event.preventDefault();
  event.stopImmediatePropagation();
  event.stopPropagation();
  scheduleNativeDropOverlayRelease(event.target);
  return true;
}

export async function buildRuntimeControlTransferFileMeta(
  transfer: RuntimeControlTransferLike | null | undefined,
): Promise<Array<Record<string, unknown>>> {
  return buildRuntimeControlFileMeta(runtimeControlFilesFromTransfer(transfer));
}

function inferAppName(domain: string): string | undefined {
  const value = normalizeDomain(domain);
  if (!value) return undefined;
  if (value.includes("openai") || value.includes("chatgpt")) return "ChatGPT";
  if (value.includes("claude") || value.includes("anthropic")) return "Claude";
  if (value.includes("gemini") || value.includes("google")) return "Gemini";
  if (value.includes("slack")) return "Slack";
  if (value.includes("outlook") || value.includes("mail.google")) return "Email";
  if (value.includes("copilot")) return "Copilot";
  return undefined;
}

function isExternalDomain(domain: string): boolean {
  const normalized = normalizeDomain(domain);
  if (!normalized) return true;
  if (normalized.endsWith(".local")) return false;
  const internalHints = ["internal", "intranet", "corp", "company", "acme.ai", "localhost"];
  return !internalHints.some((hint) => normalized === hint || normalized.endsWith(`.${hint}`));
}

function inferSourceSurface(domain: string): CopyContextPayload["source_surface_type"] {
  const normalized = normalizeDomain(domain);
  if (!normalized) return "unknown";
  if (normalized.includes("mail.google") || normalized.includes("outlook")) return "email";
  if (normalized.includes("slack")) return "slack";
  if (
    normalized.includes("openai")
    || normalized.includes("chatgpt")
    || normalized.includes("claude")
    || normalized.includes("anthropic")
    || normalized.includes("gemini")
    || normalized.includes("perplexity")
  ) {
    return "ai_tool";
  }
  if (!isExternalDomain(normalized)) return "internal_app";
  if (normalized.includes("docs") || normalized.includes("notion") || normalized.includes("confluence")) return "document";
  return "unknown";
}

function inferSourceClassification(surface: CopyContextPayload["source_surface_type"], domain: string): CopyContextPayload["source_classification_hint"] {
  if (surface === "internal_app" || surface === "document") return "protected";
  const normalized = normalizeDomain(domain);
  if (!isExternalDomain(normalized)) return "protected";
  return "unknown";
}

function inferDestinationSurface(domain: string): PasteContextPayload["destination_surface_type"] {
  const normalized = normalizeDomain(domain);
  if (!normalized) return "unknown";
  if (normalized.includes("mail.google") || normalized.includes("outlook")) return "email";
  if (normalized.includes("slack")) return "slack";
  if (
    normalized.includes("openai")
    || normalized.includes("chatgpt")
    || normalized.includes("claude")
    || normalized.includes("anthropic")
    || normalized.includes("gemini")
    || normalized.includes("copilot")
    || normalized.includes("perplexity")
    || normalized.endsWith(".ai")
  ) {
    return "ai_tool";
  }
  if (!isExternalDomain(normalized)) return "saas";
  return "unknown";
}

function inferInputContext(target: EventTarget | null): PasteContextPayload["destination_input_context"] {
  const element = target as {
    tagName?: string;
    getAttribute?: (name: string) => string | null;
    matches?: (selector: string) => boolean;
  } | null;
  const tag = String(element?.tagName || "").toUpperCase();
  if (tag === "TEXTAREA") return "compose_box";
  if (tag === "INPUT") return "form_field";
  if (element && typeof element.matches === "function" && element.matches("[contenteditable='true'], [role='textbox']")) return "chat_box";
  return "unknown";
}

function visibleActionFromTarget(target: EventTarget | null, fallbackAction?: VisibleOutputActionType): VisibleOutputActionType | null {
  if (fallbackAction) return fallbackAction;
  if (!(target instanceof Element)) return null;
  const control = target.closest("button, a, [role='button'], input[type='button'], input[type='submit']");
  if (!(control instanceof HTMLElement)) return null;
  const label = toLower(
    [
      control.getAttribute("aria-label"),
      control.getAttribute("title"),
      control.getAttribute("value"),
      control.textContent,
    ].filter(Boolean).join(" "),
  );
  if (/\b(download|save)\b/.test(label)) return "download_output";
  if (/\b(export|csv|pdf)\b/.test(label)) return "export_output";
  if (/\bshare\b/.test(label)) return "share_output";
  if (/\b(send email|email)\b/.test(label)) return "send_email";
  if (/\b(send|message)\b/.test(label)) return "send_message";
  if (/\b(submit|post|publish)\b/.test(label)) return "submit_form";
  return null;
}

function dispatchPromptTextMutationEvents(target: EventTarget | null, text: string): void {
  const eventTarget = target as { dispatchEvent?: (event: Event) => boolean } | null;
  if (!eventTarget || typeof eventTarget.dispatchEvent !== "function") return;
  try {
    eventTarget.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    eventTarget.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
    if (typeof InputEvent === "function") {
      eventTarget.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: text }));
    }
    if (typeof KeyboardEvent === "function") {
      eventTarget.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true, composed: true, key: " " }));
    }
  } catch {
    try {
      eventTarget.dispatchEvent(new Event("input", { bubbles: true }));
    } catch {
      // Best effort only: browser editors vary heavily, and failure here should not break the page.
    }
  }
}

function normalizedPromptText(value: string): string {
  return value.replace(/\s+/g, " ").trim();
}

function promptContainsExpectedText(target: EventTarget | null, expectedText: string): boolean {
  const expected = normalizedPromptText(expectedText).slice(0, 160);
  if (!expected) return true;
  return normalizedPromptText(promptText(target)).includes(expected);
}

export function insertText(target: EventTarget | null, text: string): boolean {
  const field = target as {
    value?: string;
    selectionStart?: number | null;
    selectionEnd?: number | null;
    focus?: () => void;
    dispatchEvent?: (event: Event) => boolean;
  } | null;
  if (field && typeof field.value === "string") {
    field.focus?.();
    const from = field.selectionStart ?? 0;
    const to = field.selectionEnd ?? 0;
    const current = String(field.value || "");
    field.value = `${current.slice(0, from)}${text}${current.slice(to)}`;
    const cursor = from + text.length;
    field.selectionStart = cursor;
    field.selectionEnd = cursor;
    dispatchPromptTextMutationEvents(target, text);
    return true;
  }
  const element = target as HTMLElement | null;
  if (element?.isContentEditable || element?.matches?.(".ProseMirror, [role='textbox']")) {
    element.focus();
    const selection = window.getSelection?.();
    if (selection && element.isConnected) {
      const range = document.createRange();
      range.selectNodeContents(element);
      range.collapse(false);
      selection.removeAllRanges();
      selection.addRange(range);
    }
    const inserted = typeof document.execCommand === "function" && document.execCommand("insertText", false, text);
    if (!inserted || !promptContainsExpectedText(element, text)) {
      element.textContent = `${promptText(element)}${text}`;
    }
    dispatchPromptTextMutationEvents(element, text);
    return promptText(element).trim().length > 0;
  }
  return false;
}

function isDisabledPromptControl(element: HTMLElement): boolean {
  const nativeDisabled = (element as HTMLButtonElement | HTMLInputElement).disabled === true;
  return nativeDisabled || element.getAttribute("aria-disabled") === "true" || element.getAttribute("disabled") !== null;
}

function promptSubmitSearchRoots(target: EventTarget | null): ParentNode[] {
  const roots: ParentNode[] = [];
  const targetElement = nearestPromptField(target);
  if (targetElement && typeof targetElement.closest === "function") {
    const composer = targetElement.closest(
      "form, [role='form'], [data-testid*='composer'], [data-testid*='prompt'], [data-testid*='conversation']"
    );
    if (composer) roots.push(composer);
  }
  roots.push(document);
  return roots;
}

function clickPromptSubmitControl(target: EventTarget | null): boolean {
  for (const root of promptSubmitSearchRoots(target)) {
    const controls = Array.from(root.querySelectorAll("button, [role='button'], input[type='submit']"));
    for (const control of controls) {
      if (isDisabledPromptControl(control as HTMLElement)) continue;
      if (!isPromptSubmitControlLabel(elementLabel(control))) continue;
      const click = (control as { click?: unknown }).click;
      if (typeof click !== "function") continue;
      click.call(control);
      return true;
    }
  }
  return false;
}

export function schedulePromptSubmitWhenReady(target: EventTarget | null, expectedText = ""): void {
  let submitted = false;
  let rehydrated = false;
  let replayTarget = resolveApprovedPromptReplayTarget(target);
  for (const delayMs of [120, 300, 650, 1100, 1700, 2400]) {
    window.setTimeout(() => {
      if (submitted) return;
      replayTarget = resolveApprovedPromptReplayTarget(replayTarget);
      if (expectedText && !promptContainsExpectedText(replayTarget, expectedText)) {
        if (!rehydrated) {
          rehydrated = insertText(replayTarget, expectedText);
        }
        return;
      }
      submitted = clickPromptSubmitControl(replayTarget);
    }, delayMs);
  }
}

function schedulePromptSubmit(target: EventTarget | null): void {
  schedulePromptSubmitWhenReady(target);
}

function promptText(target: EventTarget | null): string {
  const field = target as { value?: unknown; innerText?: unknown; textContent?: unknown } | null;
  if (field && typeof field.value === "string") return field.value;
  if (field && typeof field.innerText === "string") return field.innerText;
  if (field && typeof field.textContent === "string") return field.textContent;
  return "";
}

function clearPromptText(target: EventTarget | null): void {
  const field = target as {
    value?: string;
    selectionStart?: number | null;
    selectionEnd?: number | null;
    dispatchEvent?: (event: Event) => boolean;
  } | null;
  if (field && typeof field.value === "string") {
    field.value = "";
    field.selectionStart = 0;
    field.selectionEnd = 0;
    field.dispatchEvent?.(new Event("input", { bubbles: true }));
    return;
  }
  const element = target as HTMLElement | null;
  if (element?.isContentEditable || element?.matches?.(".ProseMirror, [role='textbox']")) {
    element.textContent = "";
    element.dispatchEvent(new InputEvent("input", { bubbles: true, inputType: "deleteContentBackward" }));
  }
}

async function sha256(value: string): Promise<string> {
  if (!value) return "";
  const input = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-256", input);
  const bytes = new Uint8Array(digest);
  return Array.from(bytes).map((item) => item.toString(16).padStart(2, "0")).join("");
}

export function installDataTransferHooks(options: DataTransferHookOptions): () => void {
  let warnGateUntil = 0;
  let lastCopyContext: CopyContextPayload | null = null;
  let composerQuarantineBypass = false;
  const lastComposerText = new WeakMap<HTMLElement, string>();
  const bypassUploadChange = new WeakMap<HTMLInputElement, number>();
  const BYPASS_UPLOAD_EVENT_FLAG = Symbol("hawkBypassUploadSyntheticChange");
  const trackedFileInputs = new Set<HTMLInputElement>();
  const emitHookTelemetry = (payload: Record<string, unknown>): Promise<boolean> =>
    emitNonBlockingDataTransferTelemetry(options.onTelemetry, payload);

  const markBypassUploadChange = (input: HTMLInputElement): void => {
    const pending = bypassUploadChange.get(input) ?? 0;
    bypassUploadChange.set(input, pending + 1);
  };

  const shouldBypassUploadChange = (event: Event, input: HTMLInputElement): boolean => {
    const eventRecord = event as Event & Record<string | symbol, unknown>;
    if (eventRecord[BYPASS_UPLOAD_EVENT_FLAG] === true) {
      return true;
    }
    const pending = bypassUploadChange.get(input) ?? 0;
    if (pending <= 0) {
      return false;
    }
    eventRecord[BYPASS_UPLOAD_EVENT_FLAG] = true;
    if (pending <= 1) {
      bypassUploadChange.delete(input);
    } else {
      bypassUploadChange.set(input, pending - 1);
    }
    return true;
  };

  const blockWithArtifactCleanup = async (
    target: EventTarget | null | undefined,
    input: DataTransferBlockInput,
  ): Promise<void> => {
    scheduleBlockedArtifactCleanup(target);
    await options.onBlock(input);
    scheduleBlockedArtifactCleanup(target);
  };

  const resumeApprovedPromptPaste = (
    target: EventTarget | null,
    text: string,
    destinationSurface: PasteContextPayload["destination_surface_type"],
  ): void => {
    if (!text) return;
    composerQuarantineBypass = true;
    const inserted = insertText(target, text);
    composerQuarantineBypass = false;
    if (target instanceof HTMLElement) {
      lastComposerText.set(target, promptText(target));
    }
    if (inserted && destinationSurface === "ai_tool") {
      schedulePromptSubmitWhenReady(target, text);
    }
  };

  const maybeBlockVisualTransfer = (
    event: Event,
    transfer: RuntimeControlTransferLike | null | undefined,
    sourceAction: "clipboard_paste" | "drag_drop",
  ): boolean => {
    const files = runtimeControlFilesFromTransfer(transfer);
    if (!files.some((file) => isVisualRuntimeControlFile(file))) return false;

    const destinationDomain = normalizeDomain(location.hostname);
    const destinationSurface = inferDestinationSurface(destinationDomain);
    const highRiskDestination =
      destinationSurface === "email" || destinationSurface === "slack" || destinationSurface === "ai_tool";
    if (options.policy.platform_mode !== "enforce" || !highRiskDestination) return false;

    event.preventDefault();
    event.stopImmediatePropagation();
    event.stopPropagation();
    if (sourceAction === "drag_drop") {
      scheduleNativeDropOverlayRelease(event.target);
    }

    void (async () => {
      const fileMetaItems = await buildRuntimeControlFileMeta(files);
      const visualUploadDecision = classifyVisualUploadControl(fileMetaItems, options.policy, destinationSurface);
      const fileMetaWithVisualEvidence = attachVisualClassificationEvidence(fileMetaItems, visualUploadDecision);
      const sourceDomain = normalizeDomain(location.hostname);
      const sourceSurface = inferSourceSurface(sourceDomain);
      const sourceContext: CopyContextPayload = {
        source_url: location.href,
        source_domain: sourceDomain,
        source_app_name: inferAppName(sourceDomain),
        source_surface_type: sourceSurface,
        source_classification_hint: "protected",
        copied_text_hash: await sha256(
          fileMetaWithVisualEvidence.map((item) => `${String(item.name || "")}:${String(item.size || "")}:${String(item.type || "")}`).join("|")
        ),
        copied_text_preview_redacted: redact(fileMetaWithVisualEvidence.map((item) => String(item.name || "visual_upload")).join(", ")),
        timestamp: new Date().toISOString(),
      };
      const pasteContext: PasteContextPayload = {
        destination_url: location.href,
        destination_domain: destinationDomain,
        destination_app_name: inferAppName(destinationDomain),
        destination_surface_type: destinationSurface,
        destination_input_context: inferInputContext(event.target),
        timestamp: new Date().toISOString(),
      };
      const signalTypes = [sourceAction, ...visualUploadDecision.signalTypes, visualUploadDecision.reasonCode];

      if (visualUploadDecision.decision === "require_justification") {
        const policyDecision: DataTransferDecisionResponse = {
          decision: "require_justification",
          reason_code: visualUploadDecision.reasonCode,
          explanation: visualUploadDecision.explanation,
          recommended_action: "capture_business_justification",
          justification_required: true,
          policy_version: options.policy.policy_version,
          platform_mode: options.policy.platform_mode,
        };
        const justificationResult = await options.onRequireJustification({
          domain: destinationDomain,
          reason: policyDecision.reason_code,
          recommendation: policyDecision.explanation,
        });
        if (justificationResult.action === "cancel") {
          await emitHookTelemetry({
            event_type: "file_upload_detected",
            action_taken: sourceAction === "clipboard_paste"
              ? "require_justification_cancel_visual_paste"
              : "require_justification_cancel_visual_drop",
            input_signal_types: [...signalTypes, "require_justification"],
            file_meta: fileMetaWithVisualEvidence,
            source_context: sourceContext,
            paste_context: pasteContext,
            policy_decision: policyDecision,
          });
          await blockWithArtifactCleanup(event.target, {
            domain: destinationDomain,
            reason: "Visual transfer cancelled because no justification was provided.",
          });
          return;
        }
        let justificationDecision: DataTransferJustificationResponse;
        try {
          justificationDecision = await options.onDataTransferJustify({
            ...justificationPayloadFields(justificationResult),
            copy_context: sourceContext,
            paste_context: pasteContext,
            file_meta: fileMetaWithVisualEvidence,
            policy_decision: {
              decision: "require_justification",
              reason_code: policyDecision.reason_code,
              policy_version: policyDecision.policy_version,
              platform_mode: options.policy.platform_mode,
            },
            policy_version: options.policy.policy_version,
            platform_mode: options.policy.platform_mode,
          });
        } catch {
          justificationDecision = {
            decision: "block",
            reason_code: "justification_backend_failed",
            explanation: "Justification could not be verified.",
            recommended_action: "route_to_governance",
          };
        }
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: justificationDecision.decision === "allow"
            ? "allow_visual_transfer_after_justification"
            : "block_visual_transfer_after_justification",
          input_signal_types: [...signalTypes, "require_justification"],
          file_meta: fileMetaWithVisualEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: policyDecision,
          justification_reason_code: justificationDecision.reason_code,
        });
        if (justificationDecision.decision !== "allow") {
          await blockWithArtifactCleanup(event.target, {
            domain: destinationDomain,
            reason: justificationDecision.explanation,
          });
        }
        return;
      }

      await emitHookTelemetry({
        event_type: "file_upload_detected",
        action_taken: sourceAction === "clipboard_paste"
          ? "block_unverified_visual_paste"
          : "block_unverified_visual_drop",
        input_signal_types: signalTypes,
        file_meta: fileMetaWithVisualEvidence,
        source_context: sourceContext,
        paste_context: pasteContext,
        policy_decision: {
          decision: "block",
          reason_code: visualUploadDecision.reasonCode,
          explanation: visualUploadDecision.explanation,
          platform_mode: options.policy.platform_mode,
          policy_version: options.policy.policy_version,
        },
      });
      await blockWithArtifactCleanup(event.target, {
        domain: destinationDomain,
        reason: visualUploadDecision.explanation,
      });
    })();

    return true;
  };

  const copyListener = (event: ClipboardEvent): void => {
    const text = selectedText(event.target);
    if (!text.trim()) return;
    const visibleOutputDecision = classifyVisibleOutputCopyControl(text, options.policy);
    if (visibleOutputDecision.decision === "block" && inferSourceSurface(normalizeDomain(location.hostname)) === "ai_tool") {
      event.preventDefault();
      event.stopImmediatePropagation();
      event.stopPropagation();
      void (async () => {
        const source_domain = normalizeDomain(location.hostname);
        const preview = redact(text);
        const hash = await sha256(text);
        await emitHookTelemetry({
          event_type: "clipboard_copy_detected",
          action_taken: "block:local_output_copy_policy",
          action_type: "copy_output",
          decision_badge: "Blocked Output Copy",
          input_signal_types: visibleOutputDecision.signalTypes,
          copied_text_hash: hash,
          copied_text_preview_redacted: preview,
          output_text_preview_redacted: preview,
          output_sensitivity: visibleOutputDecision.outputSensitivity,
          reason_code: visibleOutputDecision.reasonCode,
        });
        await options.onBlock({
          domain: source_domain,
          reason: visibleOutputDecision.explanation,
        });
      })();
      return;
    }
    void (async () => {
      const source_domain = normalizeDomain(location.hostname);
      const source_surface_type = inferSourceSurface(source_domain);
      const source_classification_hint = inferSourceClassification(source_surface_type, source_domain);
      const preview = redact(text);
      const context: CopyContextPayload = {
        source_url: location.href,
        source_domain,
        source_app_name: inferAppName(source_domain),
        source_surface_type,
        source_classification_hint,
        copied_text_hash: "",
        copied_text_preview_redacted: preview,
        timestamp: new Date().toISOString(),
      };
      lastCopyContext = context;
      await persistCopyContext(context);
      context.copied_text_hash = await sha256(text);
      lastCopyContext = context;
      await persistCopyContext(context);
      await emitHookTelemetry({
        event_type: "clipboard_copy_detected",
        action_taken: "observed",
        input_signal_types: ["clipboard_copy"],
        copied_text_hash: context.copied_text_hash,
        copied_text_preview_redacted: preview,
        source_context: context,
      });
    })();
  };

  const cutListener = (event: ClipboardEvent): void => {
    const text = selectedText(event.target);
    if (!text.trim()) return;
    void (async () => {
      const source_domain = normalizeDomain(location.hostname);
      const source_surface_type = inferSourceSurface(source_domain);
      const source_classification_hint = inferSourceClassification(source_surface_type, source_domain);
      const preview = redact(text);
      const context: CopyContextPayload = {
        source_url: location.href,
        source_domain,
        source_app_name: inferAppName(source_domain),
        source_surface_type,
        source_classification_hint,
        copied_text_hash: "",
        copied_text_preview_redacted: preview,
        timestamp: new Date().toISOString(),
      };
      lastCopyContext = context;
      await persistCopyContext(context);
      context.copied_text_hash = await sha256(text);
      lastCopyContext = context;
      await persistCopyContext(context);
      await emitHookTelemetry({
        event_type: "clipboard_cut_detected",
        action_taken: "observed",
        input_signal_types: ["clipboard_cut"],
        copied_text_hash: context.copied_text_hash,
        copied_text_preview_redacted: preview,
        source_context: context,
      });
    })();
  };

  const pasteListener = (event: ClipboardEvent): void => {
    if (maybeBlockVisualTransfer(event, event.clipboardData, "clipboard_paste")) return;

    const editableTarget = resolvePromptFieldTarget(event);
    if (!editableTarget) return;
    const rawPasted = String(event.clipboardData?.getData("text/plain") || "");
    const fallbackFromCopy = String(lastCopyContext?.copied_text_preview_redacted || "");
    const pasted = String(rawPasted || fallbackFromCopy || "").trim();
    if (!pasted) return;

    event.preventDefault();
    event.stopImmediatePropagation();
    event.stopPropagation();
    scheduleNativeDropOverlayRelease(event.target);

    void (async () => {
      const destination_domain = normalizeDomain(location.hostname);
      const destination_surface_type = inferDestinationSurface(destination_domain);
      const destination_context: PasteContextPayload = {
        destination_url: location.href,
        destination_domain,
        destination_app_name: inferAppName(destination_domain),
        destination_surface_type,
        destination_input_context: inferInputContext(editableTarget),
        timestamp: new Date().toISOString(),
      };

      const now = Date.now();
      const copyContextFresh = !!(
        lastCopyContext
        && lastCopyContext.timestamp
        && (now - new Date(lastCopyContext.timestamp).getTime()) <= COPY_CONTEXT_TTL_MS
      );
      const storedCopyContext = copyContextFresh ? null : await loadStoredCopyContext();
      let referrerDomain = "";
      try {
        referrerDomain = normalizeDomain(new URL(document.referrer || "").hostname);
      } catch {
        referrerDomain = "";
      }
      const inferredSourceDomain = referrerDomain || destination_domain;
      const inferredSourceSurface = inferSourceSurface(inferredSourceDomain);
      const inferredSourceClassification = inferSourceClassification(inferredSourceSurface, inferredSourceDomain);
      const source_context: CopyContextPayload = copyContextFresh && lastCopyContext
        ? lastCopyContext
        : storedCopyContext || {
          source_url: location.href,
          source_domain: inferredSourceDomain,
          source_app_name: inferAppName(inferredSourceDomain),
          source_surface_type: inferredSourceSurface,
          source_classification_hint: inferredSourceClassification,
          copied_text_hash: await sha256(pasted),
          copied_text_preview_redacted: redact(pasted),
          timestamp: new Date().toISOString(),
        };

      const textPasteClassification = destination_surface_type === "ai_tool"
        ? classifyTextPasteForAi(pasted)
        : null;
      const sensitive = sensitivePatternHit(pasted, options.policy) || !!textPasteClassification?.containsSecret;
      const businessTextPaste = !!textPasteClassification?.businessRelated;
      if ((sensitive || businessTextPaste) && source_context.source_classification_hint !== "protected") {
        source_context.source_classification_hint = "protected";
      }
      const status = domainStatus(options.domain, options.policy);

      let decision: DataTransferDecisionResponse | null = null;
      try {
        decision = await options.onDataTransferCheck({
          copy_context: source_context,
          paste_context: destination_context,
          policy_version: options.policy.policy_version,
          platform_mode: options.policy.platform_mode,
        });
      } catch {
        const fallbackDecision = classifyPasteTimeoutFallback({
          destination_surface_type,
          source_classification_hint: source_context.source_classification_hint,
          sensitive: sensitive || businessTextPaste,
          platform_mode: options.policy.platform_mode,
        });
        if (fallbackDecision === "block") {
          await emitHookTelemetry({
            event_type: "clipboard_paste_detected",
            action_taken: "data_transfer_backend_timeout_block",
            input_signal_types: ["clipboard_paste", "timeout_fail_safe"],
            copied_text_hash: source_context.copied_text_hash,
            copied_text_preview_redacted: source_context.copied_text_preview_redacted,
            source_context,
            paste_context: destination_context,
          });
          await blockWithArtifactCleanup(event.target, {
            domain: destination_domain,
            reason: "Paste blocked because runtime policy check timed out.",
          });
          return;
        }
        if (fallbackDecision === "require_justification") {
          const fallbackPolicyDecision: DataTransferDecisionResponse = {
            decision: "require_justification",
            reason_code: "runtime_policy_check_timeout",
            explanation: "Runtime policy check timed out. Enter a business justification to continue this data transfer.",
            recommended_action: "capture_business_justification",
            justification_required: true,
            policy_version: options.policy.policy_version,
            platform_mode: options.policy.platform_mode,
          };
          const justificationResult = await options.onRequireJustification({
            domain: destination_domain,
            reason: fallbackPolicyDecision.reason_code,
            recommendation: fallbackPolicyDecision.explanation,
          });
          if (justificationResult.action === "cancel") {
            await emitHookTelemetry({
              event_type: "clipboard_paste_detected",
              action_taken: "require_justification_cancel_timeout_fallback",
              input_signal_types: ["clipboard_paste", "timeout_fallback", "require_justification"],
              copied_text_hash: source_context.copied_text_hash,
              copied_text_preview_redacted: source_context.copied_text_preview_redacted,
              source_context,
              paste_context: destination_context,
              policy_decision: fallbackPolicyDecision,
            });
            return;
          }

          let justificationDecision: DataTransferJustificationResponse;
          try {
            justificationDecision = await options.onDataTransferJustify({
              ...justificationPayloadFields(justificationResult),
              copy_context: source_context,
              paste_context: destination_context,
              policy_decision: {
                decision: "require_justification",
                reason_code: fallbackPolicyDecision.reason_code,
                policy_version: fallbackPolicyDecision.policy_version,
                platform_mode: options.policy.platform_mode,
              },
              policy_version: options.policy.policy_version,
              platform_mode: options.policy.platform_mode,
            });
          } catch {
            justificationDecision = {
              decision: "block",
              reason_code: "justification_backend_failed",
              explanation: "Justification could not be recorded.",
              recommended_action: "retry_after_backend_recovers",
            };
          }

          await emitHookTelemetry({
            event_type: "clipboard_paste_detected",
            action_taken: justificationDecision.decision === "allow"
              ? "allow_after_justification_timeout_fallback"
              : "block_after_justification_timeout_fallback",
            input_signal_types: ["clipboard_paste", "timeout_fallback", "require_justification"],
            copied_text_hash: source_context.copied_text_hash,
            copied_text_preview_redacted: source_context.copied_text_preview_redacted,
            source_context,
            paste_context: destination_context,
            policy_decision: fallbackPolicyDecision,
            justification_reason_code: justificationDecision.reason_code,
          });

          if (justificationDecision.decision === "allow" && rawPasted) {
            resumeApprovedPromptPaste(editableTarget, rawPasted, destination_surface_type);
            return;
          }
          await blockWithArtifactCleanup(event.target, {
            domain: destination_domain,
            reason: justificationDecision.explanation,
          });
          return;
        }
        const proceed = await options.onWarn({
          domain: destination_domain,
          reasons: ["clipboard_paste", "timeout_fallback"],
          recommendation: "Policy check timed out. Continue with caution.",
        });
        await emitHookTelemetry({
          event_type: "clipboard_paste_detected",
          action_taken: proceed === "continue" ? "warn_timeout_continue" : "warn_timeout_cancel",
          input_signal_types: ["clipboard_paste", "timeout_fallback"],
          copied_text_hash: source_context.copied_text_hash,
          copied_text_preview_redacted: source_context.copied_text_preview_redacted,
          source_context,
          paste_context: destination_context,
        });
        if (proceed === "continue" && rawPasted) {
          insertText(editableTarget, rawPasted);
        }
        return;
      }

      const signalTypes = ["clipboard_paste", decision.reason_code];
      if (sensitive) signalTypes.push("sensitive_data_pattern");
      if (textPasteClassification) signalTypes.push(...textPasteClassification.signalTypes);
      if (status === "unknown") signalTypes.push("domain_policy_mismatch");

      if (
        options.policy.platform_mode === "enforce"
        && destination_surface_type === "ai_tool"
        && textPasteClassification?.decision === "block"
        && decision.decision !== "block"
      ) {
        decision = {
          ...decision,
          decision: "block",
          reason_code: textPasteClassification.reasonCode,
          explanation: textPasteClassification.explanation,
          recommended_action: "route_to_governance",
          justification_required: false,
        };
        signalTypes.push("local_text_paste_secret_override");
      }

      if (
        options.policy.platform_mode === "enforce"
        && destination_surface_type === "ai_tool"
        && textPasteClassification?.decision === "require_justification"
        && decision.decision !== "block"
        && decision.decision !== "require_justification"
      ) {
        decision = {
          ...decision,
          decision: "require_justification",
          reason_code: textPasteClassification.reasonCode,
          explanation: textPasteClassification.explanation,
          recommended_action: "capture_business_justification",
          justification_required: true,
        };
        signalTypes.push("local_text_paste_business_override");
      }

      if (
        options.policy.platform_mode === "enforce"
        && sensitive
        && ["email", "slack", "ai_tool"].includes(destination_surface_type)
        && decision.decision !== "block"
        && !(decision.decision === "require_justification" && ["email", "slack"].includes(destination_surface_type))
      ) {
        decision = {
          ...decision,
          decision: "block",
          reason_code: "sensitive_data_pattern",
          explanation: "Sensitive data transfer to this destination is blocked by policy.",
          recommended_action: "route_to_governance",
          justification_required: false,
        };
        signalTypes.push("local_sensitive_override");
      }

      if (decision.decision === "allow") {
        if (rawPasted) {
          insertText(editableTarget, rawPasted);
        }
        await emitHookTelemetry({
          event_type: "clipboard_paste_detected",
          action_taken: "allow_data_transfer",
          input_signal_types: signalTypes,
          copied_text_hash: source_context.copied_text_hash,
          copied_text_preview_redacted: source_context.copied_text_preview_redacted,
          source_context,
          paste_context: destination_context,
          policy_decision: decision,
        });
        return;
      }

      if (decision.decision === "warn") {
        const choice = await options.onWarn({
          domain: destination_domain,
          reasons: signalTypes,
          recommendation: decision.explanation,
        });
        await emitHookTelemetry({
          event_type: "clipboard_paste_detected",
          action_taken: choice === "continue" ? "warn_data_transfer_continue" : "warn_data_transfer_cancel",
          input_signal_types: signalTypes,
          copied_text_hash: source_context.copied_text_hash,
          copied_text_preview_redacted: source_context.copied_text_preview_redacted,
          source_context,
          paste_context: destination_context,
          policy_decision: decision,
        });
        if (choice === "continue") {
          if (rawPasted) {
            insertText(editableTarget, rawPasted);
          }
        }
        return;
      }

      if (decision.decision === "require_justification") {
        const justificationResult = await options.onRequireJustification({
          domain: destination_domain,
          reason: decision.reason_code,
          recommendation: decision.explanation,
        });
        if (justificationResult.action === "cancel") {
          await emitHookTelemetry({
            event_type: "clipboard_paste_detected",
            action_taken: "require_justification_cancel",
            input_signal_types: signalTypes,
            copied_text_hash: source_context.copied_text_hash,
            copied_text_preview_redacted: source_context.copied_text_preview_redacted,
            source_context,
            paste_context: destination_context,
            policy_decision: decision,
          });
          return;
        }

        let justificationDecision: DataTransferJustificationResponse | null = null;
        try {
          justificationDecision = await options.onDataTransferJustify({
            ...justificationPayloadFields(justificationResult),
            copy_context: source_context,
            paste_context: destination_context,
            policy_decision: {
              decision: "require_justification",
              reason_code: decision.reason_code,
              policy_version: decision.policy_version,
              platform_mode: (decision.platform_mode === "discovery" ? "discovery" : "enforce"),
            },
            policy_version: options.policy.policy_version,
            platform_mode: options.policy.platform_mode,
          });
        } catch {
          justificationDecision = {
            decision: "block",
            reason_code: "justification_backend_failed",
            explanation: "Justification could not be verified.",
            recommended_action: "route_to_governance",
          };
        }

        await emitHookTelemetry({
          event_type: "clipboard_paste_detected",
          action_taken: justificationDecision.decision === "allow" ? "allow_after_justification" : "block_after_justification",
          input_signal_types: signalTypes,
          copied_text_hash: source_context.copied_text_hash,
          copied_text_preview_redacted: source_context.copied_text_preview_redacted,
          source_context,
          paste_context: destination_context,
          policy_decision: decision,
          justification_reason_code: justificationDecision.reason_code,
        });

        if (justificationDecision.decision === "allow") {
          if (rawPasted) {
            resumeApprovedPromptPaste(editableTarget, rawPasted, destination_surface_type);
          }
          return;
        }
        await blockWithArtifactCleanup(event.target, {
          domain: destination_domain,
          reason: justificationDecision.explanation,
        });
        return;
      }

      await emitHookTelemetry({
        event_type: "clipboard_paste_detected",
        action_taken: "block_data_transfer",
        input_signal_types: signalTypes,
        copied_text_hash: source_context.copied_text_hash,
        copied_text_preview_redacted: source_context.copied_text_preview_redacted,
        source_context,
        paste_context: destination_context,
        policy_decision: decision,
      });
      await blockWithArtifactCleanup(event.target, {
        domain: destination_domain,
        reason: decision.explanation,
      });
    })();
  };

  const beforeInputListener = (event: InputEvent): void => {
    if (event.inputType !== "insertFromPaste") return;
    const editableTarget = resolvePromptFieldTarget(event);
    if (!editableTarget) return;
    const rawPasted = String(event.dataTransfer?.getData("text/plain") || event.data || "").trim();
    if (!rawPasted) return;

    const destinationDomain = normalizeDomain(location.hostname);
    const destinationSurface = inferDestinationSurface(destinationDomain);
    if (destinationSurface !== "ai_tool" || options.policy.platform_mode !== "enforce") return;

    const textPasteClassification = classifyTextPasteForAi(rawPasted);
    if (textPasteClassification.decision === "allow") return;

    event.preventDefault();
    event.stopImmediatePropagation();
    event.stopPropagation();
    scheduleNativeDropOverlayRelease(event.target);

    void (async () => {
      const sourceSurface = inferSourceSurface(destinationDomain);
      const sourceContext: CopyContextPayload = {
        source_url: location.href,
        source_domain: destinationDomain,
        source_app_name: inferAppName(destinationDomain),
        source_surface_type: sourceSurface,
        source_classification_hint: "protected",
        copied_text_hash: await sha256(rawPasted),
        copied_text_preview_redacted: redact(rawPasted),
        timestamp: new Date().toISOString(),
      };
      const pasteContext: PasteContextPayload = {
        destination_url: location.href,
        destination_domain: destinationDomain,
        destination_app_name: inferAppName(destinationDomain),
        destination_surface_type: destinationSurface,
        destination_input_context: inferInputContext(editableTarget),
        timestamp: new Date().toISOString(),
      };
      const signalTypes = [
        ...textPasteClassification.signalTypes,
        textPasteClassification.reasonCode,
        "beforeinput_insert_from_paste",
      ];
      const policyDecision: DataTransferDecisionResponse = {
        decision: textPasteClassification.decision,
        reason_code: textPasteClassification.reasonCode,
        explanation: textPasteClassification.explanation,
        recommended_action: textPasteClassification.decision === "require_justification"
          ? "capture_business_justification"
          : "route_to_governance",
        justification_required: textPasteClassification.decision === "require_justification",
        policy_version: options.policy.policy_version,
        platform_mode: options.policy.platform_mode,
      };

      if (textPasteClassification.decision === "block") {
        await emitHookTelemetry({
          event_type: "clipboard_paste_detected",
          action_taken: "block_text_paste_beforeinput",
          input_signal_types: signalTypes,
          copied_text_hash: sourceContext.copied_text_hash,
          copied_text_preview_redacted: sourceContext.copied_text_preview_redacted,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: policyDecision,
        });
        await blockWithArtifactCleanup(event.target, {
          domain: destinationDomain,
          reason: textPasteClassification.explanation,
        });
        return;
      }

      const justificationResult = await options.onRequireJustification({
        domain: destinationDomain,
        reason: policyDecision.reason_code,
        recommendation: policyDecision.explanation,
      });
      if (justificationResult.action === "cancel") {
        await emitHookTelemetry({
          event_type: "clipboard_paste_detected",
          action_taken: "require_justification_cancel_beforeinput_text_paste",
          input_signal_types: [...signalTypes, "require_justification"],
          copied_text_hash: sourceContext.copied_text_hash,
          copied_text_preview_redacted: sourceContext.copied_text_preview_redacted,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: policyDecision,
        });
        return;
      }

      let justificationDecision: DataTransferJustificationResponse;
      try {
        justificationDecision = await options.onDataTransferJustify({
          ...justificationPayloadFields(justificationResult),
          copy_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: {
            decision: "require_justification",
            reason_code: policyDecision.reason_code,
            policy_version: policyDecision.policy_version,
            platform_mode: options.policy.platform_mode,
          },
          policy_version: options.policy.policy_version,
          platform_mode: options.policy.platform_mode,
        });
      } catch {
        justificationDecision = {
          decision: "block",
          reason_code: "justification_backend_failed",
          explanation: "Justification could not be verified.",
          recommended_action: "route_to_governance",
        };
      }

      await emitHookTelemetry({
        event_type: "clipboard_paste_detected",
        action_taken: justificationDecision.decision === "allow"
          ? "allow_text_paste_after_justification_beforeinput"
          : "block_text_paste_after_justification_beforeinput",
        input_signal_types: [...signalTypes, "require_justification"],
        copied_text_hash: sourceContext.copied_text_hash,
        copied_text_preview_redacted: sourceContext.copied_text_preview_redacted,
        source_context: sourceContext,
        paste_context: pasteContext,
        policy_decision: policyDecision,
        justification_reason_code: justificationDecision.reason_code,
      });

      if (justificationDecision.decision === "allow") {
        resumeApprovedPromptPaste(editableTarget, rawPasted, destinationSurface);
        return;
      }
      await blockWithArtifactCleanup(event.target, {
        domain: destinationDomain,
        reason: justificationDecision.explanation,
      });
    })();
  };

  const composerInputListener = (event: InputEvent): void => {
    if (composerQuarantineBypass) return;
    const editableTarget = resolvePromptFieldTarget(event);
    if (!editableTarget) return;
    const destinationDomain = normalizeDomain(location.hostname);
    const destinationSurface = inferDestinationSurface(destinationDomain);
    if (destinationSurface !== "ai_tool" || options.policy.platform_mode !== "enforce") return;

    const currentText = promptText(editableTarget).trim();
    const previousText = lastComposerText.get(editableTarget) || "";
    lastComposerText.set(editableTarget, currentText);
    if (!currentText) return;

    const insertedEnoughToTreatAsTransfer =
      currentText.length - previousText.length >= 8
      || currentText.includes("\n")
      || event.inputType === "insertFromPaste"
      || event.inputType === "insertFromDrop";
    if (!insertedEnoughToTreatAsTransfer) return;

    const textPasteClassification = classifyTextPasteForAi(currentText);
    if (textPasteClassification.decision === "allow") return;

    event.preventDefault();
    event.stopImmediatePropagation();
    event.stopPropagation();
    composerQuarantineBypass = true;
    clearPromptText(editableTarget);
    composerQuarantineBypass = false;
    lastComposerText.set(editableTarget, "");

    void (async () => {
      const sourceSurface = inferSourceSurface(destinationDomain);
      const sourceContext: CopyContextPayload = {
        source_url: location.href,
        source_domain: destinationDomain,
        source_app_name: inferAppName(destinationDomain),
        source_surface_type: sourceSurface,
        source_classification_hint: "protected",
        copied_text_hash: await sha256(currentText),
        copied_text_preview_redacted: redact(currentText),
        timestamp: new Date().toISOString(),
      };
      const pasteContext: PasteContextPayload = {
        destination_url: location.href,
        destination_domain: destinationDomain,
        destination_app_name: inferAppName(destinationDomain),
        destination_surface_type: destinationSurface,
        destination_input_context: inferInputContext(editableTarget),
        timestamp: new Date().toISOString(),
      };
      const signalTypes = [
        ...textPasteClassification.signalTypes,
        textPasteClassification.reasonCode,
        "composer_quarantine",
      ];
      const policyDecision: DataTransferDecisionResponse = {
        decision: textPasteClassification.decision,
        reason_code: textPasteClassification.reasonCode,
        explanation: textPasteClassification.explanation,
        recommended_action: textPasteClassification.decision === "require_justification"
          ? "capture_business_justification"
          : "route_to_governance",
        justification_required: textPasteClassification.decision === "require_justification",
        policy_version: options.policy.policy_version,
        platform_mode: options.policy.platform_mode,
      };

      if (textPasteClassification.decision === "block") {
        await emitHookTelemetry({
          event_type: "clipboard_paste_detected",
          action_taken: "block_text_paste_composer_quarantine",
          input_signal_types: signalTypes,
          copied_text_hash: sourceContext.copied_text_hash,
          copied_text_preview_redacted: sourceContext.copied_text_preview_redacted,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: policyDecision,
        });
        await blockWithArtifactCleanup(event.target, {
          domain: destinationDomain,
          reason: textPasteClassification.explanation,
        });
        return;
      }

      const justificationResult = await options.onRequireJustification({
        domain: destinationDomain,
        reason: policyDecision.reason_code,
        recommendation: policyDecision.explanation,
      });
      if (justificationResult.action === "cancel") {
        await emitHookTelemetry({
          event_type: "clipboard_paste_detected",
          action_taken: "require_justification_cancel_composer_quarantine",
          input_signal_types: [...signalTypes, "require_justification"],
          copied_text_hash: sourceContext.copied_text_hash,
          copied_text_preview_redacted: sourceContext.copied_text_preview_redacted,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: policyDecision,
        });
        return;
      }

      let justificationDecision: DataTransferJustificationResponse;
      try {
        justificationDecision = await options.onDataTransferJustify({
          ...justificationPayloadFields(justificationResult),
          copy_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: {
            decision: "require_justification",
            reason_code: policyDecision.reason_code,
            policy_version: policyDecision.policy_version,
            platform_mode: options.policy.platform_mode,
          },
          policy_version: options.policy.policy_version,
          platform_mode: options.policy.platform_mode,
        });
      } catch {
        justificationDecision = {
          decision: "block",
          reason_code: "justification_backend_failed",
          explanation: "Justification could not be verified.",
          recommended_action: "route_to_governance",
        };
      }

      await emitHookTelemetry({
        event_type: "clipboard_paste_detected",
        action_taken: justificationDecision.decision === "allow"
          ? "allow_text_paste_after_justification_composer_quarantine"
          : "block_text_paste_after_justification_composer_quarantine",
        input_signal_types: [...signalTypes, "require_justification"],
        copied_text_hash: sourceContext.copied_text_hash,
        copied_text_preview_redacted: sourceContext.copied_text_preview_redacted,
        source_context: sourceContext,
        paste_context: pasteContext,
        policy_decision: policyDecision,
        justification_reason_code: justificationDecision.reason_code,
      });

      if (justificationDecision.decision === "allow") {
        resumeApprovedPromptPaste(editableTarget, currentText, destinationSurface);
        return;
      }
      await blockWithArtifactCleanup(event.target, {
        domain: destinationDomain,
        reason: justificationDecision.explanation,
      });
    })();
  };

  const maybeGateDroppedFileTransfer = (event: DragEvent): boolean => {
    const droppedFiles = runtimeControlFilesFromTransfer(event.dataTransfer);
    if (!droppedFiles.length) return false;

    const destinationDomain = normalizeDomain(location.hostname);
    const destinationSurface = inferDestinationSurface(destinationDomain);
    const highRiskDestination =
      destinationSurface === "email" || destinationSurface === "slack" || destinationSurface === "ai_tool";
    if (options.policy.platform_mode !== "enforce" || !highRiskDestination) return false;

    event.preventDefault();
    event.stopImmediatePropagation();
    event.stopPropagation();
    scheduleNativeDropOverlayRelease(event.target);

    void (async () => {
      const files = await buildRuntimeControlFileMeta(droppedFiles);
      const sourceDomain = normalizeDomain(location.hostname);
      const sourceSurface = inferSourceSurface(sourceDomain);
      const sourceContext: CopyContextPayload = {
        source_url: location.href,
        source_domain: sourceDomain,
        source_app_name: inferAppName(sourceDomain),
        source_surface_type: sourceSurface,
        source_classification_hint: "protected",
        copied_text_hash: await sha256(
          files.map((item) => `${String(item.name || "")}:${String(item.size || "")}:${String(item.type || "")}`).join("|")
        ),
        copied_text_preview_redacted: redact(files.map((item) => String(item.name || "")).join(", ")),
        timestamp: new Date().toISOString(),
      };
      const pasteContext: PasteContextPayload = {
        destination_url: location.href,
        destination_domain: destinationDomain,
        destination_app_name: inferAppName(destinationDomain),
        destination_surface_type: destinationSurface,
        destination_input_context: inferInputContext(event.target),
        timestamp: new Date().toISOString(),
      };
      const visualUploadDecision = classifyVisualUploadControl(files, options.policy, destinationSurface);
      const spreadsheetDecision = destinationSurface === "ai_tool"
        ? classifySpreadsheetUploadForAi(files)
        : classifySpreadsheetUploadForAi([]);
      const localDecision = classifyDroppedFileTransferForDestination(files, options.policy, destinationSurface);
      const filesWithVisualEvidence = attachVisualClassificationEvidence(files, visualUploadDecision);
      const filesWithTransferEvidence = filesWithVisualEvidence.map((item) => ({
        ...item,
        spreadsheet_classification: spreadsheetDecision.isSpreadsheet
          ? {
            business_related: spreadsheetDecision.businessRelated,
            contains_secret: spreadsheetDecision.containsSecret,
            decision: spreadsheetDecision.decision,
            reason_code: spreadsheetDecision.reasonCode,
            signal_types: spreadsheetDecision.signalTypes,
          }
          : undefined,
      }));

      const localPolicyDecision: DataTransferDecisionResponse = {
        decision: localDecision.decision,
        reason_code: localDecision.reasonCode,
        explanation: localDecision.explanation,
        recommended_action: localDecision.recommendedAction,
        justification_required: localDecision.decision === "require_justification",
        policy_version: options.policy.policy_version,
        platform_mode: options.policy.platform_mode,
      };

      const warnReattach = async (reason: string): Promise<void> => {
        await options.onWarn({
          domain: destinationDomain,
          reasons: ["drag_drop_file_upload", reason],
          recommendation: "Hawk reviewed and held this drag/drop upload before the AI app could receive it. Use the attachment button to upload it through the controlled file-picker path.",
        });
      };

      const submitJustification = async (
        policyDecision: DataTransferDecisionResponse,
      ): Promise<DataTransferJustificationResponse> => {
        const justificationResult = await options.onRequireJustification({
          domain: destinationDomain,
          reason: policyDecision.reason_code,
          recommendation: policyDecision.explanation,
        });
        if (justificationResult.action === "cancel") {
          return {
            decision: "block",
            reason_code: "justification_cancelled",
            explanation: "File drop cancelled because no justification was provided.",
            recommended_action: "route_to_governance",
          };
        }
        try {
          return await options.onDataTransferJustify({
            ...justificationPayloadFields(justificationResult),
            copy_context: sourceContext,
            paste_context: pasteContext,
            file_meta: filesWithTransferEvidence,
            policy_decision: {
              decision: "require_justification",
              reason_code: policyDecision.reason_code,
              policy_version: policyDecision.policy_version,
              platform_mode: (policyDecision.platform_mode === "discovery" ? "discovery" : "enforce"),
            },
            policy_version: options.policy.policy_version,
            platform_mode: options.policy.platform_mode,
          });
        } catch {
          return {
            decision: "block",
            reason_code: "justification_backend_failed",
            explanation: "Justification could not be verified.",
            recommended_action: "route_to_governance",
          };
        }
      };

      if (localDecision.decision === "block") {
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: "block_drag_drop_file_upload",
          input_signal_types: localDecision.signalTypes,
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: localPolicyDecision,
        });
        await blockWithArtifactCleanup(event.target, {
          domain: destinationDomain,
          reason: localDecision.explanation,
        });
        return;
      }

      if (localDecision.decision === "require_justification") {
        const justificationDecision = await submitJustification(localPolicyDecision);
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: justificationDecision.decision === "allow"
            ? "allow_drag_drop_file_upload_after_justification_reattach_required"
            : "block_drag_drop_file_upload_after_justification",
          input_signal_types: [...localDecision.signalTypes, "require_justification"],
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: localPolicyDecision,
          justification_reason_code: justificationDecision.reason_code,
        });
        if (justificationDecision.decision === "allow") {
          await warnReattach("justification_approved_reattach_required");
          return;
        }
        await blockWithArtifactCleanup(event.target, {
          domain: destinationDomain,
          reason: justificationDecision.explanation,
        });
        return;
      }

      let decision: DataTransferDecisionResponse | null = null;
      try {
        decision = await options.onDataTransferCheck({
          copy_context: sourceContext,
          paste_context: pasteContext,
          file_meta: filesWithTransferEvidence,
          policy_version: options.policy.policy_version,
          platform_mode: options.policy.platform_mode,
        });
      } catch {
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: "data_transfer_backend_timeout_block_drag_drop",
          input_signal_types: [...localDecision.signalTypes, "timeout_fallback"],
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
        });
        await blockWithArtifactCleanup(event.target, {
          domain: destinationDomain,
          reason: "Dropped file upload blocked because runtime policy check timed out.",
        });
        return;
      }

      if (decision.decision === "allow") {
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: "hold_reviewed_drag_drop_file_upload_reattach_required",
          input_signal_types: localDecision.signalTypes,
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: decision,
        });
        await warnReattach("drop_reviewed_reattach_required");
        return;
      }

      if (decision.decision === "warn") {
        const choice = await options.onWarn({
          domain: destinationDomain,
          reasons: [...localDecision.signalTypes, decision.reason_code],
          recommendation: decision.explanation || "Dropped file upload requires careful review.",
        });
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: choice === "continue"
            ? "warn_drag_drop_file_upload_reattach_required"
            : "warn_drag_drop_file_upload_cancel",
          input_signal_types: [...localDecision.signalTypes, decision.reason_code],
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: decision,
        });
        if (choice === "continue") {
          await warnReattach("warning_accepted_reattach_required");
        }
        return;
      }

      if (decision.decision === "require_justification") {
        const justificationDecision = await submitJustification(decision);
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: justificationDecision.decision === "allow"
            ? "allow_drag_drop_after_backend_justification_reattach_required"
            : "block_drag_drop_after_backend_justification",
          input_signal_types: [...localDecision.signalTypes, decision.reason_code, "require_justification"],
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: decision,
          justification_reason_code: justificationDecision.reason_code,
        });
        if (justificationDecision.decision === "allow") {
          await warnReattach("backend_justification_approved_reattach_required");
          return;
        }
        await blockWithArtifactCleanup(event.target, {
          domain: destinationDomain,
          reason: justificationDecision.explanation,
        });
        return;
      }

      await emitHookTelemetry({
        event_type: "file_upload_detected",
        action_taken: "block_drag_drop_file_upload",
        input_signal_types: [...localDecision.signalTypes, decision.reason_code || "blocked"],
        file_meta: filesWithTransferEvidence,
        source_context: sourceContext,
        paste_context: pasteContext,
        policy_decision: decision,
      });
      await blockWithArtifactCleanup(event.target, {
        domain: destinationDomain,
        reason: decision.explanation || "Dropped file upload blocked by runtime policy.",
      });
    })();

    return true;
  };

  const dropListener = (event: DragEvent): void => {
    if (maybeGateDroppedFileTransfer(event)) return;
    maybeBlockVisualTransfer(event, event.dataTransfer, "drag_drop");
  };

  const fileDragHoldListener = (event: DragEvent): void => {
    suppressNativeFileDragOverlay(event);
  };

  const fileDragReleaseListener = (event: DragEvent): void => {
    if (!transferLooksLikeFileDrag(event.dataTransfer)) return;
    scheduleNativeDropOverlayRelease(event.target);
  };

  const fileChangeListener = (event: Event): void => {
    const target = event.target;
    if (!(target instanceof HTMLInputElement) || target.type !== "file") return;
    if (shouldBypassUploadChange(event, target)) {
      return;
    }
    const selectedFiles = target.files ? Array.from(target.files) : [];
    if (!selectedFiles.length) return;

    // Gate file uploads before destination handlers consume the selection.
    event.preventDefault();
    event.stopImmediatePropagation();
    event.stopPropagation();

    void (async () => {
      const files = await fileMeta(target);
      if (!files.length) {
        target.value = "";
        scheduleBlockedArtifactCleanup(target);
        return;
      }
      const destinationDomain = normalizeDomain(location.hostname);
      const destinationSurface = inferDestinationSurface(destinationDomain);
      const highRiskDestination =
        destinationSurface === "email" || destinationSurface === "slack" || destinationSurface === "ai_tool";
      const sensitiveFile = files.some((item) => fileIsSensitive(String(item.name || "")));
      const visualUploadDecision = classifyVisualUploadControl(files, options.policy, destinationSurface);
      const signalTypes = ["file_upload"];
      if (sensitiveFile) signalTypes.push("sensitive_file_name_hint");
      signalTypes.push(...visualUploadDecision.signalTypes);
      const sourceDomain = normalizeDomain(location.hostname);
      const sourceSurface = inferSourceSurface(sourceDomain);
      const sourceClassification = (
        sensitiveFile || highRiskDestination
          ? "protected"
          : inferSourceClassification(sourceSurface, sourceDomain)
      );
      const fileSummary = files
        .map((item) => {
          const name = String(item.name || "");
          const size = Number(item.size || 0);
          const type = String(item.type || "");
          return `${name}:${size}:${type}`;
        })
        .join("|");
      const sourceContext: CopyContextPayload = {
        source_url: location.href,
        source_domain: sourceDomain,
        source_app_name: inferAppName(sourceDomain),
        source_surface_type: sourceSurface,
        source_classification_hint: sourceClassification,
        copied_text_hash: await sha256(fileSummary || "file_upload"),
        copied_text_preview_redacted: redact(
          files.map((item) => String(item.name || "")).join(", ")
        ),
        timestamp: new Date().toISOString(),
      };
      const pasteContext: PasteContextPayload = {
        destination_url: location.href,
        destination_domain: destinationDomain,
        destination_app_name: inferAppName(destinationDomain),
        destination_surface_type: destinationSurface,
        destination_input_context: inferInputContext(target),
        timestamp: new Date().toISOString(),
      };
      const spreadsheetDecision = destinationSurface === "ai_tool"
        ? classifySpreadsheetUploadForAi(files)
        : classifySpreadsheetUploadForAi([]);
      const filesWithVisualEvidence = attachVisualClassificationEvidence(files, visualUploadDecision);
      const filesWithTransferEvidence = filesWithVisualEvidence.map((item) => ({
        ...item,
        spreadsheet_classification: spreadsheetDecision.isSpreadsheet
          ? {
            business_related: spreadsheetDecision.businessRelated,
            contains_secret: spreadsheetDecision.containsSecret,
            decision: spreadsheetDecision.decision,
            reason_code: spreadsheetDecision.reasonCode,
            signal_types: spreadsheetDecision.signalTypes,
          }
          : undefined,
      }));
      for (const signal of spreadsheetDecision.signalTypes) signalTypes.push(signal);

      if (visualUploadDecision.decision === "block") {
        target.value = "";
        scheduleBlockedArtifactCleanup(target);
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: "block_unverified_visual_upload",
          input_signal_types: [...signalTypes, visualUploadDecision.reasonCode],
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: {
            decision: "block",
            reason_code: visualUploadDecision.reasonCode,
            explanation: visualUploadDecision.explanation,
            platform_mode: options.policy.platform_mode,
            policy_version: options.policy.policy_version,
          },
        });
        await blockWithArtifactCleanup(target, {
          domain: destinationDomain,
          reason: visualUploadDecision.explanation,
        });
        return;
      }

      if (visualUploadDecision.decision === "require_justification") {
        const policyDecision: DataTransferDecisionResponse = {
          decision: "require_justification",
          reason_code: visualUploadDecision.reasonCode,
          explanation: visualUploadDecision.explanation,
          recommended_action: "capture_business_justification",
          justification_required: true,
          policy_version: options.policy.policy_version,
          platform_mode: options.policy.platform_mode,
        };
        const justificationResult = await options.onRequireJustification({
          domain: destinationDomain,
          reason: policyDecision.reason_code,
          recommendation: policyDecision.explanation,
        });
        if (justificationResult.action === "cancel") {
          target.value = "";
          scheduleBlockedArtifactCleanup(target);
          await emitHookTelemetry({
            event_type: "file_upload_detected",
            action_taken: "require_justification_cancel_visual_upload",
            input_signal_types: [...signalTypes, visualUploadDecision.reasonCode],
            file_meta: filesWithTransferEvidence,
            source_context: sourceContext,
            paste_context: pasteContext,
            policy_decision: policyDecision,
          });
          return;
        }
        let justificationDecision: DataTransferJustificationResponse;
        try {
          justificationDecision = await options.onDataTransferJustify({
            ...justificationPayloadFields(justificationResult),
            copy_context: sourceContext,
            paste_context: pasteContext,
            file_meta: filesWithTransferEvidence,
            policy_decision: {
              decision: "require_justification",
              reason_code: policyDecision.reason_code,
              policy_version: policyDecision.policy_version,
              platform_mode: (policyDecision.platform_mode === "discovery" ? "discovery" : "enforce"),
            },
            policy_version: options.policy.policy_version,
            platform_mode: options.policy.platform_mode,
          });
        } catch {
          justificationDecision = {
            decision: "block",
            reason_code: "justification_backend_failed",
            explanation: "Justification could not be verified.",
            recommended_action: "route_to_governance",
          };
        }
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: justificationDecision.decision === "allow"
            ? "allow_visual_upload_after_justification"
            : "block_visual_upload_after_justification",
          input_signal_types: [...signalTypes, visualUploadDecision.reasonCode],
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: policyDecision,
          justification_reason_code: justificationDecision.reason_code,
        });
        if (justificationDecision.decision === "allow") {
          markBypassUploadChange(target);
          target.dispatchEvent(new Event("change", { bubbles: true }));
          return;
        }
        target.value = "";
        scheduleBlockedArtifactCleanup(target);
        await blockWithArtifactCleanup(target, {
          domain: destinationDomain,
          reason: justificationDecision.explanation,
        });
        return;
      }

      if (spreadsheetDecision.decision === "block") {
        target.value = "";
        scheduleBlockedArtifactCleanup(target);
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: "block_spreadsheet_upload",
          input_signal_types: [...signalTypes, spreadsheetDecision.reasonCode],
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: {
            decision: "block",
            reason_code: spreadsheetDecision.reasonCode,
            explanation: spreadsheetDecision.explanation,
            recommended_action: "route_to_governance",
            justification_required: false,
            platform_mode: options.policy.platform_mode,
            policy_version: options.policy.policy_version,
          },
        });
        await blockWithArtifactCleanup(target, {
          domain: destinationDomain,
          reason: spreadsheetDecision.explanation,
        });
        return;
      }

      if (spreadsheetDecision.decision === "require_justification") {
        const policyDecision: DataTransferDecisionResponse = {
          decision: "require_justification",
          reason_code: spreadsheetDecision.reasonCode,
          explanation: spreadsheetDecision.explanation,
          recommended_action: "capture_business_justification",
          justification_required: true,
          policy_version: options.policy.policy_version,
          platform_mode: options.policy.platform_mode,
        };
        const justificationResult = await options.onRequireJustification({
          domain: destinationDomain,
          reason: policyDecision.reason_code,
          recommendation: policyDecision.explanation,
        });
        if (justificationResult.action === "cancel") {
          target.value = "";
          scheduleBlockedArtifactCleanup(target);
          await emitHookTelemetry({
            event_type: "file_upload_detected",
            action_taken: "require_justification_cancel_business_spreadsheet_upload",
            input_signal_types: [...signalTypes, spreadsheetDecision.reasonCode],
            file_meta: filesWithTransferEvidence,
            source_context: sourceContext,
            paste_context: pasteContext,
            policy_decision: policyDecision,
          });
          return;
        }
        let justificationDecision: DataTransferJustificationResponse;
        try {
          justificationDecision = await options.onDataTransferJustify({
            ...justificationPayloadFields(justificationResult),
            copy_context: sourceContext,
            paste_context: pasteContext,
            file_meta: filesWithTransferEvidence,
            policy_decision: {
              decision: "require_justification",
              reason_code: policyDecision.reason_code,
              policy_version: policyDecision.policy_version,
              platform_mode: (policyDecision.platform_mode === "discovery" ? "discovery" : "enforce"),
            },
            policy_version: options.policy.policy_version,
            platform_mode: options.policy.platform_mode,
          });
        } catch {
          justificationDecision = {
            decision: "block",
            reason_code: "justification_backend_failed",
            explanation: "Justification could not be verified.",
            recommended_action: "route_to_governance",
          };
        }
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: justificationDecision.decision === "allow"
            ? "allow_business_spreadsheet_upload_after_justification"
            : "block_business_spreadsheet_upload_after_justification",
          input_signal_types: [...signalTypes, spreadsheetDecision.reasonCode],
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: policyDecision,
          justification_reason_code: justificationDecision.reason_code,
        });
        if (justificationDecision.decision === "allow") {
          markBypassUploadChange(target);
          target.dispatchEvent(new Event("change", { bubbles: true }));
          return;
        }
        target.value = "";
        scheduleBlockedArtifactCleanup(target);
        await blockWithArtifactCleanup(target, {
          domain: destinationDomain,
          reason: justificationDecision.explanation,
        });
        return;
      }

      let decision: DataTransferDecisionResponse | null = null;
      try {
        decision = await options.onDataTransferCheck({
          copy_context: sourceContext,
          paste_context: pasteContext,
          file_meta: filesWithTransferEvidence,
          policy_version: options.policy.policy_version,
          platform_mode: options.policy.platform_mode,
        });
      } catch {
        const failSecure = options.policy.platform_mode === "enforce" || sensitiveFile || highRiskDestination;
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: failSecure ? "data_transfer_backend_timeout_block" : "warn_timeout_file_upload",
          input_signal_types: [...signalTypes, "timeout_fallback"],
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
        });
        if (failSecure) {
          target.value = "";
          scheduleBlockedArtifactCleanup(target);
          await blockWithArtifactCleanup(target, {
            domain: destinationDomain,
            reason: "File upload blocked because runtime policy check timed out.",
          });
          return;
        }
        const proceed = await options.onWarn({
          domain: destinationDomain,
          reasons: [...signalTypes, "timeout_fallback"],
          recommendation: "Runtime policy check timed out. Continue with caution.",
        });
        if (proceed === "continue") {
          markBypassUploadChange(target);
          target.dispatchEvent(new Event("change", { bubbles: true }));
        } else {
          target.value = "";
          scheduleBlockedArtifactCleanup(target);
        }
        return;
      }

      if (
        options.policy.platform_mode === "enforce"
        && sensitiveFile
        && decision.decision !== "block"
      ) {
        decision = {
          ...decision,
          decision: "block",
          reason_code: "sensitive_file_upload",
          explanation: "Sensitive file upload blocked by runtime policy.",
          recommended_action: "route_to_governance",
          justification_required: false,
        };
      }

      if (decision.decision === "allow") {
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: "allow_file_upload",
          input_signal_types: signalTypes,
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: decision,
        });
        markBypassUploadChange(target);
        target.dispatchEvent(new Event("change", { bubbles: true }));
        return;
      }

      if (decision.decision === "warn") {
        const now = Date.now();
        const shouldPrompt = now >= warnGateUntil;
        if (shouldPrompt) {
          warnGateUntil = now + 3000;
        }
        const choice = shouldPrompt
          ? await options.onWarn({
            domain: destinationDomain,
            reasons: signalTypes,
            recommendation: decision.explanation || "File upload to this destination requires careful review.",
          })
          : "cancel";
        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: choice === "continue" ? "warn_file_upload_continue" : "warn_file_upload_cancel",
          input_signal_types: signalTypes,
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: decision,
        });
        if (choice === "continue") {
          markBypassUploadChange(target);
          target.dispatchEvent(new Event("change", { bubbles: true }));
        } else {
          target.value = "";
        }
        return;
      }

      if (decision.decision === "require_justification") {
        const justificationResult = await options.onRequireJustification({
          domain: destinationDomain,
          reason: decision.reason_code,
          recommendation: decision.explanation,
        });
        if (justificationResult.action === "cancel") {
          target.value = "";
          scheduleBlockedArtifactCleanup(target);
          await emitHookTelemetry({
            event_type: "file_upload_detected",
            action_taken: "require_justification_cancel_file_upload",
            input_signal_types: signalTypes,
            file_meta: filesWithTransferEvidence,
            source_context: sourceContext,
            paste_context: pasteContext,
            policy_decision: decision,
          });
          return;
        }

        let justificationDecision: DataTransferJustificationResponse | null = null;
        try {
          justificationDecision = await options.onDataTransferJustify({
            ...justificationPayloadFields(justificationResult),
            copy_context: sourceContext,
            paste_context: pasteContext,
            file_meta: filesWithTransferEvidence,
            policy_decision: {
              decision: "require_justification",
              reason_code: decision.reason_code,
              policy_version: decision.policy_version,
              platform_mode: (decision.platform_mode === "discovery" ? "discovery" : "enforce"),
            },
            policy_version: options.policy.policy_version,
            platform_mode: options.policy.platform_mode,
          });
        } catch {
          justificationDecision = {
            decision: "block",
            reason_code: "justification_backend_failed",
            explanation: "Justification could not be verified.",
            recommended_action: "route_to_governance",
          };
        }

        await emitHookTelemetry({
          event_type: "file_upload_detected",
          action_taken: (
            justificationDecision.decision === "allow"
              ? "allow_after_justification_file_upload"
              : "block_after_justification_file_upload"
          ),
          input_signal_types: signalTypes,
          file_meta: filesWithTransferEvidence,
          source_context: sourceContext,
          paste_context: pasteContext,
          policy_decision: decision,
          justification_reason_code: justificationDecision.reason_code,
        });
        if (justificationDecision.decision === "allow") {
          markBypassUploadChange(target);
          target.dispatchEvent(new Event("change", { bubbles: true }));
          return;
        }
        target.value = "";
        scheduleBlockedArtifactCleanup(target);
        await blockWithArtifactCleanup(target, {
          domain: destinationDomain,
          reason: justificationDecision.explanation,
        });
        return;
      }

      target.value = "";
      scheduleBlockedArtifactCleanup(target);
      await emitHookTelemetry({
        event_type: "file_upload_detected",
        action_taken: "block_file_upload",
        input_signal_types: [...signalTypes, decision.reason_code || "blocked"],
        file_meta: filesWithTransferEvidence,
        source_context: sourceContext,
        paste_context: pasteContext,
        policy_decision: decision,
      });
      await blockWithArtifactCleanup(target, {
        domain: destinationDomain,
        reason: decision.explanation || "File upload blocked by runtime policy.",
      });
    })();
  };

  const visibleOutputActionListener = (event: Event): void => {
    const action = visibleActionFromTarget(event.target, event.type === "submit" ? "submit_form" : undefined);
    if (!action) return;
    const text = selectedText(event.target).trim();
    if (!text) return;
    const localDecision = classifyVisibleOutputActionControl(text, options.policy, action);
    if (localDecision.decision !== "block" || options.policy.platform_mode !== "enforce") return;

    event.preventDefault();
    event.stopImmediatePropagation();
    event.stopPropagation();

    void (async () => {
      const domain = normalizeDomain(location.hostname);
      await emitHookTelemetry({
        event_type: "visible_output_action_blocked",
        action_taken: "block_visible_output_action",
        action_type: action,
        input_signal_types: localDecision.signalTypes,
        copied_text_hash: await sha256(text),
        copied_text_preview_redacted: redact(text),
        policy_decision: {
          decision: localDecision.decision,
          reason_code: localDecision.reasonCode,
          explanation: localDecision.explanation,
          platform_mode: options.policy.platform_mode,
          policy_version: options.policy.policy_version,
        },
      });
      await options.onBlock({
        domain,
        reason: localDecision.explanation,
      });
    })();
  };

  const attachFileInputListener = (input: HTMLInputElement): void => {
    if (trackedFileInputs.has(input)) return;
    trackedFileInputs.add(input);
    input.addEventListener("change", fileChangeListener, true);
  };

  const scanForFileInputs = (root: ParentNode): void => {
    const candidates = root.querySelectorAll?.("input[type='file']");
    if (!candidates) return;
    for (const node of Array.from(candidates)) {
      if (node instanceof HTMLInputElement) {
        attachFileInputListener(node);
      }
    }
  };

  const scanNode = (node: Node): void => {
    if (node instanceof HTMLInputElement && node.type === "file") {
      attachFileInputListener(node);
      return;
    }
    if (!(node instanceof Element)) return;

    if (node.matches("input[type='file']") && node instanceof HTMLInputElement) {
      attachFileInputListener(node);
    }
    scanForFileInputs(node);
    if (node.shadowRoot) {
      scanForFileInputs(node.shadowRoot);
    }
  };

  scanForFileInputs(document);
  for (const element of Array.from(document.querySelectorAll("*"))) {
    if (element.shadowRoot) {
      scanForFileInputs(element.shadowRoot);
    }
  }

  const uploadObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      for (const addedNode of Array.from(mutation.addedNodes)) {
        scanNode(addedNode);
      }
    }
  });
  if (document.documentElement) {
    uploadObserver.observe(document.documentElement, {
      childList: true,
      subtree: true,
    });
  }

  document.addEventListener("copy", copyListener, true);
  document.addEventListener("cut", cutListener, true);
  document.addEventListener("beforeinput", beforeInputListener, true);
  document.addEventListener("input", composerInputListener as EventListener, true);
  document.addEventListener("input", composerInputListener as EventListener, false);
  document.addEventListener("paste", pasteListener, true);
  document.addEventListener("dragenter", fileDragHoldListener, true);
  document.addEventListener("dragover", fileDragHoldListener, true);
  document.addEventListener("dragleave", fileDragReleaseListener, true);
  document.addEventListener("dragend", fileDragReleaseListener, true);
  document.addEventListener("drop", dropListener, true);
  document.addEventListener("change", fileChangeListener, true);
  document.addEventListener("click", visibleOutputActionListener, true);
  document.addEventListener("submit", visibleOutputActionListener, true);

  return () => {
    uploadObserver.disconnect();
    for (const input of trackedFileInputs) {
      input.removeEventListener("change", fileChangeListener, true);
    }
    trackedFileInputs.clear();
    document.removeEventListener("copy", copyListener, true);
    document.removeEventListener("cut", cutListener, true);
    document.removeEventListener("beforeinput", beforeInputListener, true);
    document.removeEventListener("input", composerInputListener as EventListener, true);
    document.removeEventListener("input", composerInputListener as EventListener, false);
    document.removeEventListener("paste", pasteListener, true);
    document.removeEventListener("dragenter", fileDragHoldListener, true);
    document.removeEventListener("dragover", fileDragHoldListener, true);
    document.removeEventListener("dragleave", fileDragReleaseListener, true);
    document.removeEventListener("dragend", fileDragReleaseListener, true);
    document.removeEventListener("drop", dropListener, true);
    document.removeEventListener("change", fileChangeListener, true);
    document.removeEventListener("click", visibleOutputActionListener, true);
    document.removeEventListener("submit", visibleOutputActionListener, true);
  };
}
