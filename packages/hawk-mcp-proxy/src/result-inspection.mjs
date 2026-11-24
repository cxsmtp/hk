const HAWK_RESULT_INSPECTION_META_KEY = "ai.hawk/result-inspection";
const DEFAULT_RESULT_INSPECTION_MAX_BYTES = 256 * 1024;
const MAX_RESULT_CONTENT_BLOCKS = 1024;
const MAX_STRUCTURED_CONTENT_DEPTH = 32;
const MAX_STRUCTURED_CONTENT_NODES = 8192;
const MAX_EMAIL_LOCAL_LENGTH = 64;
const MAX_EMAIL_DOMAIN_LENGTH = 253;

const SECRET_OR_CREDENTIAL_PATTERNS = [
  /-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----/i,
  /\bbearer\s+[a-z0-9._~+/-]{8,}/i,
  /\b(?:password|passwd|api[_ -]?key|access[_ -]?token|client[_ -]?secret|private[_ -]?key)\s*[:=]\s*["']?[a-z0-9_./+=-]{8,}/i,
];
const INJECTED_OR_OVERRIDE_INSTRUCTION_PATTERNS = [
  /\bignore (?:all |any )?(?:previous|prior|earlier|system|developer) instructions?\b/i,
  /\b(?:override|disregard|bypass) (?:the )?(?:system|developer|policy|safety|security) instructions?\b/i,
  /\b(?:reveal|return|print|expose) (?:the )?(?:system|developer) prompt\b/i,
  /\byou are now (?:an?|the)\b/i,
];
const PERSISTENT_MEMORY_OR_STORED_INSTRUCTION_PATTERNS = [
  /\b(?:remember|retain) (?:this|these|the following).{0,80}\b(?:instruction|directive|rule|for future|future runs?)\b/i,
  /\b(?:write|save|store|persist|add) (?:this|these|the following)?.{0,80}\b(?:memory|stored instructions?|persistent context)\b/i,
  /\b(?:persistent memory|stored instructions?)\b/i,
];
const FUTURE_TIME_PATTERN = /\b(?:later|tomorrow|next (?:run|session|hour|day|week)|future runs?|at \d{1,2}(?::\d{2})?\s*(?:am|pm)?|when (?:the )?(?:user|system|job|workflow))\b/i;
const FUTURE_ACTION_PATTERN = /\b(?:upload|send|forward|publish|post|delete|remove|execute|run|trigger|call|notify|email|transfer|schedule|deploy)\b/i;
const EXTERNAL_URL_PATTERN = /\bhttps?:\/\/[^\s<>"')\]}]+/i;
const EXCESS_CUSTOMER_DATA_PATTERN = /\b(?:all[- ]customer|customer (?:dump|export|dataset|records?)|bulk customer|entire customer)\b/i;

const TAINT_DETECTORS = [
  {
    label: "secret_or_credential",
    matches: (text) => SECRET_OR_CREDENTIAL_PATTERNS.some((pattern) => pattern.test(text)),
  },
  {
    label: "excess_customer_data",
    matches: (text) => (
      EXCESS_CUSTOMER_DATA_PATTERN.test(text)
      || hasAtLeastDistinctEmailCandidates(text, 3)
    ),
  },
  {
    label: "injected_or_override_instruction",
    matches: (text) => INJECTED_OR_OVERRIDE_INSTRUCTION_PATTERNS.some((pattern) => pattern.test(text)),
  },
  {
    label: "external_url",
    matches: (text) => EXTERNAL_URL_PATTERN.test(text),
  },
  {
    label: "future_action_instruction",
    matches: (text) => FUTURE_TIME_PATTERN.test(text) && FUTURE_ACTION_PATTERN.test(text),
  },
  {
    label: "persistent_memory_or_stored_instruction",
    matches: (text) => PERSISTENT_MEMORY_OR_STORED_INSTRUCTION_PATTERNS.some((pattern) => pattern.test(text)),
  },
];

export class ToolResultInspectionError extends Error {}

export function applyToolResultInspection(
  message,
  {
    enabled = false,
    maxBytes = DEFAULT_RESULT_INSPECTION_MAX_BYTES,
  } = {},
) {
  if (!isRecord(message?.result)) {
    if (enabled) {
      throw new ToolResultInspectionError();
    }
    return message;
  }

  stripProxyOwnedInspectionMetadata(message.result);
  if (!enabled) {
    return message;
  }

  const inspection = inspectVisibleToolResult(message.result, { maxBytes });
  const existingMeta = isRecord(message.result._meta)
    ? message.result._meta
    : {};
  message.result._meta = {
    ...existingMeta,
    [HAWK_RESULT_INSPECTION_META_KEY]: inspection,
  };
  return message;
}

export function inspectVisibleToolResult(
  result,
  { maxBytes = DEFAULT_RESULT_INSPECTION_MAX_BYTES } = {},
) {
  validateCallToolResult(result);

  const byteLimit = normalizePositiveInteger(
    maxBytes,
    DEFAULT_RESULT_INSPECTION_MAX_BYTES,
  );
  const visibleText = [];
  let visibleNonText = false;
  let inspectedBytes = 0;
  const addVisibleText = (value) => {
    if (typeof value !== "string") {
      throw new ToolResultInspectionError();
    }
    const delimiterBytes = visibleText.length ? 1 : 0;
    const valueBytes = Buffer.byteLength(value, "utf8");
    if (delimiterBytes + valueBytes > byteLimit - inspectedBytes) {
      throw new ToolResultInspectionError();
    }
    inspectedBytes += delimiterBytes + valueBytes;
    visibleText.push(value);
  };

  for (const item of result.content) {
    if (item.type === "text") {
      addVisibleText(item.text);
      continue;
    }
    if (item.type === "resource") {
      if (typeof item.resource.text === "string") {
        addVisibleText(item.resource.text);
      }
      if (typeof item.resource.uri === "string") {
        addVisibleText(item.resource.uri);
      }
      if (typeof item.resource.blob === "string") {
        visibleNonText = true;
      }
      continue;
    }
    if (item.type === "resource_link") {
      for (const key of ["uri", "name", "title", "description"]) {
        if (typeof item[key] === "string") {
          addVisibleText(item[key]);
        }
      }
      continue;
    }
    visibleNonText = true;
  }

  if (Object.prototype.hasOwnProperty.call(result, "structuredContent")) {
    const structuredContent = serializeStructuredContent(
      result.structuredContent,
      byteLimit - inspectedBytes,
    );
    addVisibleText(structuredContent);
  }

  if (!visibleText.length) {
    return buildInspectionMetadata({
      inspected: false,
      visibility: visibleNonText ? "visible_non_text" : "not_visible",
      outcome: "not_inspected",
      taintLabels: [],
    });
  }

  const combinedText = visibleText.join("\n");
  const taintLabels = TAINT_DETECTORS
    .filter(({ matches }) => matches(combinedText))
    .map(({ label }) => label);
  return buildInspectionMetadata({
    inspected: true,
    visibility: visibleNonText ? "visible_mixed" : "visible",
    outcome: taintLabels.length
      ? "tainted"
      : visibleNonText
        ? "partially_inspected"
        : "clean",
    taintLabels,
  });
}

function buildInspectionMetadata({
  inspected,
  visibility,
  outcome,
  taintLabels,
}) {
  return {
    schema_version: "1.0",
    inspected,
    visibility,
    outcome,
    taint_labels: taintLabels,
  };
}

function stripProxyOwnedInspectionMetadata(result) {
  if (!isRecord(result?._meta)) {
    return;
  }
  delete result._meta[HAWK_RESULT_INSPECTION_META_KEY];
  if (!Object.keys(result._meta).length) {
    delete result._meta;
  }
}

function validateCallToolResult(result) {
  if (!isRecord(result) || !Array.isArray(result.content)) {
    throw new ToolResultInspectionError();
  }
  if (result.content.length > MAX_RESULT_CONTENT_BLOCKS) {
    throw new ToolResultInspectionError();
  }
  if (
    hasOwn(result, "isError")
    && typeof result.isError !== "boolean"
  ) {
    throw new ToolResultInspectionError();
  }
  if (hasOwn(result, "_meta") && !isRecord(result._meta)) {
    throw new ToolResultInspectionError();
  }
  if (
    hasOwn(result, "structuredContent")
    && !isRecord(result.structuredContent)
  ) {
    throw new ToolResultInspectionError();
  }
  for (const item of result.content) {
    validateContentBlock(item);
  }
}

function validateContentBlock(item) {
  if (!isRecord(item) || typeof item.type !== "string") {
    throw new ToolResultInspectionError();
  }
  if (item.type === "text") {
    requireString(item.text);
    return;
  }
  if (item.type === "image" || item.type === "audio") {
    requireString(item.data);
    requireNonEmptyString(item.mimeType);
    return;
  }
  if (item.type === "resource") {
    validateEmbeddedResource(item.resource);
    return;
  }
  if (item.type === "resource_link") {
    requireNonEmptyString(item.uri);
    requireNonEmptyString(item.name);
    validateOptionalString(item, "title");
    validateOptionalString(item, "description");
    validateOptionalString(item, "mimeType");
    if (
      hasOwn(item, "size")
      && (
        typeof item.size !== "number"
        || !Number.isFinite(item.size)
        || item.size < 0
      )
    ) {
      throw new ToolResultInspectionError();
    }
    return;
  }
  throw new ToolResultInspectionError();
}

function validateEmbeddedResource(resource) {
  if (!isRecord(resource)) {
    throw new ToolResultInspectionError();
  }
  requireNonEmptyString(resource.uri);
  const hasText = hasOwn(resource, "text");
  const hasBlob = hasOwn(resource, "blob");
  if (!hasText && !hasBlob) {
    throw new ToolResultInspectionError();
  }
  if (hasText) {
    requireString(resource.text);
  }
  if (hasBlob) {
    requireString(resource.blob);
  }
  validateOptionalString(resource, "mimeType");
}

function serializeStructuredContent(value, byteLimit) {
  if (!Number.isFinite(byteLimit) || byteLimit < 0) {
    throw new ToolResultInspectionError();
  }
  validateStructuredContent(value, 0, { count: 0 });
  let serialized;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new ToolResultInspectionError();
  }
  if (
    typeof serialized !== "string"
    || Buffer.byteLength(serialized, "utf8") > byteLimit
  ) {
    throw new ToolResultInspectionError();
  }
  return serialized;
}

function validateStructuredContent(value, depth, nodes) {
  if (depth > MAX_STRUCTURED_CONTENT_DEPTH) {
    throw new ToolResultInspectionError();
  }
  nodes.count += 1;
  if (nodes.count > MAX_STRUCTURED_CONTENT_NODES) {
    throw new ToolResultInspectionError();
  }
  if (
    value === null
    || typeof value === "string"
    || typeof value === "boolean"
    || (typeof value === "number" && Number.isFinite(value))
  ) {
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      validateStructuredContent(item, depth + 1, nodes);
    }
    return;
  }
  if (isRecord(value)) {
    for (const item of Object.values(value)) {
      validateStructuredContent(item, depth + 1, nodes);
    }
    return;
  }
  throw new ToolResultInspectionError();
}

function isRecord(value) {
  return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function hasOwn(value, key) {
  return Object.prototype.hasOwnProperty.call(value, key);
}

function requireString(value) {
  if (typeof value !== "string") {
    throw new ToolResultInspectionError();
  }
}

function requireNonEmptyString(value) {
  requireString(value);
  if (!value.trim()) {
    throw new ToolResultInspectionError();
  }
}

function validateOptionalString(value, key) {
  if (hasOwn(value, key)) {
    requireString(value[key]);
  }
}

function hasAtLeastDistinctEmailCandidates(text, threshold) {
  const unique = new Set();
  for (let at = 0; at < text.length; at += 1) {
    if (text.charCodeAt(at) !== 64) {
      continue;
    }
    const start = findEmailLocalStart(text, at);
    if (start === -1) {
      continue;
    }
    const end = findEmailDomainEnd(text, at + 1);
    if (end === -1) {
      continue;
    }
    unique.add(text.slice(start, end).toLowerCase());
    if (unique.size >= threshold) {
      return true;
    }
    at = end - 1;
  }
  return false;
}

function findEmailLocalStart(text, at) {
  let start = at - 1;
  let length = 0;
  while (
    start >= 0
    && length < MAX_EMAIL_LOCAL_LENGTH
    && isEmailLocalChar(text.charCodeAt(start))
  ) {
    start -= 1;
    length += 1;
  }
  start += 1;
  if (
    length === 0
    || (start > 0 && isEmailLocalChar(text.charCodeAt(start - 1)))
  ) {
    return -1;
  }
  const local = text.slice(start, at);
  if (
    local.startsWith(".")
    || local.endsWith(".")
    || local.includes("..")
  ) {
    return -1;
  }
  return start;
}

function findEmailDomainEnd(text, start) {
  const maximumEnd = Math.min(
    text.length,
    start + MAX_EMAIL_DOMAIN_LENGTH,
  );
  let end = start;
  let labelLength = 0;
  let labelStartedWithHyphen = false;
  let dotCount = 0;
  while (end < maximumEnd && isEmailDomainChar(text.charCodeAt(end))) {
    const code = text.charCodeAt(end);
    if (code === 46) {
      if (
        labelLength === 0
        || labelLength > 63
        || labelStartedWithHyphen
        || text.charCodeAt(end - 1) === 45
      ) {
        return -1;
      }
      dotCount += 1;
      labelLength = 0;
      labelStartedWithHyphen = false;
    } else {
      if (labelLength === 0) {
        labelStartedWithHyphen = code === 45;
      }
      labelLength += 1;
      if (labelLength > 63) {
        return -1;
      }
    }
    end += 1;
  }
  if (
    end === start
    || dotCount === 0
    || labelLength === 0
    || labelStartedWithHyphen
    || text.charCodeAt(end - 1) === 45
    || (end < text.length && isEmailDomainChar(text.charCodeAt(end)))
  ) {
    return -1;
  }
  return end;
}

function isEmailLocalChar(code) {
  return (
    isAsciiLetterOrDigit(code)
    || code === 33
    || code === 35
    || code === 36
    || code === 37
    || code === 38
    || code === 39
    || code === 42
    || code === 43
    || code === 45
    || code === 46
    || code === 47
    || code === 61
    || code === 63
    || code === 94
    || code === 95
    || code === 96
    || code === 123
    || code === 124
    || code === 125
    || code === 126
  );
}

function isEmailDomainChar(code) {
  return isAsciiLetterOrDigit(code) || code === 45 || code === 46;
}

function isAsciiLetterOrDigit(code) {
  return (
    (code >= 48 && code <= 57)
    || (code >= 65 && code <= 90)
    || (code >= 97 && code <= 122)
  );
}

function normalizePositiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed > 0
    ? Math.floor(parsed)
    : fallback;
}
