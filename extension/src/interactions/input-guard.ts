import type { ExtensionPolicy } from "../policy-sync";

export type ConfidenceTier = "clear_negative" | "ambiguous" | "clear_positive";
export type GuardDecision = "allow" | "warn" | "block" | "hold_for_backend";

export type InputGuardEvaluation = {
  tier: ConfidenceTier;
  decision: GuardDecision;
  reasonCodes: string[];
  inputSignalTypes: string[];
  redactedPreview: string;
  promptText: string;
  fileMeta: Array<Record<string, unknown>>;
};

export type InputGuardAction = InputGuardEvaluation & {
  resumeSubmission: () => void;
};

type InstallInputGuardOptions = {
  domain: string;
  policy: ExtensionPolicy;
  onDecision: (action: InputGuardAction) => Promise<void>;
};

const PROMPT_FIELD_SELECTOR = [
  "textarea",
  "div[contenteditable='true']",
  "[data-testid='composer-input']",
  "[data-testid='prompt-textarea']",
  "[id*='prompt-textarea']",
  "[role='textbox']",
].join(", ");

const SUBMIT_BUTTON_SELECTOR = [
  "button[type='submit']",
  "button[aria-label*='send' i]",
  "button[data-testid*='send' i]",
  "button[data-testid*='submit' i]",
  "[role='button'][aria-label*='send' i]",
  "[role='button'][data-testid*='send' i]",
].join(", ");

const UAE_EMIRATES_ID_STRICT_PATTERN = /(?<!\d)784-?\d{4}-?\d{7}-?\d(?!\d)/;
const UAE_EMIRATES_ID_CONTEXT_PATTERN =
  /\b(?:emirates\s*id|uae\s*(?:id|national\s*id)|eid)\b[^\n\r]{0,40}\b\d{10,18}\b/i;
const PROMPT_INJECTION_VARIANT_PATTERNS = [
  /\bignore\b[^\n\r]{0,32}\binstructions?\b/i,
  /\b(?:reveal|show)\b[^\n\r]{0,48}\b(?:system|hidden)\s*(?:prompt|instructions?)\b/i,
  /\b(?:copy|paste)\b[^\n\r]{0,80}\b(?:prompt|instructions?|system)\b/i,
];
const PROMPT_DECOMPOSITION_VARIANT_PATTERNS = [
  /\b(?:decompose|break(?:\s+down)?|split)\b[^\n\r]{0,80}\b(?:prompt|request|payload|instructions?)\b[^\n\r]{0,80}\b(?:into|as)\b[^\n\r]{0,40}\b(?:steps?|parts?|chunks?)\b/i,
  /\b(?:step[\s-]?by[\s-]?step|one\s+step\s+at\s+a\s+time)\b[^\n\r]{0,120}\b(?:bypass|evade|avoid|circumvent|sidestep)\b[^\n\r]{0,48}\b(?:policy|guard(?:rail)?s?|filter|detection|safety)\b/i,
  /\b(?:rephrase|rewrite)\b[^\n\r]{0,80}\b(?:forbidden|blocked|restricted)\b[^\n\r]{0,80}\b(?:into|as)\b[^\n\r]{0,40}\b(?:harmless|safe)\b[^\n\r]{0,60}\b(?:steps?|parts?)\b/i,
];
const HIGH_CONFIDENCE_SECRET_PATTERNS = [
  /\b[A-Z0-9_]*(?:API[_-]?KEY|ACCESS[_-]?TOKEN|SECRET|PRIVATE[_-]?KEY|AUTH[_-]?TOKEN|BEARER[_-]?TOKEN)\b\s*[:=]\s*['"]?[A-Za-z0-9_\-./+=]{8,}/i,
  /\bAuthorization\s*:\s*Bearer\s+[A-Za-z0-9_\-./+=]{12,}/i,
  /\b(?:sk|pk|ghp|github_pat|xox[baprs]|AIza)[A-Za-z0-9_\-]{10,}\b/i,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/i,
  /\b(?:token|secret|password|passwd|pwd)\b\s*[:=]\s*['"]?[A-Za-z0-9_\-./+=]{8,}/i,
];
const PHONE_WITH_CONTEXT_PATTERN =
  /\b(?:phone|mobile|contact|whatsapp|call|sms|mock\s*number|number)\b[^\n\r]{0,48}(?:\+?\d[\d\s().-]{8,}\d)\b/i;
const LONG_PHONE_PATTERN = /(?<!\d)\+?\d[\d\s().-]{8,}\d(?!\d)/g;
const PROMPT_DRAFT_CACHE_MAX_AGE_MS = 5 * 60 * 1000;

function toLower(value: string): string {
  return String(value || "").toLowerCase();
}

function redactPrompt(value: string): string {
  return String(value || "")
    .replace(/\b[\w.+-]+@[\w.-]+\.\w+\b/g, "[email]")
    .replace(/\b\d{9,16}\b/g, "[number]")
    .slice(0, 400);
}

export type PromptDraftCache = {
  update: (value: string | null | undefined) => void;
  read: (liveValue: string | null | undefined) => string;
  clear: () => void;
};

export function createPromptDraftCache(maxAgeMs = PROMPT_DRAFT_CACHE_MAX_AGE_MS): PromptDraftCache {
  let latestText = "";
  let latestAt = 0;

  return {
    update: (value) => {
      const text = String(value || "").trim();
      if (!text) return;
      latestText = text;
      latestAt = Date.now();
    },
    read: (liveValue) => {
      const liveText = String(liveValue || "").trim();
      if (liveText) return liveText;
      if (!latestText) return "";
      if (Date.now() - latestAt > maxAgeMs) return "";
      return latestText;
    },
    clear: () => {
      latestText = "";
      latestAt = 0;
    },
  };
}

function shouldUseNaturalSubmission(evaluation: InputGuardEvaluation): boolean {
  return evaluation.decision === "allow" && evaluation.fileMeta.length === 0;
}

function readPromptValue(node: HTMLElement | null): string {
  if (!node) return "";
  if (node instanceof HTMLTextAreaElement || node instanceof HTMLInputElement) {
    return String(node.value || "").trim();
  }
  return String(node.innerText || node.textContent || "").trim();
}

function findPromptFieldFromNode(node: HTMLElement | null): HTMLElement | null {
  if (!node) return null;
  if (node.matches(PROMPT_FIELD_SELECTOR)) return node;
  return node.closest(PROMPT_FIELD_SELECTOR);
}

function looksLikeSubmitButton(button: HTMLElement): boolean {
  const buttonCtor = typeof HTMLButtonElement !== "undefined" ? HTMLButtonElement : null;
  if (
    buttonCtor &&
    button instanceof buttonCtor &&
    (button.disabled || button.getAttribute("aria-disabled") === "true")
  ) {
    return false;
  }
  if (button.getAttribute("aria-disabled") === "true") return false;
  const type = toLower(button.getAttribute("type") || "");
  if (type === "submit") return true;
  const signals = toLower(
    [
      button.innerText || button.textContent || "",
      button.getAttribute("aria-label") || "",
      button.getAttribute("data-testid") || "",
      button.getAttribute("name") || "",
      button.getAttribute("id") || "",
      button.className || "",
    ].join(" ")
  );
  return (
    signals.includes("send") ||
    signals.includes("submit") ||
    signals.includes("prompt") ||
    signals.includes("message") ||
    signals.includes("generate")
  );
}

function findFallbackSubmitButton(): HTMLElement | null {
  const directMatch = document.querySelector<HTMLElement>(SUBMIT_BUTTON_SELECTOR);
  if (directMatch && looksLikeSubmitButton(directMatch)) return directMatch;
  const candidates = Array.from(document.querySelectorAll<HTMLElement>("button, [role='button']"));
  return candidates.find((candidate) => looksLikeSubmitButton(candidate)) || null;
}

function dispatchTrustedResumeClick(target: HTMLElement): void {
  const event = typeof MouseEvent !== "undefined"
    ? new MouseEvent("click", { bubbles: true, cancelable: true })
    : new Event("click", { bubbles: true, cancelable: true });
  target.dispatchEvent(
    event
  );
}

function dispatchPromptEnter(promptField: HTMLElement): void {
  const eventInit: KeyboardEventInit = {
    key: "Enter",
    code: "Enter",
    bubbles: true,
    cancelable: true,
  };
  promptField.dispatchEvent(new KeyboardEvent("keydown", eventInit));
  promptField.dispatchEvent(new KeyboardEvent("keyup", eventInit));
}

function resumePromptSubmission(triggerElement: HTMLElement | null): boolean {
  if (triggerElement?.isConnected) {
    dispatchTrustedResumeClick(triggerElement);
    return true;
  }

  const fallbackButton = findFallbackSubmitButton();
  if (fallbackButton?.isConnected) {
    dispatchTrustedResumeClick(fallbackButton);
    return true;
  }

  const activePromptField = findPromptFieldFromNode(document.activeElement as HTMLElement | null);
  if (activePromptField?.isConnected) {
    dispatchPromptEnter(activePromptField);
    return true;
  }

  return false;
}

function collectFileMeta(): Array<Record<string, unknown>> {
  const out: Array<Record<string, unknown>> = [];
  const fileInputs = Array.from(document.querySelectorAll<HTMLInputElement>("input[type='file']"));
  for (const input of fileInputs) {
    const files = input.files ? Array.from(input.files) : [];
    for (const file of files) {
      out.push({
        name: file.name,
        size: file.size,
        type: file.type,
      });
    }
  }
  return out;
}

function extractPromptText(promptDraftCache?: PromptDraftCache): string {
  const activePromptField = findPromptFieldFromNode(document.activeElement as HTMLElement | null);
  const activeValue = readPromptValue(activePromptField);
  if (activeValue) {
    promptDraftCache?.update(activeValue);
    return activeValue;
  }

  const candidates = Array.from(document.querySelectorAll<HTMLElement>(PROMPT_FIELD_SELECTOR));
  let best = "";
  for (const node of candidates) {
    const value = readPromptValue(node);
    if (value.length > best.length) {
      best = value;
    }
  }
  if (best) {
    promptDraftCache?.update(best);
  }
  return promptDraftCache?.read(best) || best;
}

function domainMatches(candidate: string, expected: string): boolean {
  const c = candidate.replace(/^www\./, "").toLowerCase();
  const e = expected.replace(/^www\./, "").toLowerCase();
  return c === e || c.endsWith(`.${e}`);
}

function looksLikePhoneNumberLeak(prompt: string): boolean {
  if (PHONE_WITH_CONTEXT_PATTERN.test(prompt)) return true;
  const matches = prompt.match(LONG_PHONE_PATTERN) || [];
  return matches.some((value) => {
    const digits = value.replace(/\D/g, "");
    return digits.length >= 10;
  });
}

function decideFromTier(tier: ConfidenceTier, holdOnAmbiguous: boolean): GuardDecision {
  if (tier === "clear_negative") return "allow";
  if (tier === "clear_positive") return "block";
  return holdOnAmbiguous ? "hold_for_backend" : "warn";
}

function _compilePolicyPattern(pattern: string): RegExp | null {
  let source = String(pattern || "").trim();
  if (!source) return null;

  // Support Python-style leading inline flags like "(?i)" from backend policy payloads.
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

export function runLightweightInputChecks(input: {
  promptText: string;
  domain: string;
  policy: ExtensionPolicy;
  fileMeta: Array<Record<string, unknown>>;
}): InputGuardEvaluation {
  const prompt = String(input.promptText || "");
  const textLower = toLower(prompt);
  const domain = String(input.domain || "").replace(/^www\./, "").toLowerCase();
  const reasonCodes: string[] = [];
  const inputSignalTypes: string[] = [];

  if (input.policy.blocked_domains.some((item) => domainMatches(domain, item))) {
    reasonCodes.push("domain_blocked");
    inputSignalTypes.push("domain_policy_mismatch");
    return {
      tier: "clear_positive",
      decision: "block",
      reasonCodes,
      inputSignalTypes,
      redactedPreview: redactPrompt(prompt),
      promptText: prompt,
      fileMeta: input.fileMeta,
    };
  }

  const keyword = input.policy.interaction_rules.blocked_keywords.find((item) => item && textLower.includes(toLower(item)));
  if (keyword) {
    reasonCodes.push("blocked_keyword_match");
    inputSignalTypes.push("prompt_injection");
    return {
      tier: "clear_positive",
      decision: "block",
      reasonCodes,
      inputSignalTypes,
      redactedPreview: redactPrompt(prompt),
      promptText: prompt,
      fileMeta: input.fileMeta,
    };
  }

  const promptInjectionPatternHit = PROMPT_INJECTION_VARIANT_PATTERNS.some((pattern) => pattern.test(prompt));
  if (promptInjectionPatternHit) {
    reasonCodes.push("prompt_injection_pattern");
    inputSignalTypes.push("prompt_injection");
    return {
      tier: "clear_positive",
      decision: "block",
      reasonCodes: Array.from(new Set(reasonCodes)),
      inputSignalTypes: Array.from(new Set(inputSignalTypes)),
      redactedPreview: redactPrompt(prompt),
      promptText: prompt,
      fileMeta: input.fileMeta,
    };
  }

  const promptDecompositionPatternHit = PROMPT_DECOMPOSITION_VARIANT_PATTERNS.some((pattern) => pattern.test(prompt));
  if (promptDecompositionPatternHit) {
    reasonCodes.push("prompt_decomposition_pattern");
    inputSignalTypes.push("prompt_decomposition", "prompt_injection");
    return {
      tier: "clear_positive",
      decision: "block",
      reasonCodes: Array.from(new Set(reasonCodes)),
      inputSignalTypes: Array.from(new Set(inputSignalTypes)),
      redactedPreview: redactPrompt(prompt),
      promptText: prompt,
      fileMeta: input.fileMeta,
    };
  }

  if (UAE_EMIRATES_ID_STRICT_PATTERN.test(prompt) || UAE_EMIRATES_ID_CONTEXT_PATTERN.test(prompt)) {
    reasonCodes.push("uae_sensitive_identifier");
    inputSignalTypes.push("sensitive_data_pattern", "sensitive_entity:emirates_id");
    return {
      tier: "clear_positive",
      decision: "block",
      reasonCodes,
      inputSignalTypes: Array.from(new Set(inputSignalTypes)),
      redactedPreview: redactPrompt(prompt),
      promptText: prompt,
      fileMeta: input.fileMeta,
    };
  }

  const highConfidenceSecretHit = HIGH_CONFIDENCE_SECRET_PATTERNS.some((pattern) => pattern.test(prompt));
  if (highConfidenceSecretHit) {
    reasonCodes.push("high_confidence_secret_pattern");
    inputSignalTypes.push("sensitive_data_pattern", "secret_or_credential_detected");
    return {
      tier: "clear_positive",
      decision: "block",
      reasonCodes: Array.from(new Set(reasonCodes)),
      inputSignalTypes: Array.from(new Set(inputSignalTypes)),
      redactedPreview: redactPrompt(prompt),
      promptText: prompt,
      fileMeta: input.fileMeta,
    };
  }

  if (looksLikePhoneNumberLeak(prompt)) {
    reasonCodes.push("pii_phone_number");
    inputSignalTypes.push("sensitive_data_pattern", "pii:phone");
    return {
      tier: "clear_positive",
      decision: "block",
      reasonCodes: Array.from(new Set(reasonCodes)),
      inputSignalTypes: Array.from(new Set(inputSignalTypes)),
      redactedPreview: redactPrompt(prompt),
      promptText: prompt,
      fileMeta: input.fileMeta,
    };
  }

  const sensitivePattern = input.policy.interaction_rules.sensitive_patterns.find((pattern) => {
    const compiled = _compilePolicyPattern(pattern);
    if (!compiled) return false;
    return compiled.test(prompt);
  });
  if (sensitivePattern) {
    reasonCodes.push("sensitive_data_pattern");
    inputSignalTypes.push("sensitive_data_pattern");
    return {
      tier: "clear_positive",
      decision: "block",
      reasonCodes,
      inputSignalTypes,
      redactedPreview: redactPrompt(prompt),
      promptText: prompt,
      fileMeta: input.fileMeta,
    };
  }

  const highRiskHit = input.policy.interaction_rules.high_risk_terms.find((term) => term && textLower.includes(toLower(term)));
  if (highRiskHit) {
    reasonCodes.push("high_risk_term");
    inputSignalTypes.push("jailbreak");
  }

  const approved = input.policy.approved_domains.some((item) => domainMatches(domain, item));
  const warnDomain = input.policy.warn_domains.some((item) => domainMatches(domain, item));
  const blocked = input.policy.blocked_domains.some((item) => domainMatches(domain, item));
  if (!approved && !blocked) {
    reasonCodes.push(warnDomain ? "domain_warn" : "unknown_domain");
    inputSignalTypes.push("domain_policy_mismatch");
  }

  if (input.fileMeta.length) {
    reasonCodes.push("file_upload_present");
    inputSignalTypes.push("file_upload");
  }

  const tier: ConfidenceTier = reasonCodes.length === 0 ? "clear_negative" : "ambiguous";
  return {
    tier,
    decision: decideFromTier(tier, input.policy.interaction_rules.hold_for_backend_on_ambiguous),
    reasonCodes: Array.from(new Set(reasonCodes)),
    inputSignalTypes: Array.from(new Set(inputSignalTypes)),
    redactedPreview: redactPrompt(prompt),
    promptText: prompt,
    fileMeta: input.fileMeta,
  };
}

export function installInputGuard(options: InstallInputGuardOptions): () => void {
  let bypass = false;
  const promptDraftCache = createPromptDraftCache();

  const rememberPromptDraftFromNode = (node: HTMLElement | null): void => {
    const promptField = findPromptFieldFromNode(node);
    const value = readPromptValue(promptField);
    if (value) {
      promptDraftCache.update(value);
    }
  };

  const rememberPromptDraftSoon = (node: HTMLElement | null): void => {
    rememberPromptDraftFromNode(node);
    window.setTimeout(() => {
      rememberPromptDraftFromNode(node);
      if (!node || !findPromptFieldFromNode(node)) {
        const activePromptField = findPromptFieldFromNode(document.activeElement as HTMLElement | null);
        rememberPromptDraftFromNode(activePromptField);
      }
    }, 0);
  };

  const handlePotentialSubmit = async (triggerElement: HTMLElement | null): Promise<void> => {
    if (bypass) return;
    const promptText = extractPromptText(promptDraftCache);
    if (!promptText.trim()) return;
    const fileMeta = collectFileMeta();
    const evaluation = runLightweightInputChecks({
      promptText,
      domain: options.domain,
      policy: options.policy,
      fileMeta,
    });

    const resumeSubmission = (): void => {
      bypass = true;
      try {
        resumePromptSubmission(triggerElement);
      } finally {
        bypass = false;
      }
    };

    await options.onDecision({
      ...evaluation,
      resumeSubmission: () => {
        promptDraftCache.clear();
        resumeSubmission();
      },
    });
  };

  const notifyNaturalSubmission = (evaluation: InputGuardEvaluation): void => {
    void options.onDecision({
      ...evaluation,
      resumeSubmission: () => undefined,
    }).finally(() => {
      promptDraftCache.clear();
    });
  };

  const clickListener = (event: MouseEvent): void => {
    if (bypass) return;
    const target = event.target as HTMLElement | null;
    if (!target) return;
    const button = target.closest("button, [role='button']") as HTMLElement | null;
    if (!button) return;
    if (!looksLikeSubmitButton(button)) return;
    const promptText = extractPromptText(promptDraftCache);
    if (!promptText.trim()) return;
    const fileMeta = collectFileMeta();
    const evaluation = runLightweightInputChecks({
      promptText,
      domain: options.domain,
      policy: options.policy,
      fileMeta,
    });
    if (shouldUseNaturalSubmission(evaluation)) {
      notifyNaturalSubmission(evaluation);
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    void handlePotentialSubmit(button);
  };

  const keydownListener = (event: KeyboardEvent): void => {
    if (bypass) return;
    const target = event.target as HTMLElement | null;
    const promptField =
      findPromptFieldFromNode(target) || findPromptFieldFromNode(document.activeElement as HTMLElement | null);
    if (!promptField) return;
    rememberPromptDraftFromNode(promptField);
    if (event.key !== "Enter" || event.shiftKey) return;
    const promptText = extractPromptText(promptDraftCache);
    if (!promptText.trim()) return;
    const fileMeta = collectFileMeta();
    const evaluation = runLightweightInputChecks({
      promptText,
      domain: options.domain,
      policy: options.policy,
      fileMeta,
    });
    if (shouldUseNaturalSubmission(evaluation)) {
      notifyNaturalSubmission(evaluation);
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    void handlePotentialSubmit(findFallbackSubmitButton());
  };

  const submitListener = (event: Event): void => {
    if (bypass) return;
    const form = event.target as HTMLFormElement | null;
    if (!(form instanceof HTMLFormElement)) return;
    const promptText = extractPromptText(promptDraftCache);
    if (!promptText.trim()) return;
    const fileMeta = collectFileMeta();
    const evaluation = runLightweightInputChecks({
      promptText,
      domain: options.domain,
      policy: options.policy,
      fileMeta,
    });
    if (shouldUseNaturalSubmission(evaluation)) {
      notifyNaturalSubmission(evaluation);
      return;
    }
    event.preventDefault();
    event.stopPropagation();
    const submitButton =
      form.querySelector<HTMLElement>(SUBMIT_BUTTON_SELECTOR) || findFallbackSubmitButton();
    void handlePotentialSubmit(submitButton || null);
  };

  const inputListener = (event: Event): void => {
    rememberPromptDraftSoon(event.target as HTMLElement | null);
  };

  const pasteListener = (event: ClipboardEvent): void => {
    rememberPromptDraftSoon(event.target as HTMLElement | null);
  };

  document.addEventListener("beforeinput", inputListener, true);
  document.addEventListener("input", inputListener, true);
  document.addEventListener("change", inputListener, true);
  document.addEventListener("keyup", inputListener, true);
  document.addEventListener("paste", pasteListener, true);
  document.addEventListener("click", clickListener, true);
  document.addEventListener("keydown", keydownListener, true);
  document.addEventListener("submit", submitListener, true);

  return () => {
    document.removeEventListener("beforeinput", inputListener, true);
    document.removeEventListener("input", inputListener, true);
    document.removeEventListener("change", inputListener, true);
    document.removeEventListener("keyup", inputListener, true);
    document.removeEventListener("paste", pasteListener, true);
    document.removeEventListener("click", clickListener, true);
    document.removeEventListener("keydown", keydownListener, true);
    document.removeEventListener("submit", submitListener, true);
  };
}

export const __inputGuardTestHooks = {
  resumePromptSubmission,
  shouldUseNaturalSubmission,
};
