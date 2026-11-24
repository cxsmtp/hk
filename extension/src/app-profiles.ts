export type AppRiskLevel = "low" | "medium" | "high";
export type FallbackStrategy = "selectors_first" | "contenteditable_only" | "keyword_and_dom";

export type AppProfile = {
  app_id: "chatgpt" | "claude" | "gemini" | "perplexity" | "generic_ai_app";
  name: string;
  domains: string[];
  known_input_selectors: string[];
  submit_selectors: string[];
  upload_selectors: string[];
  contenteditable_support: boolean;
  risk_level: AppRiskLevel;
  fallback_strategy: FallbackStrategy;
};

export type AppDetectionConfidence = {
  app_detected: boolean;
  confidence: number;
  signals: string[];
  profile: AppProfile;
};

const CHAT_UI_HINT_SELECTORS = [
  "textarea",
  "[contenteditable='true']",
  "[role='textbox']",
  "button[type='submit']",
  "button[aria-label*='send' i]",
  "button[data-testid*='send' i]",
  "input[type='file']",
];

const APP_PROFILES: AppProfile[] = [
  {
    app_id: "chatgpt",
    name: "ChatGPT",
    domains: ["chatgpt.com", "chat.openai.com", "platform.openai.com"],
    known_input_selectors: [
      "#prompt-textarea",
      "[data-testid='prompt-textarea']",
      "textarea[placeholder*='message' i]",
      "[contenteditable='true'][role='textbox']",
    ],
    submit_selectors: [
      "button[data-testid='send-button']",
      "button[aria-label*='send' i]",
      "button[type='submit']",
    ],
    upload_selectors: [
      "input[type='file']",
      "button[aria-label*='upload' i]",
      "button[data-testid*='upload' i]",
    ],
    contenteditable_support: true,
    risk_level: "high",
    fallback_strategy: "selectors_first",
  },
  {
    app_id: "claude",
    name: "Claude",
    domains: ["claude.ai", "console.anthropic.com"],
    known_input_selectors: [
      "textarea[placeholder*='reply' i]",
      "[data-testid*='composer' i]",
      "[contenteditable='true'][role='textbox']",
      "div[contenteditable='true']",
    ],
    submit_selectors: [
      "button[aria-label*='send' i]",
      "button[type='submit']",
      "button[data-testid*='send' i]",
    ],
    upload_selectors: [
      "input[type='file']",
      "button[aria-label*='upload' i]",
      "button[data-testid*='attach' i]",
    ],
    contenteditable_support: true,
    risk_level: "high",
    fallback_strategy: "selectors_first",
  },
  {
    app_id: "gemini",
    name: "Gemini",
    domains: ["gemini.google.com", "aistudio.google.com", "notebooklm.google.com"],
    known_input_selectors: [
      "textarea",
      "[role='textbox']",
      "div[contenteditable='true']",
    ],
    submit_selectors: [
      "button[aria-label*='send' i]",
      "button[type='submit']",
      "[role='button'][aria-label*='send' i]",
    ],
    upload_selectors: [
      "input[type='file']",
      "button[aria-label*='upload' i]",
      "button[aria-label*='attach' i]",
    ],
    contenteditable_support: true,
    risk_level: "high",
    fallback_strategy: "selectors_first",
  },
  {
    app_id: "perplexity",
    name: "Perplexity",
    domains: ["perplexity.ai", "www.perplexity.ai"],
    known_input_selectors: [
      "textarea",
      "div[contenteditable='true']",
      "[role='textbox']",
      "input[type='text']",
    ],
    submit_selectors: [
      "button[type='submit']",
      "button[aria-label*='ask' i]",
      "button[aria-label*='send' i]",
    ],
    upload_selectors: [
      "input[type='file']",
      "button[aria-label*='upload' i]",
      "button[aria-label*='attach' i]",
    ],
    contenteditable_support: true,
    risk_level: "medium",
    fallback_strategy: "selectors_first",
  },
];

export const GENERIC_AI_APP_PROFILE: AppProfile = {
  app_id: "generic_ai_app",
  name: "Generic AI App",
  domains: [],
  known_input_selectors: [
    "textarea",
    "[contenteditable='true']",
    "[role='textbox']",
    "input[type='text']",
  ],
  submit_selectors: [
    "button[type='submit']",
    "button[aria-label*='send' i]",
    "button[aria-label*='submit' i]",
    "[role='button'][aria-label*='send' i]",
  ],
  upload_selectors: [
    "input[type='file']",
    "button[aria-label*='upload' i]",
    "button[aria-label*='attach' i]",
  ],
  contenteditable_support: true,
  risk_level: "medium",
  fallback_strategy: "keyword_and_dom",
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

function hasAnySelectorMatch(root: ParentNode | null | undefined, selectors: string[]): boolean {
  if (!root || !selectors.length || typeof (root as ParentNode).querySelector !== "function") return false;
  return selectors.some((selector) => {
    try {
      return Boolean((root as ParentNode).querySelector(selector));
    } catch {
      return false;
    }
  });
}

function computeKnownProfileConfidence(
  profile: AppProfile,
  input: { domain: string; title?: string | null; root?: ParentNode | null },
): AppDetectionConfidence {
  const signals: string[] = [];
  let score = 0;
  const domain = normalizeDomain(input.domain);
  const title = String(input.title || "").toLowerCase();

  if (profile.domains.some((item) => domainMatches(domain, item))) {
    score += 0.52;
    signals.push("domain_match");
  }
  if (title.includes(profile.name.toLowerCase())) {
    score += 0.2;
    signals.push("title_match");
  }
  if (hasAnySelectorMatch(input.root, profile.known_input_selectors)) {
    score += 0.18;
    signals.push("input_selector_match");
  }
  if (hasAnySelectorMatch(input.root, profile.submit_selectors)) {
    score += 0.1;
    signals.push("submit_selector_match");
  }

  const confidence = Math.max(0, Math.min(1, score));
  return {
    app_detected: confidence >= 0.45,
    confidence,
    signals,
    profile,
  };
}

function computeGenericConfidence(input: {
  domain: string;
  url?: string | null;
  title?: string | null;
  root?: ParentNode | null;
}): AppDetectionConfidence {
  const signals: string[] = [];
  let score = 0;
  const title = String(input.title || "").toLowerCase();
  const url = String(input.url || "").toLowerCase();
  const domain = normalizeDomain(input.domain);

  const keywords = [
    "ai",
    "assistant",
    "chat",
    "prompt",
    "model",
    "copilot",
    "llm",
    "agent",
  ];
  if (keywords.some((item) => title.includes(item) || url.includes(item) || domain.includes(item))) {
    score += 0.3;
    signals.push("keyword_match");
  }

  if (hasAnySelectorMatch(input.root, CHAT_UI_HINT_SELECTORS)) {
    score += 0.4;
    signals.push("chat_ui_structure");
  }

  if (hasAnySelectorMatch(input.root, GENERIC_AI_APP_PROFILE.upload_selectors)) {
    score += 0.15;
    signals.push("upload_capability");
  }

  if (hasAnySelectorMatch(input.root, GENERIC_AI_APP_PROFILE.submit_selectors)) {
    score += 0.15;
    signals.push("submit_capability");
  }

  const confidence = Math.max(0, Math.min(1, score));
  return {
    app_detected: confidence >= 0.5,
    confidence,
    signals,
    profile: GENERIC_AI_APP_PROFILE,
  };
}

export function getAllAppProfiles(): AppProfile[] {
  return [...APP_PROFILES, GENERIC_AI_APP_PROFILE];
}

export function detectAppProfile(input: {
  domain: string;
  url?: string | null;
  title?: string | null;
  root?: ParentNode | null;
}): AppDetectionConfidence {
  const knownMatches = APP_PROFILES
    .map((profile) => computeKnownProfileConfidence(profile, input))
    .filter((result) => result.app_detected)
    .sort((left, right) => right.confidence - left.confidence);
  if (knownMatches.length > 0) {
    return knownMatches[0];
  }
  return computeGenericConfidence(input);
}
