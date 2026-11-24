type ContentSignalResult = {
  signal_types: string[];
  categories: string[];
  risk_score: number;
  redacted_snippet: string;
};

const SECRET_PATTERNS: Array<{ code: string; regex: RegExp; score: number }> = [
  { code: "api_key", regex: /\bsk-[a-z0-9]{16,}\b/i, score: 85 },
  { code: "aws_key", regex: /\bAKIA[0-9A-Z]{16}\b/, score: 85 },
  { code: "private_key", regex: /-----BEGIN (?:RSA |EC |OPENSSH |)PRIVATE KEY-----/, score: 95 },
  { code: "password_assignment", regex: /\b(password|passwd|pwd)\s*[:=]\s*['"]?.{4,}['"]?/i, score: 78 },
  { code: "token_assignment", regex: /\b(token|secret|api[_-]?token|access[_-]?token)\s*[:=]\s*['"]?.{6,}['"]?/i, score: 82 },
  { code: "env_export", regex: /\b(?:export\s+)?[A-Z0-9_]{3,}\s*=\s*[^=\n]{6,}/, score: 72 },
];

const PII_PATTERNS: Array<{ code: string; regex: RegExp; score: number }> = [
  { code: "email", regex: /\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b/i, score: 40 },
  { code: "phone", regex: /\+?\d[\d\s().-]{8,}\d/, score: 38 },
  { code: "emirates_id", regex: /(?<!\d)784-?\d{4}-?\d{7}-?\d(?!\d)/, score: 78 },
  { code: "ssn_like", regex: /\b\d{3}-\d{2}-\d{4}\b/, score: 75 },
];

const FINANCIAL_PATTERNS: Array<{ code: string; regex: RegExp; score: number }> = [
  { code: "card_number_like", regex: /\b(?:\d[ -]?){13,19}\b/, score: 68 },
  { code: "iban_like", regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/, score: 70 },
  { code: "bank_account", regex: /\b(account|iban|routing|swift)\b/i, score: 45 },
];

const PROMPT_INJECTION_PATTERNS: Array<{ code: string; regex: RegExp; score: number }> = [
  { code: "ignore_instructions", regex: /\bignore\b[^\n\r]{0,32}\binstructions?\b/i, score: 65 },
  { code: "reveal_system_prompt", regex: /\b(?:reveal|show)\b[^\n\r]{0,48}\b(?:system|hidden)\s*(?:prompt|instructions?)\b/i, score: 70 },
  { code: "jailbreak_phrase", regex: /\bjailbreak\b|\bdo anything now\b|\bdan mode\b/i, score: 62 },
];

function redact(value: string, max = 360): string {
  return String(value || "")
    .replace(/\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b/gi, "[email]")
    .replace(/\b(?:\d[ -]?){9,20}\b/g, "[number]")
    .replace(/\b(?:sk-[a-z0-9]{8,}|AKIA[0-9A-Z]{8,})\b/g, "[secret]")
    .slice(0, max);
}

function collectSignals(
  source: string,
  patterns: Array<{ code: string; regex: RegExp; score: number }>,
  signalPrefix: string,
  category: string,
): { signal_types: string[]; score: number; categories: string[] } {
  const signalTypes: string[] = [];
  let score = 0;
  for (const item of patterns) {
    if (!item.regex.test(source)) continue;
    signalTypes.push(`${signalPrefix}:${item.code}`);
    score = Math.max(score, item.score);
  }
  return {
    signal_types: signalTypes,
    score,
    categories: signalTypes.length ? [category] : [],
  };
}

export function detectContentSignals(input: { text: string; additionalSignals?: string[] }): ContentSignalResult {
  const source = String(input.text || "");
  const normalized = source.trim();
  if (!normalized) {
    return {
      signal_types: Array.from(new Set(input.additionalSignals || [])),
      categories: [],
      risk_score: 0,
      redacted_snippet: "",
    };
  }

  const secret = collectSignals(normalized, SECRET_PATTERNS, "secret", "secrets");
  const pii = collectSignals(normalized, PII_PATTERNS, "pii", "pii");
  const financial = collectSignals(normalized, FINANCIAL_PATTERNS, "financial", "financial");
  const injection = collectSignals(normalized, PROMPT_INJECTION_PATTERNS, "prompt_injection", "prompt_injection");

  const riskScore = Math.min(
    100,
    Math.max(secret.score, pii.score, financial.score, injection.score),
  );

  return {
    signal_types: Array.from(
      new Set([
        ...(input.additionalSignals || []),
        ...secret.signal_types,
        ...pii.signal_types,
        ...financial.signal_types,
        ...injection.signal_types,
      ]),
    ),
    categories: Array.from(new Set([...secret.categories, ...pii.categories, ...financial.categories, ...injection.categories])),
    risk_score: riskScore,
    redacted_snippet: redact(normalized),
  };
}

export type { ContentSignalResult };
