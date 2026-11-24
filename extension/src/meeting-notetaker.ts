export type MeetingSurface = "google_meet" | "microsoft_teams" | "unknown";

export type MeetingNotetakerProvider =
  | "fireflies"
  | "read_ai"
  | "otter"
  | "fathom"
  | "avoma"
  | "tldv"
  | "granola"
  | "notta"
  | "krisp"
  | "scribe"
  | "grain"
  | "jamie"
  | "meetgeek"
  | "colibri"
  | "supernormal"
  | "tactiq"
  | "rev"
  | "generic_ai_notetaker";

export type MeetingNotetakerDetection = {
  surface: MeetingSurface;
  provider: MeetingNotetakerProvider;
  providerLabel: string;
  confidence: number;
  matchedTextRedacted: string;
  reasons: string[];
  participantVisible: true;
  controlMode: "external_required";
  actionTaken: "warn_notetaker_visible";
};

type ProviderMatcher = {
  provider: MeetingNotetakerProvider;
  label: string;
  confidence: number;
  pattern: RegExp;
};

const PROVIDER_MATCHERS: ProviderMatcher[] = [
  { provider: "fireflies", label: "Fireflies.ai", confidence: 0.97, pattern: /\bfireflies(?:\.ai)?\b/i },
  { provider: "read_ai", label: "Read.ai", confidence: 0.97, pattern: /\bread[ ._-]?ai\b/i },
  { provider: "otter", label: "Otter.ai", confidence: 0.95, pattern: /\botter(?:\.ai)?\b/i },
  { provider: "fathom", label: "Fathom", confidence: 0.94, pattern: /\bfathom\b/i },
  { provider: "avoma", label: "Avoma", confidence: 0.94, pattern: /\bavoma\b/i },
  { provider: "tldv", label: "tl;dv", confidence: 0.94, pattern: /\b(?:tl;?dv|tldv)\b/i },
  { provider: "granola", label: "Granola", confidence: 0.92, pattern: /\bgranola\b/i },
  { provider: "notta", label: "Notta", confidence: 0.92, pattern: /\bnotta\b/i },
  { provider: "krisp", label: "Krisp", confidence: 0.9, pattern: /\bkrisp\b/i },
  { provider: "scribe", label: "Scribe", confidence: 0.88, pattern: /\bscribe\b/i },
  { provider: "grain", label: "Grain", confidence: 0.88, pattern: /\bgrain\b/i },
  { provider: "jamie", label: "Jamie", confidence: 0.86, pattern: /\bjamie\b/i },
  { provider: "meetgeek", label: "MeetGeek", confidence: 0.92, pattern: /\bmeet[ ._-]?geek\b/i },
  { provider: "colibri", label: "Colibri", confidence: 0.88, pattern: /\bcolibri\b/i },
  { provider: "supernormal", label: "Supernormal", confidence: 0.92, pattern: /\bsupernormal\b/i },
  { provider: "tactiq", label: "Tactiq", confidence: 0.92, pattern: /\btactiq\b/i },
  { provider: "rev", label: "Rev", confidence: 0.84, pattern: /\brev(?:\.com)?\b/i },
  {
    provider: "generic_ai_notetaker",
    label: "AI notetaker",
    confidence: 0.78,
    pattern: /\b(?:ai\s+note[- ]?taker|meeting\s+note[- ]?taker|transcription\s+bot|transcript\s+bot|recording\s+bot)\b/i,
  },
];

export function detectMeetingSurface(hostname: string, url = ""): MeetingSurface {
  const host = hostname.toLowerCase().replace(/^www\./, "");
  const lowerUrl = url.toLowerCase();
  if (host === "meet.google.com" || host.endsWith(".meet.google.com")) {
    return "google_meet";
  }
  if (
    host === "teams.microsoft.com"
    || host.endsWith(".teams.microsoft.com")
    || host === "teams.live.com"
    || host.endsWith(".teams.live.com")
    || host === "teams.cloud.microsoft"
    || host.endsWith(".teams.cloud.microsoft")
    || lowerUrl.includes("teams.microsoft.com")
  ) {
    return "microsoft_teams";
  }
  return "unknown";
}

export function detectMeetingAiNotetaker(input: {
  hostname: string;
  url?: string;
  visibleText?: string;
}): MeetingNotetakerDetection | null {
  const surface = detectMeetingSurface(input.hostname, input.url);
  if (surface === "unknown") return null;

  const visibleText = normalizeVisibleText(input.visibleText || "");
  if (!visibleText) return null;

  for (const matcher of PROVIDER_MATCHERS) {
    const match = visibleText.match(matcher.pattern);
    if (!match) continue;
    return {
      surface,
      provider: matcher.provider,
      providerLabel: matcher.label,
      confidence: matcher.confidence,
      matchedTextRedacted: matcher.provider === "generic_ai_notetaker" ? redactMatch(match[0]) : matcher.label,
      reasons: [
        "visible_meeting_participant_or_roster_text",
        `meeting_surface:${surface}`,
        `notetaker_provider:${matcher.provider}`,
      ],
      participantVisible: true,
      controlMode: "external_required",
      actionTaken: "warn_notetaker_visible",
    };
  }

  return null;
}

function normalizeVisibleText(text: string): string {
  return text.replace(/\s+/g, " ").trim().slice(0, 120_000);
}

function redactMatch(value: string): string {
  return value.replace(/[^\w .;:-]/g, "").slice(0, 80);
}
