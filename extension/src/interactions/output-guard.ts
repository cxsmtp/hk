import type { ExtensionPolicy } from "../policy-sync";

type OutputGuardOptions = {
  policy: ExtensionPolicy;
  domain: string;
  onFlag: (payload: {
    reason: string;
    preview: string;
    inputSignalTypes: string[];
  }) => Promise<void>;
};

// MVP stub: lightweight observer for obvious output leakage markers.
export function installOutputGuard(options: OutputGuardOptions): () => void {
  if (!options.policy.interaction_rules.output_checks_enabled) {
    return () => undefined;
  }

  const observer = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      const text = (mutation.target.textContent || "").trim();
      if (!text) continue;
      const lower = text.toLowerCase();
      const hit = options.policy.interaction_rules.blocked_keywords.find((keyword) => keyword && lower.includes(keyword.toLowerCase()));
      if (!hit) continue;
      void options.onFlag({
        reason: "output_keyword_match",
        preview: text.slice(0, 280),
        inputSignalTypes: ["tool_output"],
      });
      break;
    }
  });

  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true,
  });

  return () => observer.disconnect();
}
