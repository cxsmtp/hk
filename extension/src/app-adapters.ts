import type { AppDetectionConfidence, AppProfile } from "./app-profiles";

export type BoundInput = {
  node: HTMLElement;
  input_method: "textarea" | "contenteditable" | "textbox" | "input" | "unknown";
};

export type AppAdapter = {
  profile: AppProfile;
  detectApp: () => AppDetectionConfidence;
  bindInput: () => BoundInput[];
  detectSubmit: () => HTMLElement[];
  detectUpload: () => HTMLElement[];
  extractPrompt: (preferredNode?: HTMLElement | null) => string;
  blockAction: (reason: string) => void;
  showWarning: (message: string) => void;
  recoverContext: () => void;
};

type AppAdapterOptions = {
  profile: AppProfile;
  detect: () => AppDetectionConfidence;
  onBlockAction?: (reason: string) => void;
  onWarn?: (message: string) => void;
};

function safeQueryAll(selectors: string[]): HTMLElement[] {
  const out: HTMLElement[] = [];
  for (const selector of selectors) {
    try {
      out.push(...Array.from(document.querySelectorAll<HTMLElement>(selector)));
    } catch {
      // Ignore malformed selectors.
    }
  }
  return out;
}

function inferInputMethod(node: HTMLElement): BoundInput["input_method"] {
  if (node instanceof HTMLTextAreaElement) return "textarea";
  if (node instanceof HTMLInputElement) return "input";
  if (node.isContentEditable) return "contenteditable";
  if (String(node.getAttribute("role") || "").toLowerCase() === "textbox") return "textbox";
  return "unknown";
}

function readPrompt(node: HTMLElement | null): string {
  if (!node) return "";
  if (node instanceof HTMLTextAreaElement || node instanceof HTMLInputElement) {
    return String(node.value || "").trim();
  }
  if (node.isContentEditable) {
    return String(node.innerText || node.textContent || "").trim();
  }
  return String(node.textContent || "").trim();
}

function longestPromptFromSelectors(selectors: string[]): string {
  const nodes = safeQueryAll(selectors);
  let best = "";
  for (const node of nodes) {
    const value = readPrompt(node);
    if (value.length > best.length) {
      best = value;
    }
  }
  return best;
}

export function createAppAdapter(options: AppAdapterOptions): AppAdapter {
  const { profile, detect, onBlockAction, onWarn } = options;

  return {
    profile,
    detectApp: detect,
    bindInput: () => {
      const nodes = safeQueryAll(profile.known_input_selectors);
      return nodes
        .map((node) => ({
          node,
          input_method: inferInputMethod(node),
        }))
        .filter((item) => !!item.node);
    },
    detectSubmit: () => safeQueryAll(profile.submit_selectors),
    detectUpload: () => safeQueryAll(profile.upload_selectors),
    extractPrompt: (preferredNode?: HTMLElement | null) => {
      const preferred = readPrompt(preferredNode || null);
      if (preferred) return preferred;

      const active = document.activeElement as HTMLElement | null;
      const activePrompt = readPrompt(active);
      if (activePrompt) return activePrompt;

      return longestPromptFromSelectors(profile.known_input_selectors);
    },
    blockAction: (reason: string) => {
      if (typeof onBlockAction === "function") {
        onBlockAction(reason);
      }
    },
    showWarning: (message: string) => {
      if (typeof onWarn === "function") {
        onWarn(message);
      }
    },
    recoverContext: () => {
      // Trigger lightweight access to keep adapter state current after SPA transitions.
      void safeQueryAll(profile.known_input_selectors);
      void safeQueryAll(profile.submit_selectors);
      void safeQueryAll(profile.upload_selectors);
    },
  };
}
