const INTERSTITIAL_ID = "ai-control-plane-block-interstitial";

export function clearBlockInterstitial(): void {
  const existing = document.getElementById(INTERSTITIAL_ID);
  if (existing) existing.remove();
}

export function showBlockInterstitial(input: {
  domain: string;
  reason: string;
  policyVersion?: string;
  onRequestReview?: () => void;
}): void {
  clearBlockInterstitial();
  const overlay = document.createElement("div");
  overlay.id = INTERSTITIAL_ID;
  overlay.style.position = "fixed";
  overlay.style.inset = "0";
  overlay.style.zIndex = "2147483647";
  overlay.style.background = "rgba(15, 23, 42, 0.9)";
  overlay.style.display = "flex";
  overlay.style.alignItems = "center";
  overlay.style.justifyContent = "center";
  overlay.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";

  const card = document.createElement("div");
  card.style.width = "min(560px, calc(100% - 32px))";
  card.style.background = "#ffffff";
  card.style.borderRadius = "14px";
  card.style.padding = "20px";
  card.style.boxShadow = "0 24px 60px rgba(15, 23, 42, 0.35)";
  card.style.color = "#0f172a";

  const title = document.createElement("h2");
  title.textContent = "Request blocked by enterprise policy";
  title.style.margin = "0 0 8px";
  title.style.fontSize = "22px";

  const domain = document.createElement("p");
  domain.textContent = `Application: ${input.domain}`;
  domain.style.margin = "0 0 6px";
  domain.style.fontSize = "14px";
  domain.style.color = "#334155";

  const reason = document.createElement("p");
  reason.textContent = `Reason: ${input.reason}`;
  reason.style.margin = "0 0 6px";
  reason.style.fontSize = "14px";
  reason.style.color = "#334155";

  const policy = document.createElement("p");
  policy.textContent = `Policy version: ${input.policyVersion || "unknown"}`;
  policy.style.margin = "0 0 16px";
  policy.style.fontSize = "13px";
  policy.style.color = "#64748b";

  const actions = document.createElement("div");
  actions.style.display = "flex";
  actions.style.justifyContent = "flex-end";

  const reviewButton = document.createElement("button");
  reviewButton.type = "button";
  reviewButton.textContent = "Request review";
  reviewButton.style.border = "1px solid #0f172a";
  reviewButton.style.background = "#0f172a";
  reviewButton.style.color = "#fff";
  reviewButton.style.borderRadius = "8px";
  reviewButton.style.padding = "8px 12px";
  reviewButton.style.cursor = "pointer";
  reviewButton.onclick = () => {
    if (input.onRequestReview) input.onRequestReview();
  };

  actions.appendChild(reviewButton);
  card.appendChild(title);
  card.appendChild(domain);
  card.appendChild(reason);
  card.appendChild(policy);
  card.appendChild(actions);
  overlay.appendChild(card);
  document.documentElement.appendChild(overlay);
}
