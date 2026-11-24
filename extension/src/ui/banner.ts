const BANNER_ID = "ai-control-plane-warn-banner";
const HOLD_ID = "ai-control-plane-hold-banner";
const JUSTIFICATION_ID = "ai-control-plane-justification-modal";
const BLOCK_NOTICE_ID = "ai-control-plane-block-action-banner";
const MONITORING_NOTICE_ID = "ai-control-plane-monitoring-banner";
const MEETING_NOTETAKER_ID = "ai-control-plane-meeting-notetaker-banner";

function removeNode(id: string): void {
  const existing = document.getElementById(id);
  if (existing) existing.remove();
}

export function clearWarnBanner(): void {
  removeNode(BANNER_ID);
}

export function clearHoldBanner(): void {
  removeNode(HOLD_ID);
}

export function clearJustificationModal(): void {
  removeNode(JUSTIFICATION_ID);
}

export function clearBlockActionBanner(): void {
  removeNode(BLOCK_NOTICE_ID);
}

export function clearMonitoringBanner(): void {
  removeNode(MONITORING_NOTICE_ID);
}

export function clearMeetingNotetakerBanner(): void {
  removeNode(MEETING_NOTETAKER_ID);
}

export function showHoldBanner(message: string): void {
  clearHoldBanner();
  const root = document.createElement("div");
  root.id = HOLD_ID;
  root.style.position = "fixed";
  root.style.top = "16px";
  root.style.right = "16px";
  root.style.zIndex = "2147483647";
  root.style.maxWidth = "380px";
  root.style.padding = "10px 12px";
  root.style.borderRadius = "10px";
  root.style.background = "#0f172a";
  root.style.color = "#f8fafc";
  root.style.boxShadow = "0 14px 35px rgba(2, 6, 23, 0.35)";
  root.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";
  root.style.fontSize = "13px";
  root.textContent = `Security review in progress: ${message}`;
  document.documentElement.appendChild(root);
}

export function showWarnBanner(input: {
  domain: string;
  reasons: string[];
  recommendation: string;
  canContinue: boolean;
}): Promise<"continue" | "cancel"> {
  clearWarnBanner();
  return new Promise((resolve) => {
    const root = document.createElement("div");
    root.id = BANNER_ID;
    root.style.position = "fixed";
    root.style.left = "16px";
    root.style.right = "16px";
    root.style.bottom = "16px";
    root.style.zIndex = "2147483647";
    root.style.display = "flex";
    root.style.flexDirection = "column";
    root.style.gap = "8px";
    root.style.padding = "12px 14px";
    root.style.background = "#fff7ed";
    root.style.border = "1px solid #fdba74";
    root.style.borderRadius = "12px";
    root.style.boxShadow = "0 14px 32px rgba(124, 45, 18, 0.18)";
    root.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";
    root.style.color = "#7c2d12";

    const title = document.createElement("div");
    title.style.fontWeight = "700";
    title.textContent = `Security warning for ${input.domain}`;

    const details = document.createElement("div");
    details.style.fontSize = "13px";
    details.textContent = `${input.recommendation} Reasons: ${input.reasons.join(", ") || "policy check"}.`;

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.gap = "8px";
    actions.style.justifyContent = "flex-end";

    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.textContent = "Cancel";
    cancel.style.border = "1px solid #fb923c";
    cancel.style.background = "#fff";
    cancel.style.color = "#9a3412";
    cancel.style.borderRadius = "8px";
    cancel.style.padding = "6px 10px";
    cancel.style.cursor = "pointer";
    cancel.onclick = () => {
      clearWarnBanner();
      resolve("cancel");
    };

    actions.appendChild(cancel);
    if (input.canContinue) {
      const proceed = document.createElement("button");
      proceed.type = "button";
      proceed.textContent = "Continue";
      proceed.style.border = "1px solid #c2410c";
      proceed.style.background = "#c2410c";
      proceed.style.color = "#fff";
      proceed.style.borderRadius = "8px";
      proceed.style.padding = "6px 10px";
      proceed.style.cursor = "pointer";
      proceed.onclick = () => {
        clearWarnBanner();
        resolve("continue");
      };
      actions.appendChild(proceed);
    }

    root.appendChild(title);
    root.appendChild(details);
    root.appendChild(actions);
    document.documentElement.appendChild(root);
  });
}

export function showBlockActionBanner(input: {
  domain: string;
  reason: string;
  policyVersion?: string;
  onRequestReview?: () => void;
}): void {
  clearBlockActionBanner();

  const root = document.createElement("div");
  root.id = BLOCK_NOTICE_ID;
  root.style.position = "fixed";
  root.style.left = "16px";
  root.style.right = "16px";
  root.style.bottom = "16px";
  root.style.zIndex = "2147483647";
  root.style.display = "flex";
  root.style.flexDirection = "column";
  root.style.gap = "8px";
  root.style.padding = "12px 14px";
  root.style.background = "#fff1f2";
  root.style.border = "1px solid #fda4af";
  root.style.borderRadius = "12px";
  root.style.boxShadow = "0 14px 32px rgba(127, 29, 29, 0.22)";
  root.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";
  root.style.color = "#7f1d1d";

  const title = document.createElement("div");
  title.style.fontWeight = "700";
  title.textContent = `Action blocked for ${input.domain}`;

  const details = document.createElement("div");
  details.style.fontSize = "13px";
  details.textContent = `${input.reason} ${
    input.policyVersion ? `(Policy: ${input.policyVersion})` : ""
  }`.trim();

  const actions = document.createElement("div");
  actions.style.display = "flex";
  actions.style.gap = "8px";
  actions.style.justifyContent = "flex-end";

  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.textContent = "Dismiss";
  dismiss.style.border = "1px solid #fda4af";
  dismiss.style.background = "#fff";
  dismiss.style.color = "#7f1d1d";
  dismiss.style.borderRadius = "8px";
  dismiss.style.padding = "6px 10px";
  dismiss.style.cursor = "pointer";
  dismiss.onclick = () => clearBlockActionBanner();
  actions.appendChild(dismiss);

  if (input.onRequestReview) {
    const review = document.createElement("button");
    review.type = "button";
    review.textContent = "Request review";
    review.style.border = "1px solid #7f1d1d";
    review.style.background = "#7f1d1d";
    review.style.color = "#fff";
    review.style.borderRadius = "8px";
    review.style.padding = "6px 10px";
    review.style.cursor = "pointer";
    review.onclick = () => {
      input.onRequestReview?.();
      clearBlockActionBanner();
    };
    actions.appendChild(review);
  }

  root.appendChild(title);
  root.appendChild(details);
  root.appendChild(actions);
  document.documentElement.appendChild(root);

  window.setTimeout(() => {
    const existing = document.getElementById(BLOCK_NOTICE_ID);
    if (existing) existing.remove();
  }, 8000);
}

export function showMonitoringBanner(input: {
  domain: string;
  message: string;
}): void {
  clearMonitoringBanner();

  const root = document.createElement("div");
  root.id = MONITORING_NOTICE_ID;
  root.style.position = "fixed";
  root.style.right = "16px";
  root.style.bottom = "16px";
  root.style.zIndex = "2147483647";
  root.style.maxWidth = "520px";
  root.style.display = "flex";
  root.style.flexDirection = "column";
  root.style.gap = "6px";
  root.style.padding = "10px 12px";
  root.style.background = "#ecfeff";
  root.style.border = "1px solid #67e8f9";
  root.style.borderRadius = "12px";
  root.style.boxShadow = "0 14px 30px rgba(8, 47, 73, 0.2)";
  root.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";
  root.style.color = "#0e7490";

  const title = document.createElement("div");
  title.style.fontWeight = "700";
  title.textContent = `Monitoring mode on ${input.domain}`;

  const details = document.createElement("div");
  details.style.fontSize = "13px";
  details.textContent = input.message;

  root.appendChild(title);
  root.appendChild(details);
  document.documentElement.appendChild(root);

  window.setTimeout(() => {
    const existing = document.getElementById(MONITORING_NOTICE_ID);
    if (existing) existing.remove();
  }, 6000);
}

export function showMeetingNotetakerBanner(input: {
  domain: string;
  surfaceLabel: string;
  providerLabel: string;
  reason: string;
  onRecordBlockRequest?: () => void | Promise<void>;
}): void {
  clearMeetingNotetakerBanner();

  const root = document.createElement("div");
  root.id = MEETING_NOTETAKER_ID;
  root.style.position = "fixed";
  root.style.left = "16px";
  root.style.right = "16px";
  root.style.bottom = "16px";
  root.style.zIndex = "2147483647";
  root.style.display = "flex";
  root.style.flexDirection = "column";
  root.style.gap = "8px";
  root.style.padding = "12px 14px";
  root.style.background = "#fffbeb";
  root.style.border = "1px solid #f59e0b";
  root.style.borderRadius = "12px";
  root.style.boxShadow = "0 14px 32px rgba(120, 53, 15, 0.22)";
  root.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";
  root.style.color = "#78350f";

  const title = document.createElement("div");
  title.style.fontWeight = "800";
  title.textContent = `AI notetaker detected in ${input.surfaceLabel}`;

  const details = document.createElement("div");
  details.style.fontSize = "13px";
  details.textContent = `${input.providerLabel} appears visible in this meeting. ${input.reason}`;

  const honesty = document.createElement("div");
  honesty.style.fontSize = "12px";
  honesty.style.color = "#92400e";
  honesty.textContent =
    "Hawk can record a block request now. Automatic removal requires Meet/Teams host or admin enforcement permissions.";

  const actions = document.createElement("div");
  actions.style.display = "flex";
  actions.style.gap = "8px";
  actions.style.justifyContent = "flex-end";

  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.textContent = "Dismiss";
  dismiss.style.border = "1px solid #f59e0b";
  dismiss.style.background = "#fff";
  dismiss.style.color = "#78350f";
  dismiss.style.borderRadius = "8px";
  dismiss.style.padding = "6px 10px";
  dismiss.style.cursor = "pointer";
  dismiss.onclick = () => clearMeetingNotetakerBanner();
  actions.appendChild(dismiss);

  const requestBlock = document.createElement("button");
  requestBlock.type = "button";
  requestBlock.textContent = "Record block request";
  requestBlock.style.border = "1px solid #92400e";
  requestBlock.style.background = "#92400e";
  requestBlock.style.color = "#fff";
  requestBlock.style.borderRadius = "8px";
  requestBlock.style.padding = "6px 10px";
  requestBlock.style.cursor = "pointer";
  requestBlock.onclick = async () => {
    requestBlock.disabled = true;
    requestBlock.textContent = "Recorded";
    await input.onRecordBlockRequest?.();
    window.setTimeout(() => clearMeetingNotetakerBanner(), 1800);
  };
  actions.appendChild(requestBlock);

  root.appendChild(title);
  root.appendChild(details);
  root.appendChild(honesty);
  root.appendChild(actions);
  document.documentElement.appendChild(root);
}

export function showJustificationModal(input: {
  domain: string;
  reason: string;
  recommendation: string;
  defaultEmail?: string;
  defaultRole?: string;
  defaultDepartment?: string;
}): Promise<{
  action: "submit";
  justification: string;
  submitter_name: string;
  submitter_email: string;
  submitter_role: string;
  submitter_department?: string;
} | { action: "cancel" }> {
  clearJustificationModal();
  return new Promise((resolve) => {
    const overlay = document.createElement("div");
    overlay.id = JUSTIFICATION_ID;
    overlay.style.position = "fixed";
    overlay.style.inset = "0";
    overlay.style.zIndex = "2147483647";
    overlay.style.background = "rgba(15, 23, 42, 0.55)";
    overlay.style.display = "flex";
    overlay.style.alignItems = "center";
    overlay.style.justifyContent = "center";
    overlay.style.fontFamily = "system-ui, -apple-system, Segoe UI, Roboto, sans-serif";

    const card = document.createElement("div");
    card.style.width = "min(560px, calc(100% - 32px))";
    card.style.background = "#ffffff";
    card.style.borderRadius = "12px";
    card.style.padding = "16px";
    card.style.boxShadow = "0 20px 55px rgba(2, 6, 23, 0.35)";
    card.style.color = "#0f172a";
    card.style.display = "flex";
    card.style.flexDirection = "column";
    card.style.gap = "10px";

    const title = document.createElement("h3");
    title.textContent = "Justification required";
    title.style.margin = "0";
    title.style.fontSize = "18px";

    const summary = document.createElement("p");
    summary.textContent = `Sensitive data movement was detected to ${input.domain}.`;
    summary.style.margin = "0";
    summary.style.fontSize = "14px";
    summary.style.color = "#334155";

    const reason = document.createElement("p");
    reason.textContent = `Reason: ${input.reason}`;
    reason.style.margin = "0";
    reason.style.fontSize = "13px";
    reason.style.color = "#475569";

    const recommendation = document.createElement("p");
    recommendation.textContent = input.recommendation;
    recommendation.style.margin = "0";
    recommendation.style.fontSize = "13px";
    recommendation.style.color = "#475569";

    const fieldStyle = (field: HTMLInputElement | HTMLTextAreaElement): void => {
      field.style.width = "100%";
      field.style.border = "1px solid #cbd5e1";
      field.style.borderRadius = "8px";
      field.style.padding = "8px";
      field.style.fontSize = "13px";
      field.style.boxSizing = "border-box";
    };

    const identityGrid = document.createElement("div");
    identityGrid.style.display = "grid";
    identityGrid.style.gridTemplateColumns = "1fr 1fr";
    identityGrid.style.gap = "8px";

    const nameInput = document.createElement("input");
    nameInput.type = "text";
    nameInput.placeholder = "Submitter name";
    nameInput.autocomplete = "name";
    fieldStyle(nameInput);

    const emailInput = document.createElement("input");
    emailInput.type = "email";
    emailInput.placeholder = "Submitter email";
    emailInput.autocomplete = "email";
    emailInput.value = String(input.defaultEmail || "");
    fieldStyle(emailInput);

    const roleInput = document.createElement("input");
    roleInput.type = "text";
    roleInput.placeholder = "Role / job title";
    // Valid HTML autofill token absent from this TypeScript version's AutoFill union.
    roleInput.setAttribute("autocomplete", "organization-title");
    roleInput.value = String(input.defaultRole || "");
    fieldStyle(roleInput);

    const departmentInput = document.createElement("input");
    departmentInput.type = "text";
    departmentInput.placeholder = "Department (optional)";
    departmentInput.autocomplete = "organization";
    departmentInput.value = String(input.defaultDepartment || "");
    fieldStyle(departmentInput);

    identityGrid.appendChild(nameInput);
    identityGrid.appendChild(emailInput);
    identityGrid.appendChild(roleInput);
    identityGrid.appendChild(departmentInput);

    const textArea = document.createElement("textarea");
    textArea.rows = 5;
    textArea.placeholder = "Enter business justification...";
    fieldStyle(textArea);

    const actions = document.createElement("div");
    actions.style.display = "flex";
    actions.style.justifyContent = "flex-end";
    actions.style.gap = "8px";

    const cancel = document.createElement("button");
    cancel.type = "button";
    cancel.textContent = "Cancel";
    cancel.style.border = "1px solid #94a3b8";
    cancel.style.background = "#fff";
    cancel.style.color = "#334155";
    cancel.style.borderRadius = "8px";
    cancel.style.padding = "7px 10px";
    cancel.style.cursor = "pointer";
    cancel.onclick = () => {
      clearJustificationModal();
      resolve({ action: "cancel" });
    };

    const submit = document.createElement("button");
    submit.type = "button";
    submit.textContent = "Submit & Continue";
    submit.style.border = "1px solid #0f172a";
    submit.style.background = "#0f172a";
    submit.style.color = "#fff";
    submit.style.borderRadius = "8px";
    submit.style.padding = "7px 10px";
    submit.style.cursor = "pointer";
    submit.onclick = () => {
      const submitter_name = nameInput.value.trim();
      const submitter_email = emailInput.value.trim().toLowerCase();
      const submitter_role = roleInput.value.trim();
      const submitter_department = departmentInput.value.trim();
      const justification = textArea.value.trim();
      if (!submitter_name) {
        nameInput.focus();
        return;
      }
      if (!submitter_email) {
        emailInput.focus();
        return;
      }
      if (!submitter_role) {
        roleInput.focus();
        return;
      }
      if (!justification) {
        textArea.focus();
        return;
      }
      clearJustificationModal();
      resolve({
        action: "submit",
        justification,
        submitter_name,
        submitter_email,
        submitter_role,
        submitter_department: submitter_department || undefined,
      });
    };

    actions.appendChild(cancel);
    actions.appendChild(submit);

    card.appendChild(title);
    card.appendChild(summary);
    card.appendChild(reason);
    card.appendChild(recommendation);
    card.appendChild(identityGrid);
    card.appendChild(textArea);
    card.appendChild(actions);
    overlay.appendChild(card);
    document.documentElement.appendChild(overlay);
    if (!nameInput.value.trim()) nameInput.focus();
    else if (!emailInput.value.trim()) emailInput.focus();
    else if (!roleInput.value.trim()) roleInput.focus();
    else textArea.focus();
  });
}
