import { describe, expect, it, vi } from "vitest";

import {
  attachVisualClassificationEvidence,
  buildRuntimeControlFileMeta,
  buildRuntimeControlTransferFileMeta,
  classifyDroppedFileTransferForDestination,
  classifyPasteTimeoutFallback,
  classifySpreadsheetUploadForAi,
  classifyTextPasteForAi,
  classifyVisualUploadControl,
  classifyVisibleOutputActionControl,
  classifyVisibleOutputCopyControl,
  clickAttachmentRemovalControl,
  clearNativeDropOverlays,
  emitNonBlockingDataTransferTelemetry,
  insertText,
  isAttachmentRemovalControlLabel,
  isPromptSubmitControlLabel,
  releaseNativeDropOverlay,
  schedulePromptSubmitWhenReady,
  suppressNativeFileDragOverlay,
} from "./data-transfer-hooks";
import type { ExtensionPolicy } from "../policy-sync";

function crc32(bytes: Uint8Array): number {
  let crc = 0xffffffff;
  for (const byte of bytes) {
    crc ^= byte;
    for (let idx = 0; idx < 8; idx += 1) {
      crc = (crc >>> 1) ^ (crc & 1 ? 0xedb88320 : 0);
    }
  }
  return (crc ^ 0xffffffff) >>> 0;
}

function writeUint16(buffer: number[], value: number): void {
  buffer.push(value & 0xff, (value >>> 8) & 0xff);
}

function writeUint32(buffer: number[], value: number): void {
  buffer.push(value & 0xff, (value >>> 8) & 0xff, (value >>> 16) & 0xff, (value >>> 24) & 0xff);
}

function minimalStoredZip(entries: Record<string, string>): Uint8Array {
  const output: number[] = [];
  const central: number[] = [];
  const encoder = new TextEncoder();

  for (const [name, content] of Object.entries(entries)) {
    const nameBytes = encoder.encode(name);
    const contentBytes = encoder.encode(content);
    const localOffset = output.length;
    const checksum = crc32(contentBytes);

    writeUint32(output, 0x04034b50);
    writeUint16(output, 20);
    writeUint16(output, 0);
    writeUint16(output, 0);
    writeUint16(output, 0);
    writeUint16(output, 0);
    writeUint32(output, checksum);
    writeUint32(output, contentBytes.length);
    writeUint32(output, contentBytes.length);
    writeUint16(output, nameBytes.length);
    writeUint16(output, 0);
    output.push(...nameBytes, ...contentBytes);

    writeUint32(central, 0x02014b50);
    writeUint16(central, 20);
    writeUint16(central, 20);
    writeUint16(central, 0);
    writeUint16(central, 0);
    writeUint16(central, 0);
    writeUint16(central, 0);
    writeUint32(central, checksum);
    writeUint32(central, contentBytes.length);
    writeUint32(central, contentBytes.length);
    writeUint16(central, nameBytes.length);
    writeUint16(central, 0);
    writeUint16(central, 0);
    writeUint16(central, 0);
    writeUint16(central, 0);
    writeUint32(central, 0);
    writeUint32(central, localOffset);
    central.push(...nameBytes);
  }

  const centralOffset = output.length;
  output.push(...central);
  writeUint32(output, 0x06054b50);
  writeUint16(output, 0);
  writeUint16(output, 0);
  writeUint16(output, Object.keys(entries).length);
  writeUint16(output, Object.keys(entries).length);
  writeUint32(output, central.length);
  writeUint32(output, centralOffset);
  writeUint16(output, 0);
  return new Uint8Array(output);
}

function xlsxFile(name: string, cellText: string): File {
  const xml = `<?xml version="1.0" encoding="UTF-8"?>
    <worksheet><sheetData><row><c t="inlineStr"><is><t>${cellText}</t></is></c></row></sheetData></worksheet>`;
  const bytes = minimalStoredZip({
    "xl/worksheets/sheet1.xml": xml,
    "xl/sharedStrings.xml": "<sst></sst>",
  });
  return new File([new Uint8Array(bytes).buffer], name, {
    type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
  });
}

const policy: ExtensionPolicy = {
  tenant_id: "t1",
  platform_mode: "enforce",
  policy_version: "pv1",
  approved_domains: ["chatgpt.com"],
  blocked_domains: [],
  warn_domains: [],
  critical_domains: [],
  unknown_domain_behavior: "warn",
  interaction_rules: {
    input_checks_enabled: true,
    output_checks_enabled: true,
    sensitive_patterns: ["(?i)api[_\\s-]?key\\s*[:=]\\s*[A-Za-z0-9_-]{8,}"],
    blocked_keywords: [],
    high_risk_terms: [],
    hold_for_backend_on_ambiguous: true,
    backend_allow_confirmation_enabled: false,
  },
  browser_automation_control: {
    policy_id: "browser-automation-control-default",
    name: "Browser Automation Control",
    category: "BROWSER_AUTOMATION_CONTROL",
    mode: "block",
    enabled: true,
    scope: {
      users: [],
      groups: [],
      tenant_id: "t1",
      surfaces: ["browser_extension"],
      source_vendors: [],
      agentic_browser_assets: [],
      domains_allowlist: ["chatgpt.com"],
      domains_blocklist: [],
      url_patterns_allowlist: [],
      url_patterns_blocklist: [],
    },
    automation: {
      detection_required: true,
      confidence_threshold: 0.6,
      sources: ["browser_visible", "unknown"],
    },
    allowed_actions: ["page_view", "search", "navigate", "read_content"],
    blocked_actions: ["add_to_cart", "checkout"],
    action_overrides: [],
    decisions: {
      on_allowed_browsing: "allow",
      on_automation_detected: "warn",
      on_blocked_domain: "block",
      on_disallowed_domain: "warn",
      on_blocked_action: "block",
      on_scope_violation: "block",
      on_unknown_automation_source: "warn",
      on_sensitive_data_or_secret: "block",
    },
  },
  intent_aware_action_control: {
    policy_id: "intent-aware-default",
    schema_version: "intent-aware-ai-action-control/v1",
    name: "Intent-Aware AI Action Control",
    category: "INTENT_AWARE_AI_ACTION_CONTROL",
    mode: "block",
    enabled: true,
    scope: {
      users: [],
      groups: [],
      surfaces: ["browser_extension"],
      applications: [],
      domains: [],
      destination_trust_levels: ["public", "unknown"],
    },
    allowed_intents: ["public_research", "company_lookup"],
    blocked_intents: ["credential_or_secret_handling"],
    intent_action_rules: [],
    copy_export_rules: [
      {
        output_contains: ["business_email", "secret_like_value"],
        output_sensitivity_threshold: "medium",
        action: "copy_output",
        decision: "block",
      },
    ],
    alignment_rules: [],
  },
};

describe("visible output copy control", () => {
  it("allows generic public summaries", () => {
    const result = classifyVisibleOutputCopyControl(
      "Microsoft is a public technology company with cloud and productivity products.",
      policy,
    );

    expect(result.decision).toBe("allow");
    expect(result.outputSensitivity).toBe("low");
  });

  it("blocks copied AI output containing business emails", () => {
    const result = classifyVisibleOutputCopyControl(
      "Send the proposal to jane@clientcorp.com and ops@clientcorp.com.",
      policy,
    );

    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("ai_output_copy_contains_business_email");
    expect(result.signalTypes).toContain("output_contains_business_email");
  });

  it("blocks copied AI output containing high-confidence API keys", () => {
    const result = classifyVisibleOutputCopyControl(
      "Use API key: sk-test1234567890abcdef for the example.",
      policy,
    );

    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("ai_output_copy_contains_secret");
    expect(result.signalTypes).toContain("output_contains_secret");
  });

  it("blocks copied AI output containing high-risk payment PII", () => {
    const result = classifyVisibleOutputCopyControl(
      "Customer Jane Doe card number 4111 1111 1111 1111 expires 12/29.",
      policy,
    );

    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("ai_output_copy_contains_high_risk_pii");
    expect(result.outputSensitivity).toBe("critical");
    expect(result.signalTypes).toContain("output_contains_high_risk_pii");
  });

  it("blocks copied AI output containing proprietary code context", () => {
    const result = classifyVisibleOutputCopyControl(
      [
        "Here is the internal auth middleware patch:",
        "export async function verifyTenantToken(req) {",
        "  const tenant = req.headers['x-tenant-id'];",
        "  return checkRbac(req.user, tenant, 'admin');",
        "}",
      ].join("\n"),
      policy,
    );

    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("ai_output_copy_contains_protected_code");
    expect(result.outputSensitivity).toBe("high");
    expect(result.signalTypes).toContain("output_contains_protected_code");
  });

  it("blocks visible download/export/share/send/form actions for protected AI output", () => {
    const sensitiveOutput = "Export these customer contacts: jane@clientcorp.com, ops@clientcorp.com.";

    for (const action of ["download_output", "export_output", "share_output", "send_email", "submit_form"] as const) {
      const result = classifyVisibleOutputActionControl(sensitiveOutput, policy, action);

      expect(result.decision).toBe("block");
      expect(result.reasonCode).toBe("ai_output_action_contains_business_email");
      expect(result.signalTypes).toContain(`visible_${action}`);
      expect(result.signalTypes).toContain("output_contains_business_email");
    }
  });

  it("allows generic visible output export when no protected data is present", () => {
    const result = classifyVisibleOutputActionControl(
      "Microsoft is a public technology company with cloud and productivity products.",
      policy,
      "export_output",
    );

    expect(result.decision).toBe("allow");
    expect(result.reasonCode).toBe("visible_output_action_allowed");
    expect(result.outputSensitivity).toBe("low");
  });
});

describe("approved prompt submit controls", () => {
  it("recognizes AI prompt send controls without matching upload or cancel controls", () => {
    expect(isPromptSubmitControlLabel("Send prompt")).toBe(true);
    expect(isPromptSubmitControlLabel("send-button")).toBe(true);
    expect(isPromptSubmitControlLabel("Submit message")).toBe(true);

    expect(isPromptSubmitControlLabel("Upload file")).toBe(false);
    expect(isPromptSubmitControlLabel("Cancel")).toBe(false);
    expect(isPromptSubmitControlLabel("Attach file")).toBe(false);
  });

  it("restores accepted justification prompt text into editable fields", () => {
    const textarea = {
      value: "",
      selectionStart: 0,
      selectionEnd: 0,
      focus: vi.fn(),
      dispatchEvent: vi.fn(() => true),
    };

    const inserted = insertText(
      textarea as unknown as EventTarget,
      "Customer email: jane@clientcorp.com\nContract value: AED 250,000",
    );

    expect(inserted).toBe(true);
    expect(textarea.value).toContain("jane@clientcorp.com");
    expect(textarea.value).toContain("Contract value");
    expect(textarea.dispatchEvent).toHaveBeenCalled();
  });

  it("waits for accepted justification prompt text before sending", () => {
    vi.useFakeTimers();

    class FakeElement {
      disabled = false;
      parentElement: FakeElement | null = null;
      textContent = "";
      click = vi.fn();

      getAttribute(): string | null {
        return null;
      }
    }

    const textarea = {
      value: "",
      selectionStart: 0,
      selectionEnd: 0,
      focus: vi.fn(),
      dispatchEvent: vi.fn(() => true),
    };
    const button = new FakeElement();
    button.textContent = "Send prompt";

    vi.stubGlobal("window", { setTimeout });
    vi.stubGlobal("Element", FakeElement);
    vi.stubGlobal("HTMLElement", FakeElement);
    vi.stubGlobal("document", {
      querySelectorAll: vi.fn(() => [button]),
    });

    schedulePromptSubmitWhenReady(textarea as unknown as EventTarget, "Customer email: jane@clientcorp.com");

    vi.advanceTimersByTime(121);
    expect(textarea.value).toContain("jane@clientcorp.com");
    expect(button.click).not.toHaveBeenCalled();

    vi.advanceTimersByTime(200);
    expect(button.click).toHaveBeenCalledTimes(1);

    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("replays accepted justification prompt text into the live prompt field when the original editor was replaced", () => {
    vi.useFakeTimers();

    class FakeElement {
      disabled = false;
      parentElement: FakeElement | null = null;
      textContent = "";
      isConnected = true;
      click = vi.fn();

      getAttribute(): string | null {
        return null;
      }

      matches(): boolean {
        return false;
      }

      closest(): Element | null {
        return null;
      }
    }

    const staleTextarea = {
      value: "",
      selectionStart: 0,
      selectionEnd: 0,
      isConnected: false,
      focus: vi.fn(),
      dispatchEvent: vi.fn(() => true),
    };
    const liveTextarea = {
      value: "",
      selectionStart: 0,
      selectionEnd: 0,
      isConnected: true,
      focus: vi.fn(),
      dispatchEvent: vi.fn(() => true),
      matches: vi.fn((selector: string) => selector.includes("textarea")),
      closest: vi.fn(() => null),
    };
    const button = new FakeElement();
    button.textContent = "Send prompt";

    vi.stubGlobal("window", { setTimeout, getSelection: vi.fn(() => null) });
    vi.stubGlobal("Element", FakeElement);
    vi.stubGlobal("HTMLElement", FakeElement);
    vi.stubGlobal("document", {
      activeElement: liveTextarea,
      querySelector: vi.fn(() => liveTextarea),
      querySelectorAll: vi.fn(() => [button]),
    });

    schedulePromptSubmitWhenReady(
      staleTextarea as unknown as EventTarget,
      "Customer email: jane@clientcorp.com",
    );

    vi.advanceTimersByTime(121);
    expect(staleTextarea.value).toBe("");
    expect(liveTextarea.value).toContain("jane@clientcorp.com");
    expect(button.click).not.toHaveBeenCalled();

    vi.advanceTimersByTime(200);
    expect(button.click).toHaveBeenCalledTimes(1);

    vi.unstubAllGlobals();
    vi.useRealTimers();
  });
});

describe("runtime control file metadata", () => {
  it("requires justification instead of generic continue when Gmail paste policy check times out", () => {
    const result = classifyPasteTimeoutFallback({
      destination_surface_type: "email",
      source_classification_hint: "protected",
      sensitive: false,
      platform_mode: "enforce",
    });

    expect(result).toBe("require_justification");
  });

  it("still blocks protected paste timeout fallback to public AI tools in enforce mode", () => {
    const result = classifyPasteTimeoutFallback({
      destination_surface_type: "ai_tool",
      source_classification_hint: "protected",
      sensitive: true,
      platform_mode: "enforce",
    });

    expect(result).toBe("block");
  });

  it("requires justification for business/customer text pasted to public AI", () => {
    const result = classifyTextPasteForAi([
      "Customer email: jane@clientcorp.com",
      "Contract value: AED 250,000",
      "Send this to ChatGPT.",
    ].join("\n"));

    expect(result.decision).toBe("require_justification");
    expect(result.reasonCode).toBe("business_text_paste_to_public_ai");
    expect(result.signalTypes).toContain("paste_contains_business_email");
    expect(result.signalTypes).toContain("business_text_paste");
  });

  it("blocks high-confidence secrets pasted to public AI", () => {
    const result = classifyTextPasteForAi("Please analyze this production API key: api_key: sk-live-1234567890abcdef");

    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("text_paste_contains_secret");
    expect(result.signalTypes).toContain("paste_contains_secret");
  });

  it("blocks high-risk payment PII pasted to public AI", () => {
    const result = classifyTextPasteForAi("Customer Jane Doe card number 4111 1111 1111 1111 phone +971501234567");

    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("text_paste_contains_high_risk_pii");
    expect(result.signalTypes).toContain("paste_contains_high_risk_pii");
  });

  it("requires justification for SQL explanation prompts with schema context", () => {
    const result = classifyTextPasteForAi([
      "Explain this SQL query for the reporting module:",
      "SELECT customer_id, total_amount FROM dbo.Invoice WHERE status = 'open'",
    ].join("\n"));

    expect(result.decision).toBe("require_justification");
    expect(result.reasonCode).toBe("business_text_paste_to_public_ai");
    expect(result.signalTypes).toContain("sql_database_context");
    expect(result.signalTypes).toContain("business_text_paste");
  });

  it("blocks destructive SQL pasted to public AI", () => {
    const result = classifyTextPasteForAi("Explain and optimize: DROP TABLE dbo.Customer; DELETE FROM dbo.Invoice;");

    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("text_paste_contains_operational_command");
    expect(result.signalTypes).toContain("paste_contains_operational_command");
    expect(result.signalTypes).toContain("sql_database_context");
  });

  it("requires justification for business contact/account spreadsheets uploaded to public AI", () => {
    const result = classifySpreadsheetUploadForAi([
      {
        name: "account-list.xlsx",
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        text_preview: "account,email,owner,renewal\nAcme,jane@clientcorp.com,Asha,2026-06-30",
      },
    ]);

    expect(result.decision).toBe("require_justification");
    expect(result.reasonCode).toBe("business_spreadsheet_to_public_ai");
    expect(result.signalTypes).toContain("business_spreadsheet_upload");
    expect(result.signalTypes).toContain("spreadsheet_contains_business_email");
  });

  it("requires justification for engineering BOQ spreadsheets instead of hard blocking SOW drafting", () => {
    const result = classifySpreadsheetUploadForAi([
      {
        name: "solution-boq.xlsx",
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        text_preview: [
          "Qty,Part Number,Description,Type",
          "1,FMG-200G,FortiManager-200G centralized management appliance,HW",
          "1,FC-10-M200G-247-02-12,FortiCare Premium Support,SS",
        ].join("\n"),
      },
    ]);

    expect(result.decision).toBe("require_justification");
    expect(result.reasonCode).toBe("business_spreadsheet_to_public_ai");
    expect(result.signalTypes).toContain("engineering_boq_context");
    expect(result.signalTypes).toContain("business_spreadsheet_upload");
  });

  it("allows generic spreadsheets to avoid overblocking all Excel uploads", () => {
    const result = classifySpreadsheetUploadForAi([
      {
        name: "weather-summary.xlsx",
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        text_preview: "city,temperature,humidity\nDubai,39,48",
      },
    ]);

    expect(result.decision).toBe("allow");
    expect(result.reasonCode).toBe("generic_spreadsheet_upload");
  });

  it("blocks spreadsheet uploads with high-confidence API keys", () => {
    const result = classifySpreadsheetUploadForAi([
      {
        name: "service-credentials.xlsx",
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        text_preview: "service,api_key\nprod,api_key: sk-live-1234567890abcdef",
      },
    ]);

    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("spreadsheet_contains_secret");
    expect(result.signalTypes).toContain("spreadsheet_contains_secret");
  });

  it("blocks spreadsheet uploads with credit card data even when filename is generic", () => {
    const result = classifySpreadsheetUploadForAi([
      {
        name: "sample.xlsx",
        type: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        text_preview: "name,card,phone\nJane Doe,4111 1111 1111 1111,+971501234567",
      },
    ]);

    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("spreadsheet_contains_high_risk_pii");
    expect(result.signalTypes).toContain("spreadsheet_contains_high_risk_pii");
  });

  it("extracts small XLSX cell text so innocently named customer spreadsheets require justification", async () => {
    const file = xlsxFile("q2-summary.xlsx", "account,email,owner Acme,jane@clientcorp.com,Asha");

    const [meta] = await buildRuntimeControlFileMeta([file]);
    const result = classifySpreadsheetUploadForAi([meta]);

    expect(meta.text_preview).toContain("jane@clientcorp.com");
    expect(meta.inline_text_preview).toBe(true);
    expect(result.decision).toBe("require_justification");
    expect(result.reasonCode).toBe("business_spreadsheet_to_public_ai");
    expect(result.signalTypes).toContain("spreadsheet_contains_business_email");
  });

  it("extracts small XLSX cell text so secrets in benign filenames are blocked", async () => {
    const file = xlsxFile("q2-summary.xlsx", "service,api_key prod,api_key: sk-live-1234567890abcdef");

    const [meta] = await buildRuntimeControlFileMeta([file]);
    const result = classifySpreadsheetUploadForAi([meta]);

    expect(meta.text_preview).toContain("sk-live-1234567890abcdef");
    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("spreadsheet_contains_secret");
  });

  it("extracts small XLSX cell text so credit card data in benign filenames is blocked", async () => {
    const file = xlsxFile("sample.xlsx", "customer,card,phone Jane Doe,4111 1111 1111 1111,+971501234567");

    const [meta] = await buildRuntimeControlFileMeta([file]);
    const result = classifySpreadsheetUploadForAi([meta]);

    expect(meta.text_preview).toContain("4111 1111 1111 1111");
    expect(result.decision).toBe("block");
    expect(result.reasonCode).toBe("spreadsheet_contains_high_risk_pii");
  });

  it("includes bounded text preview for CSV uploads so backend can classify business emails", async () => {
    const file = new File(
      ["name,email,company\nJane,jane@clientcorp.com,ClientCorp\nPat,pat@prospectco.com,ProspectCo"],
      "contacts.csv",
      { type: "text/csv" },
    );

    const [meta] = await buildRuntimeControlFileMeta([file]);

    expect(meta.name).toBe("contacts.csv");
    expect(meta.type).toBe("text/csv");
    expect(meta.mime_type).toBe("text/csv");
    expect(meta.inline_text_preview).toBe(true);
    expect(String(meta.text_preview)).toContain("jane@clientcorp.com");
    expect(String(meta.text_preview)).toContain("pat@prospectco.com");
  });

  it("does not inline large text uploads into policy telemetry", async () => {
    const oversized = new File(["a".repeat(70_000)], "large.csv", { type: "text/csv" });

    const [meta] = await buildRuntimeControlFileMeta([oversized]);

    expect(meta.name).toBe("large.csv");
    expect(meta.text_preview).toBeUndefined();
    expect(meta.inline_text_preview).toBeUndefined();
  });

  it("blocks unverified screenshot uploads to AI tools in enforce mode", async () => {
    const file = new File(["fake image"], "Screenshot 2026-06-03 at 10.00.00.png", { type: "image/png" });
    const [meta] = await buildRuntimeControlFileMeta([file]);

    const decision = classifyVisualUploadControl([meta], policy, "ai_tool");

    expect(meta.inline_ocr_payload).toBe(true);
    expect(decision.decision).toBe("block");
    expect(decision.reasonCode).toBe("unverified_visual_content_upload");
    expect(decision.signalTypes).toContain("visual_content_upload");
    expect(decision.signalTypes).toContain("screenshot_upload");
  });

  it("requires justification when OCR text on a screenshot contains business contacts", () => {
    const meta = {
      name: "screenshot.png",
      mime_type: "image/png",
      ocr_text: "Customer contacts: Jane jane@clientcorp.com, renewal owner Asha",
    };
    const decision = classifyVisualUploadControl([
      meta,
    ], policy, "ai_tool");
    const [withEvidence] = attachVisualClassificationEvidence([meta], decision);

    expect(decision.decision).toBe("require_justification");
    expect(decision.reasonCode).toBe("visual_business_content_to_public_ai");
    expect(decision.signalTypes).toContain("visual_contains_business_email");
    expect(withEvidence?.visual_classification).toMatchObject({
      business_related: true,
      contains_secret: false,
      decision: "require_justification",
      reason_code: "visual_business_content_to_public_ai",
    });
  });

  it("requires justification when OCR text on a screenshot contains SQL/database schema context", () => {
    const meta = {
      name: "database screenshot.png",
      mime_type: "image/png",
      ocr_text: "Microsoft SQL Server Management Studio Databases Titus_Reporting Tables dbo.Attachment dbo.ErrorLog dbo.EventLog",
    };
    const decision = classifyVisualUploadControl([
      meta,
    ], policy, "ai_tool");

    expect(decision.decision).toBe("require_justification");
    expect(decision.reasonCode).toBe("visual_business_content_to_public_ai");
    expect(decision.signalTypes).toContain("visual_engineering_context");
  });

  it("blocks when OCR text on a screenshot contains a high-confidence secret", () => {
    const meta = {
      name: "screenshot.png",
      mime_type: "image/png",
      ocr_text: "Production api_key: sk-live-1234567890abcdef",
    };
    const decision = classifyVisualUploadControl([
      meta,
    ], policy, "ai_tool");
    const [withEvidence] = attachVisualClassificationEvidence([meta], decision);

    expect(decision.decision).toBe("block");
    expect(decision.reasonCode).toBe("visual_contains_secret");
    expect(decision.signalTypes).toContain("visual_contains_secret");
    expect(withEvidence?.visual_classification).toMatchObject({
      business_related: false,
      contains_secret: true,
      decision: "block",
      reason_code: "visual_contains_secret",
    });
  });

  it("blocks when OCR text on a screenshot contains high-risk payment PII", () => {
    const meta = {
      name: "sample-file.png",
      mime_type: "image/png",
      ocr_text: "Customer Jane Doe card number 4111 1111 1111 1111 phone +971501234567",
    };
    const decision = classifyVisualUploadControl([
      meta,
    ], policy, "ai_tool");
    const [withEvidence] = attachVisualClassificationEvidence([meta], decision);

    expect(decision.decision).toBe("block");
    expect(decision.reasonCode).toBe("visual_contains_high_risk_pii");
    expect(decision.signalTypes).toContain("visual_contains_high_risk_pii");
    expect(withEvidence?.visual_classification).toMatchObject({
      business_related: false,
      contains_high_risk_pii: true,
      decision: "block",
      reason_code: "visual_contains_high_risk_pii",
    });
  });

  it("blocks pasted screenshot image transfer metadata to AI tools in enforce mode", async () => {
    const file = new File(["fake image"], "image.png", { type: "image/png" });
    const meta = await buildRuntimeControlTransferFileMeta({
      files: { 0: file, length: 1 },
      items: {
        0: {
          kind: "file",
          type: "image/png",
          getAsFile: () => file,
        },
        length: 1,
      },
    });

    const decision = classifyVisualUploadControl(meta, policy, "ai_tool");

    expect(meta).toHaveLength(1);
    expect(meta[0]?.inline_ocr_payload).toBe(true);
    expect(decision.decision).toBe("block");
    expect(decision.reasonCode).toBe("unverified_visual_content_upload");
    expect(decision.signalTypes).toContain("visual_content_upload");
  });

  it("routes dragged business spreadsheets through the same justification policy as file picker uploads", async () => {
    const file = xlsxFile("q2-summary.xlsx", "account,email,contract Acme,jane@clientcorp.com,AED 250000");
    const meta = await buildRuntimeControlTransferFileMeta({
      files: { 0: file, length: 1 },
      items: {
        0: {
          kind: "file",
          type: file.type,
          getAsFile: () => file,
        },
        length: 1,
      },
    });

    const decision = classifyDroppedFileTransferForDestination(meta, policy, "ai_tool");

    expect(decision.decision).toBe("require_justification");
    expect(decision.reasonCode).toBe("business_spreadsheet_to_public_ai");
    expect(decision.signalTypes).toContain("drag_drop_file_upload");
    expect(decision.signalTypes).toContain("business_spreadsheet_upload");
  });

  it("blocks dragged spreadsheet files that contain high-confidence secrets", async () => {
    const file = xlsxFile("service-list.xlsx", "service,api_key prod,api_key: sk-live-1234567890abcdef");
    const meta = await buildRuntimeControlTransferFileMeta({
      files: { 0: file, length: 1 },
      items: {
        0: {
          kind: "file",
          type: file.type,
          getAsFile: () => file,
        },
        length: 1,
      },
    });

    const decision = classifyDroppedFileTransferForDestination(meta, policy, "ai_tool");

    expect(decision.decision).toBe("block");
    expect(decision.reasonCode).toBe("spreadsheet_contains_secret");
    expect(decision.signalTypes).toContain("drag_drop_file_upload");
    expect(decision.signalTypes).toContain("spreadsheet_contains_secret");
  });

  it("blocks dragged spreadsheet files that contain credit card data", async () => {
    const file = xlsxFile("sample.xlsx", "customer,card Jane Doe,4111 1111 1111 1111");
    const meta = await buildRuntimeControlTransferFileMeta({
      files: { 0: file, length: 1 },
      items: {
        0: {
          kind: "file",
          type: file.type,
          getAsFile: () => file,
        },
        length: 1,
      },
    });

    const decision = classifyDroppedFileTransferForDestination(meta, policy, "ai_tool");

    expect(decision.decision).toBe("block");
    expect(decision.reasonCode).toBe("spreadsheet_contains_high_risk_pii");
    expect(decision.signalTypes).toContain("drag_drop_file_upload");
    expect(decision.signalTypes).toContain("spreadsheet_contains_high_risk_pii");
  });

  it("does not fail the user action when data-transfer telemetry throws", async () => {
    const result = await emitNonBlockingDataTransferTelemetry(
      async () => {
        throw new TypeError("Cannot read properties of undefined (reading 'local')");
      },
      { event_type: "file_upload_detected", action_taken: "allow_file_upload" },
    );

    expect(result).toBe(false);
  });

  it("releases host drag/drop overlays after Hawk intercepts a file drop", () => {
    const target = new EventTarget();
    const body = new EventTarget();
    const fakeDocument = Object.assign(new EventTarget(), { body });
    const fakeWindow = new EventTarget();
    const previousDocument = globalThis.document;
    const previousWindow = globalThis.window;

    const seen: string[] = [];
    target.addEventListener("dragleave", () => seen.push("target:dragleave"));
    target.addEventListener("dragend", () => seen.push("target:dragend"));
    fakeDocument.addEventListener("dragleave", () => seen.push("document:dragleave"), { once: true });
    fakeWindow.addEventListener("dragend", () => seen.push("window:dragend"), { once: true });

    try {
      Object.defineProperty(globalThis, "document", { value: fakeDocument, configurable: true });
      Object.defineProperty(globalThis, "window", { value: fakeWindow, configurable: true });
      const dispatched = releaseNativeDropOverlay(target);

      expect(dispatched).toBeGreaterThanOrEqual(4);
      expect(seen).toContain("target:dragleave");
      expect(seen).toContain("target:dragend");
      expect(seen).toContain("document:dragleave");
      expect(seen).toContain("window:dragend");
    } finally {
      Object.defineProperty(globalThis, "document", { value: previousDocument, configurable: true });
      Object.defineProperty(globalThis, "window", { value: previousWindow, configurable: true });
    }
  });

  it("removes ChatGPT-style native drop veil after Hawk holds a drag/drop upload", () => {
    const previousDocument = globalThis.document;
    const previousWindow = globalThis.window;
    let removed = false;
    const windowRef = new EventTarget();
    const overlay = Object.assign(new EventTarget(), {
      textContent: "Add anything Drop any file here to add it to the conversation",
      style: {} as Record<string, string>,
      remove: () => {
        removed = true;
      },
    });
    const documentRef = Object.assign(new EventTarget(), {
      body: new EventTarget(),
      querySelectorAll: () => [overlay],
    });

    try {
      Object.defineProperty(globalThis, "document", { value: documentRef, configurable: true });
      Object.defineProperty(globalThis, "window", { value: windowRef, configurable: true });

      releaseNativeDropOverlay(overlay);

      expect(removed).toBe(true);
      expect(overlay.style.display).toBe("none");
    } finally {
      Object.defineProperty(globalThis, "document", { value: previousDocument, configurable: true });
      Object.defineProperty(globalThis, "window", { value: previousWindow, configurable: true });
    }
  });

  it("does not remove ChatGPT app containers when clearing native drop overlays", () => {
    const previousDocument = globalThis.document;
    const previousElement = globalThis.Element;
    class FakeElement extends EventTarget {
      id = "";
      tagName = "DIV";
      textContent = "";
      children: unknown[] = [];
      removed = false;
      attributes = new Map<string, string>();
      getAttribute(name: string): string | null {
        return this.attributes.get(name) ?? null;
      }
      setAttribute(name: string, value: string): void {
        this.attributes.set(name, value);
      }
      querySelector(): unknown {
        return null;
      }
      remove(): void {
        this.removed = true;
      }
    }

    try {
      Object.defineProperty(globalThis, "Element", { value: FakeElement, configurable: true });
      const appRoot = new FakeElement();
      appRoot.id = "__next";
      appRoot.textContent = "ChatGPT New chat Add anything Drop any file here to add it to the conversation";

      const documentRef = Object.assign(new EventTarget(), {
        documentElement: new FakeElement(),
        body: new FakeElement(),
        querySelectorAll: () => [appRoot],
      });
      Object.defineProperty(globalThis, "document", { value: documentRef, configurable: true });

      const cleared = clearNativeDropOverlays(documentRef);

      expect(cleared).toBe(0);
      expect(appRoot.removed).toBe(false);
    } finally {
      Object.defineProperty(globalThis, "document", { value: previousDocument, configurable: true });
      Object.defineProperty(globalThis, "Element", { value: previousElement, configurable: true });
    }
  });

  it("suppresses native AI app drag overlays before dropped files are reviewed", () => {
    const file = new File(["customer email,jane@clientcorp.com"], "accounts.csv", { type: "text/csv" });
    const event = new Event("dragover", { bubbles: true, cancelable: true }) as DragEvent;
    let stopped = false;
    let removed = false;
    Object.defineProperty(event, "dataTransfer", {
      configurable: true,
      value: {
        files: { 0: file, length: 1 },
        items: {
          0: { kind: "file", type: file.type, getAsFile: () => file },
          length: 1,
        },
        types: ["Files"],
      },
    });
    event.stopImmediatePropagation = () => {
      stopped = true;
    };

    const previousDocument = globalThis.document;
    const previousWindow = globalThis.window;
    const windowRef = Object.assign(new EventTarget(), {
      setTimeout: (callback: () => void) => {
        callback();
        return 1;
      },
    });
    const overlay = Object.assign(new EventTarget(), {
      textContent: "Add anything Drop any file here to add it to the conversation",
      style: {} as Record<string, string>,
      remove: () => {
        removed = true;
      },
    });
    const documentRef = Object.assign(new EventTarget(), {
      body: new EventTarget(),
      querySelectorAll: () => [overlay],
    });

    try {
      Object.defineProperty(globalThis, "document", { value: documentRef, configurable: true });
      Object.defineProperty(globalThis, "window", { value: windowRef, configurable: true });

      expect(suppressNativeFileDragOverlay(event)).toBe(true);
      expect(event.defaultPrevented).toBe(true);
      expect(stopped).toBe(true);
      expect(removed).toBe(true);
      expect(overlay.style.display).toBe("none");
    } finally {
      Object.defineProperty(globalThis, "document", { value: previousDocument, configurable: true });
      Object.defineProperty(globalThis, "window", { value: previousWindow, configurable: true });
    }
  });

  it("recognizes AI app attachment remove controls for blocked artifact cleanup", () => {
    for (const label of [
      "Remove file",
      "Remove attachment",
      "Delete image",
      "Dismiss upload",
      "Cancel attachment",
      "Clear Screenshot 2026-06-03.png",
    ]) {
      expect(isAttachmentRemovalControlLabel(label)).toBe(true);
    }

    for (const label of ["Send message", "Upload file", "Attach file", "Copy code", "Regenerate"]) {
      expect(isAttachmentRemovalControlLabel(label)).toBe(false);
    }
  });

  it("recognizes ChatGPT-style close controls on spreadsheet preview cards", () => {
    expect(isAttachmentRemovalControlLabel("Close spreadsheet preview exam_schedule.xlsx QTY")).toBe(true);
    expect(isAttachmentRemovalControlLabel("× spreadsheet preview exam_schedule.xlsx QTY")).toBe(true);
  });

  it("skips non-clickable labelled attachment nodes during cleanup", () => {
    expect(clickAttachmentRemovalControl({} as Element)).toBe(false);
  });
});
