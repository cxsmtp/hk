import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";
import { loadGatewayChoiceLists, loadGatewayPolicyVersions } from "../src/components/llm-gateway/document-control-load-state.mjs";

const read = (path) => readFile(new URL(path, import.meta.url), "utf8");

test("document gateway client posts multipart form data without masking authority flags", async () => {
  const api = await read("../src/lib/api.ts");
  assert.ok(/llmGatewayDocumentComplete[\s\S]*?\/llm-gateway\/documents\/complete/.test(api), "multipart client targets the document completion route");
  assert.ok(api.includes("new FormData()"), "request uses multipart form data");
  assert.ok(!/reversible_masking|restore_to_authenticated_caller/.test(api), "client cannot send masking authority");
});

test("policy publishing stores masking only in a new persisted policy version and defaults off", async () => {
  const page = await read("../src/app/policies/page.tsx");
  assert.ok(/getSession\(\)[\s\S]*?admin/i.test(page), "masking settings are shown only to admins");
  assert.ok(page.includes("reversible_masking"), "settings are persisted as a reversible masking policy");
  assert.ok(page.includes("setReversibleMaskingEnabled(false)"), "missing policy defaults to disabled");
  assert.ok(/scope:[\s\S]*?llm_gateway_security/.test(page), "settings are included in the published policy scope");
  for (const field of ["mapping_ttl_seconds", "max_document_bytes", "max_document_pages"]) {
    assert.ok(page.includes(field), `policy scope includes ${field}`);
  }
});

test("document card limits uploads and downloads only an allowed PDF or DOCX response", async () => {
  const component = await read("../src/components/llm-gateway/document-control.tsx");
  assert.ok(component.includes('accept=".pdf,.docx'), "file picker accepts only PDF and DOCX");
  assert.ok(component.includes("10 * 1024 * 1024"), "upload bound is 10 MiB");
  assert.ok(component.includes('decision !== "allow" && decision !== "warn"'), "download requires an allowed final decision");
  assert.ok(component.includes("content_base64"), "download requires the validated response payload");
  assert.ok(component.includes("URL.createObjectURL"), "allowed response is downloaded in the browser");
  assert.ok(/unsupported|scanned|encrypted/i.test(component), "unsupported document limits are visible");
  assert.ok(component.includes('versionsStatus !== "ready"'), "submission stays disabled while versions load or fail");
  assert.ok(component.includes("Retry versions") && component.includes("setRetryChoices"), "failed lookups can be retried");
  assert.ok(component.includes("if (!current) return"), "stale async selections cannot replace the current options");
  assert.ok(component.includes("file:text-cyan-100"), "native file picker text remains readable on the dark background");
  for (const code of [
    "unsupported_document_format", "document_size_limit", "document_page_limit", "document_text_limit",
    "document_block_limit", "invalid_pdf_document", "invalid_docx_document", "unsupported_document_content",
    "invalid_document_archive", "unsafe_document_archive", "document_structure_changed",
  ]) {
    assert.ok(new RegExp(`${code}: \\\"[^\\\"]*[A-Za-z][^\\\"]*\\\"`).test(component), `${code} has friendly copy`);
  }
  const call = component.slice(component.indexOf("api.llmGatewayDocumentComplete({"), component.indexOf("const blob = decodeAllowedDocument"));
  assert.ok(!/reversible_masking|restore_to_authenticated_caller/.test(call), "document call does not carry masking authority flags");
});

test("interaction security embeds the document workflow and exposes only sanitized masking metadata", async () => {
  const page = await read("../src/app/interaction-security/page.tsx");
  assert.ok(page.includes("DocumentControl"), "document workflow is on the existing security page");
  assert.ok(page.includes("reversible_masking"), "activity details show sanitized masking facts");
  assert.ok(!/content_base64|placeholder_token|restored_values/.test(page), "activity details omit content and placeholder data");
});

test("document choice loading distinguishes a failed request from a successful empty list", async () => {
  const state = await loadGatewayChoiceLists(
    async () => { throw new Error("gateway unavailable"); },
    async () => ({ items: [] }),
  );
  assert.deepEqual(state.systems, { status: "error", items: [] });
  assert.deepEqual(state.packs, { status: "empty", items: [] });
});

test("policy versions report failures, preserve true empty state, and order available versions newest first", async () => {
  const failed = await loadGatewayPolicyVersions(async () => { throw new Error("database unavailable"); }, "pack-a");
  assert.deepEqual(failed, { status: "error", items: [] });
  const empty = await loadGatewayPolicyVersions(async () => ({ items: [] }), "pack-a");
  assert.deepEqual(empty, { status: "empty", items: [] });
  const ready = await loadGatewayPolicyVersions(async () => ({ items: [
    { id: "older", created_at: "2026-01-01T00:00:00Z" },
    { id: "newer", created_at: "2026-02-01T00:00:00Z" },
  ] }), "pack-a");
  assert.equal(ready.status, "ready");
  assert.deepEqual(ready.items.map((version) => version.id), ["newer", "older"]);
});
