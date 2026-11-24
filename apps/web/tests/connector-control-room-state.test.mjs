import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

async function loadStateModule() {
  const source = readFileSync(
    new URL("../src/lib/connector-control-room-state.ts", import.meta.url),
    "utf8",
  );
  const result = ts.transpileModule(source, {
    compilerOptions: {
      module: ts.ModuleKind.ESNext,
      target: ts.ScriptTarget.ES2022,
    },
    reportDiagnostics: true,
  });
  const errors = (result.diagnostics || []).filter(
    (diagnostic) => diagnostic.category === ts.DiagnosticCategory.Error,
  );
  assert.deepEqual(errors, []);
  const encoded = Buffer.from(result.outputText).toString("base64");
  return import(`data:text/javascript;base64,${encoded}`);
}

test("browser presentation grants inline status only to explicit inline modes", async () => {
  const { deriveGmailBrowserPresentation } = await loadStateModule();

  assert.deepEqual(deriveGmailBrowserPresentation(null), {
    mode: "Unknown",
    isInline: false,
    isBlocked: false,
    isTelemetryOnly: false,
  });
  assert.deepEqual(deriveGmailBrowserPresentation("incomplete"), {
    mode: "Unknown",
    isInline: false,
    isBlocked: false,
    isTelemetryOnly: false,
  });

  for (const mode of ["telemetry_only", "detected_only", "review_required", "warned"]) {
    assert.deepEqual(deriveGmailBrowserPresentation(mode), {
      mode: "Telemetry-only",
      isInline: false,
      isBlocked: false,
      isTelemetryOnly: true,
    });
  }

  assert.deepEqual(deriveGmailBrowserPresentation("inline_prevented"), {
    mode: "Inline when Chrome-routed",
    isInline: true,
    isBlocked: true,
    isTelemetryOnly: false,
  });
  assert.deepEqual(deriveGmailBrowserPresentation("inline_allowed"), {
    mode: "Inline when Chrome-routed",
    isInline: true,
    isBlocked: false,
    isTelemetryOnly: false,
  });
});

test("selected evaluation and evidence links require exact persisted proof", async () => {
  const { canLinkVerifiedEvidence, selectMatchingEvaluation } = await loadStateModule();
  const evaluation = { connector: { id: "connector-a" }, marker: "proof-a" };

  assert.equal(selectMatchingEvaluation("connector-a", evaluation), evaluation);
  assert.equal(selectMatchingEvaluation("connector-b", evaluation), null);
  assert.equal(selectMatchingEvaluation("connector-a", null), null);

  assert.equal(canLinkVerifiedEvidence("evidence-1", "valid"), true);
  assert.equal(canLinkVerifiedEvidence("evidence-1", "unknown"), false);
  assert.equal(canLinkVerifiedEvidence("evidence-1", "invalid"), false);
  assert.equal(canLinkVerifiedEvidence(null, "valid"), false);
  assert.equal(canLinkVerifiedEvidence("", "valid"), false);
});

test("stale connector operations cannot install results under a new selection", async () => {
  const { shouldApplyConnectorOperation } = await loadStateModule();
  const current = {
    operationId: 4,
    currentOperationId: 4,
    requestedConnectorId: "connector-a",
    selectedConnectorId: "connector-a",
    responseConnectorId: "connector-a",
  };

  assert.equal(shouldApplyConnectorOperation(current), true);
  assert.equal(shouldApplyConnectorOperation({ ...current, currentOperationId: 5 }), false);
  assert.equal(shouldApplyConnectorOperation({ ...current, selectedConnectorId: "connector-b" }), false);
  assert.equal(shouldApplyConnectorOperation({ ...current, responseConnectorId: "connector-b" }), false);
});
