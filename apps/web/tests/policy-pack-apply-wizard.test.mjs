import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";
import { runInNewContext } from "node:vm";

const source = readFileSync(
  new URL("../src/components/lifecycle/policy-pack-platform-workspace.tsx", import.meta.url),
  "utf8",
);

test("Policy Packs presents the approved staged apply workflow", () => {
  assert.match(source, /const WIZARD_STEPS = \[/);
  assert.match(source, /const \[wizardStep, setWizardStep\] = useState\(0\)/);
  for (const label of ["Choose pack", "Map scope", "Configure & simulate", "Review & apply"]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /wizardStep === 0/);
  assert.match(source, /wizardStep === 1/);
  assert.match(source, /wizardStep === 2/);
  assert.match(source, /wizardStep === 3/);
  assert.match(source, /setWizardStep\(\(current\) => current \+ 1\)/);
  assert.match(source, /setWizardStep\(\(current\) => current - 1\)/);
});

test("Policy Packs keeps strong enforcement behind the existing transition gate", () => {
  assert.match(source, /Broad blocking moves require a passed simulation and a separate authorized approver\./);
  assert.doesNotMatch(source, /<option value="APPROVAL_ENFORCED">/);
  assert.doesNotMatch(source, /<option value="ENFORCED">/);
});

test("Policy Packs preserves the local-template disable control", () => {
  assert.doesNotMatch(source, /item \? current\.filter/);
});

test("Policy Packs exposes a Governance Atlas wired into preview, simulation and apply", () => {
  for (const label of [
    "Governance Atlas",
    "RBI FREE-AI",
    "MeitY AI Guidelines",
    "DPDP",
    "SEBI AI/ML",
    "IMDA Agentic AI",
    "EU AI Act",
    "OWASP GenAI",
    "MITRE ATLAS",
    "mapped controls",
    "Framework-driven control coverage",
    "Framework-driven simulations",
    "Framework-driven evidence requirements",
  ]) {
    assert.match(source, new RegExp(label));
  }
  assert.match(source, /listPolicyPackPlatformFrameworkAtlas/);
  assert.match(source, /selectFrameworkPack/);
  assert.match(source, /Preview and apply/);
  assert.match(source, /not certified compliant/);
  assert.match(source, /simulation_links/);
  assert.match(source, /control_coverage/);
  assert.match(source, /evidence_requirements/);
});

test("Policy Pack counts distinguish loaded empty from failed requests and generic 401/404 errors", () => {
  const functionSource = (name) => {
    const start = source.indexOf(`function ${name}(`);
    assert.notEqual(start, -1);
    const end = source.indexOf("\n}\n", start);
    assert.notEqual(end, -1);
    return source.slice(start, end + 2);
  };
  const javascript = ts.transpileModule([functionSource("message"), functionSource("rolloutNotEnabled"), functionSource("displayCount"), "({ rolloutNotEnabled, displayCount })"].join("\n"), { compilerOptions: { target: ts.ScriptTarget.ES2022 } }).outputText;
  const { rolloutNotEnabled, displayCount } = runInNewContext(javascript, { Error });
  assert.equal(displayCount("loaded", 0), 0);
  assert.equal(displayCount("error", 0), "Unavailable");
  assert.equal(displayCount("loading", 0), "…");
  assert.equal(rolloutNotEnabled(new Error("HTTP 401 Unauthorized")), false);
  assert.equal(rolloutNotEnabled(new Error("HTTP 404 Not found")), false);
  assert.equal(rolloutNotEnabled(new Error("tenant_rollout_not_enabled")), true);
  assert.match(source, /Promise\.allSettled\(\[/);
  assert.match(source, /setUnavailable\(\[catalogResult, instanceResult, frameworkResult\]\.every\(\(result\) => result\.status === "rejected" && rolloutNotEnabled\(result\.reason\)\)\)/);
  assert.match(source, /coverageState === "error" \? <p[^>]*>Capability preview unavailable/);
  assert.match(source, /catalogState === "error" \? "Unavailable" : displayCount\(coverageState, coverage\?\.verified_pre_execution_block_surfaces\.length \?\? 0\)/);
  assert.match(source, /emptyLabel=\{catalogState === "error" \|\| coverageState === "error" \? "Unavailable: capability preview could not be loaded\."/);
  assert.match(source, /emptyLabel=\{instanceState === "error" \? "Unavailable: customer instances could not be loaded\."/);
});
