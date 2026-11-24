import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const source = readFileSync(
  new URL("../src/app/dashboard/command-center/page.tsx", import.meta.url),
  "utf8",
);

const defaultBranchStart = source.indexOf(
  'if (process.env.NEXT_PUBLIC_LEGACY_COMMAND_CENTER !== "true")',
);
const legacyBranchStart = source.indexOf("\n  return (", defaultBranchStart);
const defaultBranch = source.slice(defaultBranchStart, legacyBranchStart);
const topbarSource = readFileSync(
  new URL("../src/components/topbar.tsx", import.meta.url),
  "utf8",
);
const activityMapSource = readFileSync(
  new URL("../src/app/runtime-intelligence/activity-map/page.tsx", import.meta.url),
  "utf8",
);
const interactionSecuritySource = readFileSync(
  new URL("../src/app/interaction-security/page.tsx", import.meta.url),
  "utf8",
);
const validationCoverageSource = readFileSync(
  new URL("../src/app/validation/coverage/page.tsx", import.meta.url),
  "utf8",
);

function componentSource(name) {
  const start = source.indexOf(`function ${name}`);
  const end = source.indexOf("\nfunction ", start + 1);
  assert.ok(start >= 0, `${name} is missing`);
  return source.slice(start, end >= 0 ? end : source.length);
}

test("default Command Center preserves the full one-page operational context", () => {
  assert.ok(defaultBranchStart >= 0, "default Command Center branch is missing");

  for (const requiredSection of [
    "TopActionsNow",
    "AIActionControlCard",
    "FourSurfaceMatrix",
    "Risk and policy breakdown",
    "Identity and authority",
    "Highest-risk action chain",
    "Microsoft AI surfaces",
    "Agentic browser control",
    "Intent-aware control",
    "Findings alerts",
    "Violations requiring action",
    "AIExposureScanCard",
  ]) {
    assert.match(defaultBranch, new RegExp(requiredSection), `${requiredSection} is not visible in the default one-page view`);
  }
});

test("default Command Center keeps filters accessible through progressive disclosure and excludes unverified executive metrics", () => {
  assert.match(defaultBranch, /<details[\s\S]*?Scope & filters/);
  assert.match(defaultBranch, /<details[\s\S]*?Detailed operating view/);
  assert.doesNotMatch(defaultBranch, /CrqImpactCard/);
  assert.doesNotMatch(defaultBranch, /ExposureGauge/);
  assert.doesNotMatch(defaultBranch, /ExternalRiskIntelCard/);
});

test("priority activity leads while live scope and controls remain accessible", () => {
  const scopeIndex = defaultBranch.indexOf('title="Visible scope"');
  const actionsIndex = defaultBranch.indexOf("<TopActionsNow");
  const controlIndex = defaultBranch.indexOf("<AIActionControlCard");
  const surfacesIndex = defaultBranch.indexOf("<FourSurfaceMatrix");

  assert.ok(defaultBranch.indexOf("<OperationsConsoleTabs") < scopeIndex, "live status must precede visible scope");
  assert.ok(defaultBranch.indexOf("<PageHeader") < scopeIndex, "updated status must precede visible scope");
  assert.ok(actionsIndex >= 0 && actionsIndex < scopeIndex, "top actions must precede optional visible scope");
  assert.ok(actionsIndex < controlIndex && controlIndex < surfacesIndex, "prioritized sections are out of order");

  const scopeSource = defaultBranch.slice(scopeIndex);
  for (const filterTitle of [
    "Filter by time window",
    "Filter by AI system",
    "Filter by severity",
    "Filter by intent category",
    "Filter by input sensitivity",
    "Filter by output sensitivity",
    "Filter by action alignment",
  ]) {
    assert.match(scopeSource, new RegExp(`title="${filterTitle}"`), `${filterTitle} is not visibly rendered`);
  }
});

test("default Command Center mounts the four evidence-backed operational modules with live state", () => {
  for (const usage of [
    /<MCPGatewayVisibility\s+summary=\{data\?\.mcp_tool_calls\}/,
    /<InteractionSecurityMatrix[\s\S]*?users=\{data\?\.users_view\?\.items \|\| \[\]\}[\s\S]*?activity=\{data\?\.live_activity_feed\?\.items \|\| \[\]\}/,
    /<AIIAMPosture[\s\S]*?identity=\{data\?\.identity_risk\}[\s\S]*?agents=\{data\?\.agents_view\}/,
    /<ControlValidationPanel[\s\S]*?simulations=\{data\?\.simulations\}[\s\S]*?coverage=\{data\?\.control_coverage\}/,
  ]) {
    assert.match(defaultBranch, usage);
  }
});

test("evidence-backed operational modules use their required visible titles", () => {
  for (const [component, title] of [
    ["MCPGatewayVisibility", "MCP Gateway visibility"],
    ["InteractionSecurityMatrix", "Interaction Security by user, app, and surface"],
    ["AIIAMPosture", "AI IAM"],
    ["ControlValidationPanel", "Simulation / Control Validation"],
  ]) {
    assert.match(source, new RegExp(`function ${component}\\b[\\s\\S]*?title="${title}"`));
  }
});

test("MCP metrics and drilldown describe observed outcomes without claiming inline proof", () => {
  const mcp = componentSource("MCPGatewayVisibility");
  assert.match(mcp, /Observed call events/);
  assert.match(mcp, /Blocked decisions/);
  assert.match(mcp, /observed policy outcome/i);
  assert.match(mcp, /not inline prevention/i);
  assert.match(mcp, /activity-map\?surface=mcp_tool_call/);
  assert.doesNotMatch(mcp, /Gateway blocked|Calls today/);
});

test("interaction outcomes evidence-gate prevention and reconcile every action", () => {
  const interaction = componentSource("InteractionSecurityMatrix");
  assert.match(interaction, /item\.decision_explanation\?\.evidence/);
  for (const evidenceField of ["evidence_refs", "evidence_bundle_id", "trace_id", "event_hash", "finding_id"]) {
    assert.match(interaction, new RegExp(evidenceField));
  }
  assert.match(interaction, /const other = observed\.length - prevented - review/);
  assert.match(interaction, /row\.other/);
});

test("AI IAM correlates chain authority and unexecuted controls stay posture-only", () => {
  const iam = componentSource("AIIAMPosture");
  const validation = componentSource("ControlValidationPanel");
  assert.match(iam, /identity\?\.top_agents\.find/);
  assert.match(iam, /max_chain_depth/);
  assert.match(validation, /hasExecutedRuns \? control\.status : "Posture only"/);
  assert.match(validation, /columns=\{\["Lowest control", "Maturity", "Technical", "Coverage", "Status", "Open"\]\}/);
  assert.match(validation, /href="\/validation\/coverage"/);
});

test("lowest controls deep-link to a destination that selects the requested control", () => {
  const validation = componentSource("ControlValidationPanel");
  assert.match(validation, /href=\{`\/validation\/coverage\?control_id=\$\{encodeURIComponent\(control\.control_id\)\}`\}/);

  assert.match(validationCoverageSource, /useSearchParams/);
  assert.match(validationCoverageSource, /searchParams\.get\("control_id"\)/);
  assert.match(validationCoverageSource, /controls\.find\(\(control\) => control\.id === requestedControlId\)/);
  assert.match(validationCoverageSource, /setSelectedControl/);
  assert.match(validationCoverageSource, /controls\[0\]\?\.id \|\| ""/);
});

test("invalid control deep links deterministically fall back to the first control", () => {
  assert.match(validationCoverageSource, /if \(requestedControlId\) return requestedControl\?\.id \|\| controls\[0\]\?\.id \|\| ""/);
});

test("interaction matrix distinguishes loading, unavailable, and successful empty states", () => {
  const interaction = componentSource("InteractionSecurityMatrix");
  assert.match(interaction, /loading: boolean/);
  assert.match(interaction, /unavailable: boolean/);
  assert.match(interaction, /Loading interaction security data/);
  assert.match(interaction, /Interaction security data is unavailable; current user activity cannot be verified/);
  assert.match(interaction, /No user records are available to correlate with the current activity feed/);
  assert.match(defaultBranch, /<InteractionSecurityMatrix[\s\S]*?loading=\{loading\}[\s\S]*?unavailable=\{Boolean\(dashboardLoadError\) \|\| \(!loading && !data\)\}/);
});

test("default risk trend tone comes from observed risk rather than synthetic exposure", () => {
  assert.doesNotMatch(defaultBranch, /tone=\{toneFromExposure\(exposureScore\)\}/);
  assert.match(defaultBranch, /tone=\{observedRiskTone\}/);
  assert.match(source, /const observedRiskPeak[\s\S]*?riskTrendPoints[\s\S]*?const observedRiskTone = toneFromExposure\(observedRiskPeak\)/);
});

test("scoped dashboard links are consumed by their destination pages", () => {
  assert.match(activityMapSource, /useSearchParams/);
  assert.match(activityMapSource, /searchParams\.get\("surface"\)/);
  assert.match(activityMapSource, /normalized === "mcp_tool_call"[\s\S]*?sourceSurface\.includes\("mcp"\)[\s\S]*?eventType\.includes\("mcp_tool_call"\)/);
  assert.match(activityMapSource, /\(eventPayload\.items \|\| \[\]\)\.filter\(\(event\) => matchesSurfaceFilter\(event, surfaceFilter\)\)/);

  assert.match(interactionSecuritySource, /useSearchParams/);
  assert.match(interactionSecuritySource, /searchParams\.get\("user_id"\)/);
  assert.match(interactionSecuritySource, /setActorSearch\(requestedUserId\)/);
});

test("search-param pages place useSearchParams beneath Suspense boundaries", () => {
  for (const [pageSource, contentName, pageName] of [
    [activityMapSource, "RuntimeIntelligenceActivityMapContent", "RuntimeIntelligenceActivityMapPage"],
    [interactionSecuritySource, "InteractionSecurityContent", "InteractionSecurityPage"],
    [validationCoverageSource, "ValidationCoverageContent", "ValidationCoveragePage"],
  ]) {
    assert.match(pageSource, /import \{[^}]*Suspense[^}]*\} from "react"/);
    assert.match(pageSource, new RegExp(`function ${contentName}\\(`));
    assert.match(pageSource, new RegExp(`export default function ${pageName}\\(`));
    assert.match(pageSource, new RegExp(`<Suspense[\\s\\S]*?<${contentName} \\/>`));
  }
});

test("MCP surface filtering includes canonical event metadata", () => {
  assert.match(activityMapSource, /event\.metadata\?\.ai_surface/);
  assert.match(activityMapSource, /event\.metadata\?\.action_type/);
  assert.match(activityMapSource, /event\.metadata\?\.operation/);
  assert.match(activityMapSource, /canonicalFields\.some\(\(value\) => value\.includes\("mcp"\)\)/);
});

test("interaction user deep links use exact actor identity matching", () => {
  assert.match(interactionSecuritySource, /const requestedActorId = requestedUserId\.toLowerCase\(\)/);
  assert.match(interactionSecuritySource, /if \(requestedActorId\)[\s\S]*?String\(item\.actor_type \|\| ""\)\.trim\(\)\.toLowerCase\(\) !== "human"/);
  assert.match(interactionSecuritySource, /if \(requestedActorId\)[\s\S]*?String\(item\.actor_id \|\| ""\)\.trim\(\)\.toLowerCase\(\) !== requestedActorId/);
  assert.match(interactionSecuritySource, /else if \(actorSearch\)/);
});

test("interaction filter controls release URL-derived user constraints", () => {
  assert.match(interactionSecuritySource, /import \{[^}]*useRouter[^}]*\} from "next\/navigation"/);
  assert.match(interactionSecuritySource, /const router = useRouter\(\)/);
  assert.match(interactionSecuritySource, /new URLSearchParams\(searchParams\.toString\(\)\)/);
  assert.match(interactionSecuritySource, /\.delete\("user_id"\)/);
  assert.match(interactionSecuritySource, /router\.replace\(/);
  assert.match(interactionSecuritySource, /function updateActorSearch\([\s\S]*?clearRequestedUserConstraint\(\)[\s\S]*?setActorSearch\(value\)/);
  assert.match(interactionSecuritySource, /function clearFilters\([\s\S]*?clearRequestedUserConstraint\(\)[\s\S]*?setActorSearch\(""\)/);
  assert.match(interactionSecuritySource, /onChange=\{updateActorSearch\}/);
  assert.match(interactionSecuritySource, /onClick=\{clearFilters\}/);
  assert.match(interactionSecuritySource, /if \(requestedUserId\) setActorSearch\(requestedUserId\)/);
});

test("Command Center coalesces in-flight refreshes and generation-gates state writes", () => {
  assert.match(source, /loadRequestGenerationRef/);
  assert.match(source, /queuedLoadRef/);
  assert.match(source, /while \(queuedLoadRef\.current\)/);
  assert.match(source, /request\.generation === loadRequestGenerationRef\.current/);
  assert.match(source, /resolvers/);
  assert.doesNotMatch(source, /if \(!forceRefresh\) return loadInFlightRef\.current/);
});

test("Command Center restarts queue draining after releasing in-flight ownership", () => {
  assert.match(
    source,
    /const drainLoadQueue = useCallback\(async \(\) => \{[\s\S]*?while \(true\) \{[\s\S]*?loadInFlightRef\.current = null;[\s\S]{0,180}if \(!queuedLoadRef\.current\) return;/,
  );
});

test("Command Center health polling remains single-shot per interval", () => {
  assert.doesNotMatch(source, /setInterval\(\(\) => \{\s*loadPilotHealth\(\)\.catch\(\(\) => undefined\);\s*loadPilotHealth\(\)\.catch/);
});

test("shared top bar stacks safely on narrow screens", () => {
  assert.match(topbarSource, /flex flex-col items-stretch gap-3[^"]*sm:flex-row/);
  assert.match(topbarSource, /max-w-\[9rem\][^"]*truncate[^"]*sm:max-w-none/);
  assert.match(topbarSource, /hidden[^"]*lg:inline/);
});
