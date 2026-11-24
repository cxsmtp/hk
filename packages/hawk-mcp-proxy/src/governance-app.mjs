export const HAWK_GOVERNANCE_RESOURCE_URI = "ui://hawk/governance/status.html";
const GOVERNANCE_META_KEY = "ai.hawk/governance";

function plainRecord(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {};
}

function cleanString(value, maxLength = 256) {
  return typeof value === "string" ? value.trim().slice(0, maxLength) : "";
}

function cleanCount(value, maximum = 1_000_000_000) {
  if (value === null || value === undefined || value === "") return null;
  const parsed = Number(value);
  return Number.isInteger(parsed) && parsed >= 0 ? Math.min(parsed, maximum) : null;
}

function cleanTokenUsage(value) {
  const source = plainRecord(value);
  const total = cleanCount(source.total);
  return {
    total,
    provenance: total !== null && ["exact", "estimated"].includes(source.provenance)
      ? source.provenance
      : "unknown",
  };
}

function cleanMoney(value, maximum = 1_000_000_000) {
  if (value === null || value === undefined || value === "" || typeof value === "boolean") return null;
  const parsed = Number(value);
  return Number.isFinite(parsed) && parsed >= 0 && parsed <= maximum ? parsed : null;
}

function cleanCostUsage(value) {
  const source = plainRecord(value);
  const amount = cleanMoney(source.amount);
  const currency = /^[A-Z]{3}$/.test(String(source.currency || "").trim().toUpperCase())
    ? String(source.currency).trim().toUpperCase()
    : null;
  const namedSource = ["provider_billed", "provider_reported", "customer_rate_card", "calculated_estimate", "mixed"]
    .includes(source.source) ? source.source : "unknown";
  const provenance = amount !== null && currency !== null && ["exact", "estimated"].includes(source.provenance)
    ? source.provenance
    : "unknown";
  if (amount === null || currency === null || provenance === "unknown" || namedSource === "unknown") {
    return { amount: null, currency: null, provenance: "unknown", source: "unknown" };
  }
  return { amount, currency, provenance, source: namedSource };
}

export function governanceStatusForDecision(decision, {
  sessionId,
  serverId,
  clientApp,
  connected = true,
  availableToolCount,
  toolCallCount,
  tokenUsage,
  costUsage,
} = {}) {
  const source = plainRecord(decision);
  const controlMode = cleanString(source.control_mode, 64).toLowerCase();
  const inline = ["inline_authorized", "inline_allowed", "inline_prevented", "warned", "scoped"].includes(controlMode);
  const monitor = controlMode.startsWith("monitor_would_") || ["detected_only", "telemetry_only", "shadow_would_block"].includes(controlMode);
  const evidenceRef = cleanString(source.evidence_ref || source.evidence_bundle_id, 256) || null;
  const state = controlMode === "inline_prevented" && evidenceRef
    ? "blocked"
    : inline && evidenceRef
      ? "governed"
      : monitor && evidenceRef
        ? "monitor"
        : "unknown";
  return {
    schema_version: "1.0",
    state,
    label: state === "governed" ? "Governed" : state === "blocked" ? "Blocked" : state === "monitor" ? "Monitor" : "Unknown",
    decision: cleanString(source.decision || source.action, 64).toLowerCase() || "unknown",
    control_mode: controlMode || "unknown",
    connected: connected === true,
    client_app: cleanString(clientApp, 128) || null,
    session_id: cleanString(sessionId, 256) || null,
    server_id: cleanString(serverId, 256) || null,
    available_tool_count: cleanCount(availableToolCount, 100_000),
    tool_call_count: cleanCount(toolCallCount),
    evidence_ref: evidenceRef,
    policy_id: cleanString(source.policy_id || source.policy_version_id, 256) || null,
    token_usage: cleanTokenUsage(tokenUsage),
    cost_usage: cleanCostUsage(costUsage),
  };
}

export function governanceToolMetadata(tool) {
  const source = plainRecord(tool);
  const existingMeta = plainRecord(source._meta);
  return {
    ...source,
    _meta: {
      ...existingMeta,
      ui: { ...plainRecord(existingMeta.ui), resourceUri: HAWK_GOVERNANCE_RESOURCE_URI },
      "ui/resourceUri": HAWK_GOVERNANCE_RESOURCE_URI,
    },
  };
}

export function attachGovernanceMetadata(result, governance) {
  const source = plainRecord(result);
  const currentMeta = { ...plainRecord(source._meta) };
  delete currentMeta[GOVERNANCE_META_KEY];
  const trusted = plainRecord(governance);
  return {
    ...source,
    _meta: {
      ...currentMeta,
      [GOVERNANCE_META_KEY]: {
        schema_version: "1.0",
        state: cleanString(trusted.state, 64) || "unknown",
        label: cleanString(trusted.label, 64) || undefined,
        decision: cleanString(trusted.decision, 64) || "unknown",
        control_mode: cleanString(trusted.control_mode, 64) || "unknown",
        connected: trusted.connected === true,
        client_app: cleanString(trusted.client_app, 128) || null,
        session_id: cleanString(trusted.session_id, 256) || null,
        server_id: cleanString(trusted.server_id, 256) || null,
        available_tool_count: cleanCount(trusted.available_tool_count, 100_000),
        tool_call_count: cleanCount(trusted.tool_call_count),
        evidence_ref: cleanString(trusted.evidence_ref, 256) || null,
        policy_id: cleanString(trusted.policy_id, 256) || null,
        token_usage: cleanTokenUsage(trusted.token_usage),
        cost_usage: cleanCostUsage(trusted.cost_usage),
      },
    },
  };
}

export function governanceResource() {
  return {
    uri: HAWK_GOVERNANCE_RESOURCE_URI,
    name: "Hawk governed session status",
    mimeType: "text/html;profile=mcp-app",
    _meta: {
      ui: {
        csp: { connectDomains: [], resourceDomains: [] },
      },
    },
    text: `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<style>
:root{color-scheme:dark;font-family:ui-sans-serif,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:transparent;color:#f8fafc}.card{border:1px solid rgba(148,163,184,.18);border-radius:16px;background:#0c1016;overflow:hidden}.summary{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 16px}.brand{font-size:10px;font-weight:750;letter-spacing:.16em;text-transform:uppercase;color:#fb923c}.status{margin-top:5px;font-size:15px;font-weight:700}.meta{margin-top:4px;font-size:11px;color:#94a3b8}.badge{display:inline-flex;align-items:center;gap:7px;border:1px solid rgba(52,211,153,.28);border-radius:999px;background:rgba(52,211,153,.1);padding:7px 10px;font-size:11px;font-weight:700;color:#a7f3d0}.dot{width:7px;height:7px;border-radius:999px;background:#6ee7b7}.unknown{border-color:rgba(148,163,184,.24);background:rgba(148,163,184,.08);color:#cbd5e1}.unknown .dot{background:#94a3b8}.monitor{border-color:rgba(251,191,36,.28);background:rgba(251,191,36,.09);color:#fde68a}.monitor .dot{background:#fbbf24}.blocked{border-color:rgba(251,113,133,.32);background:rgba(251,113,133,.1);color:#fecdd3}.blocked .dot{background:#fb7185}.details{display:none;border-top:1px solid rgba(148,163,184,.14);padding:12px 16px 14px}.details.open{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px}.metric{border:1px solid rgba(148,163,184,.13);border-radius:10px;background:#111722;padding:9px}.metric b{display:block;font-size:10px;color:#94a3b8;text-transform:uppercase;letter-spacing:.08em}.metric span{display:block;margin-top:5px;font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.toggle{border:0;background:transparent;color:#94a3b8;font:inherit;font-size:11px;cursor:pointer;padding:3px 0}.foot{grid-column:1/-1;display:flex;justify-content:space-between;color:#94a3b8;font-size:10px}@media(max-width:520px){.details.open{grid-template-columns:repeat(2,minmax(0,1fr))}}
</style></head><body><div class="card"><div class="summary"><div><div class="brand">Hawk AI · Governed sessions</div><div id="status" class="status">Governance status pending</div><div id="meta" class="meta">Waiting for verified Hawk decision evidence</div><button id="toggle" class="toggle" type="button">View governance details</button></div><div id="badge" class="badge unknown"><span class="dot"></span><span id="label">Unknown</span></div></div><div id="details" class="details"><div class="metric"><b>Connection</b><span id="connection">Unknown</span></div><div class="metric"><b>Available tools</b><span id="tools">Unknown</span></div><div class="metric"><b>Tool calls</b><span id="calls">Unknown</span></div><div class="metric"><b>Tokens</b><span id="tokens">Unknown</span></div><div class="metric"><b>Spend</b><span id="spend">Cost not reported</span></div><div class="metric"><b>Policy</b><span id="policy">Unknown</span></div><div class="metric"><b>Evidence</b><span id="evidence">Unavailable</span></div><div class="foot"><span id="session">Session unavailable</span><span>Verified by Hawk</span></div></div></div>
<script>
const key="ai.hawk/governance",by=id=>document.getElementById(id),show=value=>value===null||value===undefined?"Unknown":String(value);function render(value){const data=value&&typeof value==="object"?value:{};const state=String(data.state||"unknown"),label=String(data.label||"Unknown"),badge=by("badge");badge.className="badge "+(state==="governed"?"":state==="blocked"?"blocked":state==="monitor"?"monitor":"unknown");by("label").textContent=label;by("status").textContent=(data.decision||"Unknown decision")+" · "+(data.control_mode||"mode unknown");by("meta").textContent=[data.client_app,data.server_id,data.evidence_ref?"evidence attached":"evidence unavailable"].filter(Boolean).join(" · ");by("connection").textContent=data.connected?"Connected":"Unknown";by("tools").textContent=show(data.available_tool_count);by("calls").textContent=show(data.tool_call_count);const usage=data.token_usage||{};by("tokens").textContent=usage.total===null||usage.total===undefined?"Unknown":usage.total+" · "+(usage.provenance||"unknown");const cost=data.cost_usage||{};by("spend").textContent=cost.amount===null||cost.amount===undefined||!cost.currency?"Cost not reported":cost.currency+" "+Number(cost.amount).toFixed(6)+" · "+(cost.provenance||"unknown")+" · "+String(cost.source||"unknown").replaceAll("_"," ");by("policy").textContent=data.policy_id||"Unknown";by("evidence").textContent=data.evidence_ref||"Unavailable";by("session").textContent=data.session_id?"Session "+data.session_id:"Session unavailable";}by("toggle").addEventListener("click",()=>{const open=by("details").classList.toggle("open");by("toggle").textContent=open?"Hide governance details":"View governance details";});window.addEventListener("message",event=>{const message=event.data||{};if(message.method==="ui/notifications/tool-result"){const result=message.params?.result||message.params||{};render(result._meta?.[key]);}});
</script></body></html>`,
  };
}

export function governanceResourceResult() {
  const resource = governanceResource();
  return { contents: [resource] };
}
