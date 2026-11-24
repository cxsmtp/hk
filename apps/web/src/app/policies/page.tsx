"use client";

import Link from "next/link";
import { FormEvent, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";

import { AppShell } from "@/components/app-shell";
import { KpiStrip } from "@/components/kpi-strip";
import { ModuleReportPanel } from "@/components/module-report-panel";
import { PolicyPackPlatformWorkspace } from "@/components/lifecycle/policy-pack-platform-workspace";
import { PageSection } from "@/components/page-section";
import { PageHeader } from "@/components/page-header";
import { RowActions } from "@/components/row-actions";
import { SimpleTable } from "@/components/simple-table";
import { FilterInput, FilterLabel, FilterSelect, TableFilters } from "@/components/table-filters";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getSession } from "@/lib/auth";
import { api } from "@/lib/api";
import type { PolicyPack, PolicyScopedRule, PolicyVersion, RunningPolicyStatus } from "@/lib/types";

type GuardianContract = Record<string, unknown>;

type TunePayload = {
  blockedKeywords: string[];
  highRiskTerms: string[];
  sensitivePatterns: string[];
};

type ScopedRuleDecision =
  | "allow"
  | "warn"
  | "block"
  | "redact"
  | "require_approval"
  | "require_justification"
  | "hold_for_approval";

type ScopedRuleForm = {
  rule_id: string;
  enabled: boolean;
  priority: number;
  description: string;
  decision: ScopedRuleDecision;
  reason_code: string;
  explanation: string;
  recommended_action: string;
  user_ids: string;
  roles: string;
  departments: string;
  actor_types: string;
  agent_ids: string;
  endpoint_ids: string;
  source_surfaces: string;
  ai_system_ids: string;
  domains: string;
  tools: string;
  providers: string;
  models: string;
  action_types: string;
  action_operations: string;
  data_classifications: string;
  risk_tiers: string;
  contains_sensitive: "any" | "true" | "false";
  metadata_json: string;
};

const SCOPED_RULE_DECISIONS: ScopedRuleDecision[] = [
  "allow",
  "warn",
  "block",
  "redact",
  "require_approval",
  "require_justification",
  "hold_for_approval",
];

function parseCsv(input: string): string[] {
  return Array.from(
    new Set(
      input
        .split(",")
        .map((item) => item.trim())
        .filter(Boolean)
    )
  );
}

function parseCsvLower(input: string): string[] {
  return parseCsv(input).map((item) => item.toLowerCase());
}

function csvFrom(values?: string[]): string {
  if (!Array.isArray(values)) return "";
  return values.join(", ");
}

function metadataJsonFrom(value: unknown): string {
  if (!value || typeof value !== "object" || Array.isArray(value)) return "{}";
  try {
    return JSON.stringify(value);
  } catch {
    return "{}";
  }
}

function defaultScopedRuleForm(index: number): ScopedRuleForm {
  return {
    rule_id: `scoped_rule_${index}`,
    enabled: true,
    priority: 100,
    description: "",
    decision: "warn",
    reason_code: "",
    explanation: "",
    recommended_action: "",
    user_ids: "",
    roles: "",
    departments: "",
    actor_types: "",
    agent_ids: "",
    endpoint_ids: "",
    source_surfaces: "",
    ai_system_ids: "",
    domains: "",
    tools: "",
    providers: "",
    models: "",
    action_types: "",
    action_operations: "",
    data_classifications: "",
    risk_tiers: "",
    contains_sensitive: "any",
    metadata_json: "{}",
  };
}

function toScopedRuleForm(rule: PolicyScopedRule, index: number): ScopedRuleForm {
  return {
    rule_id: rule.rule_id || `scoped_rule_${index + 1}`,
    enabled: rule.enabled !== false,
    priority: Number(rule.priority ?? rule.effect?.priority ?? 100) || 100,
    description: rule.description || "",
    decision: (rule.effect?.decision as ScopedRuleDecision) || "allow",
    reason_code: rule.effect?.reason_code || "",
    explanation: rule.effect?.explanation || "",
    recommended_action: rule.effect?.recommended_action || "",
    user_ids: csvFrom(rule.subjects?.user_ids),
    roles: csvFrom(rule.subjects?.roles),
    departments: csvFrom(rule.subjects?.departments),
    actor_types: csvFrom(rule.subjects?.actor_types),
    agent_ids: csvFrom(rule.subjects?.agent_ids),
    endpoint_ids: csvFrom(rule.subjects?.endpoint_ids),
    source_surfaces: csvFrom(rule.subjects?.source_surfaces),
    ai_system_ids: csvFrom(rule.resources?.ai_system_ids),
    domains: csvFrom(rule.resources?.domains),
    tools: csvFrom(rule.resources?.tools),
    providers: csvFrom(rule.resources?.providers),
    models: csvFrom(rule.resources?.models),
    action_types: csvFrom(rule.actions?.types),
    action_operations: csvFrom(rule.actions?.operations),
    data_classifications: csvFrom(rule.conditions?.data_classifications),
    risk_tiers: csvFrom(rule.conditions?.risk_tiers),
    contains_sensitive:
      rule.conditions?.contains_sensitive === true
        ? "true"
        : rule.conditions?.contains_sensitive === false
          ? "false"
          : "any",
    metadata_json: metadataJsonFrom(rule.metadata),
  };
}

function recordOf(value: unknown): Record<string, unknown> {
  if (!value || typeof value !== "object" || Array.isArray(value)) return {};
  return { ...(value as Record<string, unknown>) };
}

function ensureGuardian(contracts: GuardianContract[], guardianId: string, description: string): GuardianContract {
  const existing = contracts.find((item) => String(item.guardian_id || "") === guardianId);
  if (existing) return existing;

  const created: GuardianContract = {
    guardian_id: guardianId,
    description,
    enabled: true,
    trigger: {
      signal_types: ["prompt.text"],
      conditions: [],
    },
    evaluation: { method: "rules", confidence_threshold: 0.7 },
    decision: { on_pass: "allow", on_fail: "block", on_uncertain: "warn" },
    actions: {},
    evidence: { link_to_controls: [] },
    control_impact: { enforcement_strictness_increase: 1 },
  };
  contracts.push(created);
  return created;
}

function upsertCondition(
  guardian: GuardianContract,
  condition: { field: string; operator: "contains" | "regex"; value: string; case_sensitive?: boolean }
): void {
  const trigger = recordOf(guardian.trigger);
  const existingConditions = Array.isArray(trigger.conditions) ? [...trigger.conditions] : [];
  const key = `${condition.field}:${condition.operator}:${condition.value.toLowerCase()}`;

  const seenKeys = new Set(
    existingConditions
      .filter((item): item is Record<string, unknown> => !!item && typeof item === "object" && !Array.isArray(item))
      .map((item) => {
        const field = String(item.field || "");
        const operator = String(item.operator || "");
        const value = String(item.value || "").toLowerCase();
        return `${field}:${operator}:${value}`;
      })
  );

  if (!seenKeys.has(key)) {
    existingConditions.push({
      field: condition.field,
      operator: condition.operator,
      value: condition.value,
      case_sensitive: Boolean(condition.case_sensitive),
    });
  }

  const signalTypes = Array.isArray(trigger.signal_types)
    ? Array.from(
        new Set(
          trigger.signal_types
            .map((item) => String(item || "").trim())
            .filter(Boolean)
            .concat("prompt.text")
        )
      )
    : ["prompt.text"];

  trigger.conditions = existingConditions;
  trigger.signal_types = signalTypes;
  guardian.trigger = trigger;
}

function applyGuardianTuning(baseContracts: GuardianContract[], tune: TunePayload): GuardianContract[] {
  const contracts = baseContracts.map((contract) => ({ ...contract }));

  const promptInjection = ensureGuardian(contracts, "prompt_injection", "Tenant-tuned prompt injection guardrail.");
  const jailbreak = ensureGuardian(contracts, "jailbreak", "Tenant-tuned jailbreak guardrail.");
  const sensitiveLeakage = ensureGuardian(contracts, "sensitive_data_leakage", "Tenant-tuned sensitive data guardrail.");

  for (const keyword of tune.blockedKeywords) {
    upsertCondition(promptInjection, {
      field: "prompt.text",
      operator: "contains",
      value: keyword,
      case_sensitive: false,
    });
  }

  for (const term of tune.highRiskTerms) {
    upsertCondition(jailbreak, {
      field: "prompt.text",
      operator: "contains",
      value: term,
      case_sensitive: false,
    });
  }

  for (const pattern of tune.sensitivePatterns) {
    upsertCondition(sensitiveLeakage, {
      field: "prompt.text",
      operator: "regex",
      value: pattern,
      case_sensitive: false,
    });
  }

  return contracts;
}

function sortVersionsByCreatedAt(versions: PolicyVersion[]): PolicyVersion[] {
  return [...versions].sort((a, b) => {
    const aTs = new Date(a.created_at || 0).getTime();
    const bTs = new Date(b.created_at || 0).getTime();
    return bTs - aTs;
  });
}

function revealPolicyHashTarget(): void {
  if (typeof window === "undefined" || !window.location.hash) return;
  const target = document.getElementById(window.location.hash.slice(1));
  if (!target) return;
  let ancestor: HTMLElement | null = target;
  while (ancestor) {
    if (ancestor instanceof HTMLDetailsElement) ancestor.open = true;
    ancestor = ancestor.parentElement;
  }
  window.requestAnimationFrame(() => target.scrollIntoView({ block: "start" }));
}

export default function PoliciesPage() {
  const [packs, setPacks] = useState<PolicyPack[]>([]);
  const [running, setRunning] = useState<RunningPolicyStatus | null>(null);
  const [name, setName] = useState("Enterprise Runtime Pack");
  const [statusFilter, setStatusFilter] = useState("");
  const [search, setSearch] = useState("");

  const [targetPackId, setTargetPackId] = useState("");
  const [newVersion, setNewVersion] = useState("");
  const [defaultDecision, setDefaultDecision] = useState("block");
  const [escalation, setEscalation] = useState("approval");
  const [blockedKeywordsInput, setBlockedKeywordsInput] = useState("ignore previous instructions,jailbreak");
  const [highRiskTermsInput, setHighRiskTermsInput] = useState("bypass policy,override policy");
  const [sensitivePatternsInput, setSensitivePatternsInput] = useState("(?i)emirates\\s*id,(?i)api\\s*key,(?i)credit\\s*card");
  const [publishing, setPublishing] = useState(false);
  const [seedingPilotPack, setSeedingPilotPack] = useState(false);
  const [scopedPackId, setScopedPackId] = useState("");
  const [scopedVersionId, setScopedVersionId] = useState("");
  const [scopedVersions, setScopedVersions] = useState<PolicyVersion[]>([]);
  const [scopedRules, setScopedRules] = useState<ScopedRuleForm[]>([]);
  const [loadingScopedRules, setLoadingScopedRules] = useState(false);
  const [savingScopedRules, setSavingScopedRules] = useState(false);
  const [canAdministerMasking, setCanAdministerMasking] = useState(false);
  const [maskingConfigPackId, setMaskingConfigPackId] = useState("");
  const [reversibleMaskingEnabled, setReversibleMaskingEnabled] = useState(false);
  const [mappingTtlSeconds, setMappingTtlSeconds] = useState("120");
  const [documentsEnabled, setDocumentsEnabled] = useState(true);
  const [maxDocumentMiB, setMaxDocumentMiB] = useState("10");
  const [maxDocumentPages, setMaxDocumentPages] = useState("100");
  const [packsState, setPacksState] = useState<"loading" | "loaded" | "error">("loading");
  const [runningState, setRunningState] = useState<"loading" | "loaded" | "error">("loading");

  useEffect(() => {
    const role = String(getSession()?.userRole || "").toLowerCase();
    setCanAdministerMasking(["admin", "owner", "super", "super_admin"].includes(role));
  }, []);

  useEffect(() => {
    revealPolicyHashTarget();
    window.addEventListener("hashchange", revealPolicyHashTarget);
    return () => window.removeEventListener("hashchange", revealPolicyHashTarget);
  }, []);

  async function load() {
    setPacksState("loading");
    setRunningState("loading");
    const [packsResult, runningResult] = await Promise.allSettled([api.listPolicyPacks(), api.runningPolicyStatus()]);
    const runningPayload = runningResult.status === "fulfilled" ? runningResult.value : null;
    setRunningState(runningResult.status === "fulfilled" ? "loaded" : "error");
    if (runningPayload) setRunning(runningPayload);
    if (packsResult.status === "rejected") {
      setPacksState("error");
      setPacks([]);
      throw packsResult.reason;
    }
    setPacksState("loaded");
    const packsPayload = packsResult.value;

    const nextPacks = packsPayload.items || [];
    setPacks(nextPacks);
    if (runningPayload) setRunning(runningPayload);

    if (!targetPackId) {
      const preferred =
        nextPacks.find((item) => String(item.status || "").toLowerCase() === "active")?.id ||
        nextPacks[0]?.id ||
        "";
      setTargetPackId(preferred);
    }

    if (!scopedPackId) {
      const preferred =
        nextPacks.find((item) => String(item.status || "").toLowerCase() === "active")?.id ||
        nextPacks[0]?.id ||
        "";
      setScopedPackId(preferred);
    }
  }

  useEffect(() => {
    load().catch(() => {
      setPacks([]);
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  useEffect(() => {
    if (!newVersion) {
      setNewVersion(`tuned-${new Date().toISOString().slice(0, 19).replace(/[T:]/g, "-")}`);
    }
  }, [newVersion]);

  useEffect(() => {
    if (!scopedPackId) {
      setScopedVersions([]);
      setScopedVersionId("");
      setScopedRules([]);
      return;
    }

    api
      .listPolicyVersions(scopedPackId)
      .then((payload) => {
        const sorted = sortVersionsByCreatedAt(payload.items || []);
        setScopedVersions(sorted);
        setScopedVersionId(
          (current) => sorted.find((item) => item.id === current)?.id || sorted[0]?.id || "",
        );
      })
      .catch(() => {
        setScopedVersions([]);
        setScopedVersionId("");
        setScopedRules([]);
      });
  }, [scopedPackId]);

  useEffect(() => {
    if (!targetPackId) return;
    let cancelled = false;
    setMaskingConfigPackId("");
    api.listPolicyVersions(targetPackId).then((payload) => {
      if (cancelled) return;
      const base = sortVersionsByCreatedAt(payload.items || [])[0];
      const gateway = recordOf(recordOf(base?.scope).llm_gateway_security);
      const masking = recordOf(gateway.reversible_masking);
      setReversibleMaskingEnabled(masking.enabled === true);
      setMappingTtlSeconds(String(Math.min(300, Math.max(30, Number(masking.mapping_ttl_seconds) || 120))));
      setDocumentsEnabled(masking.documents_enabled !== false);
      setMaxDocumentMiB(String(Math.min(10, Math.max(1, Math.ceil((Number(masking.max_document_bytes) || 10485760) / 1048576)))));
      setMaxDocumentPages(String(Math.min(100, Math.max(1, Number(masking.max_document_pages) || 100))));
      setMaskingConfigPackId(targetPackId);
    }).catch(() => {
      if (cancelled) return;
      setReversibleMaskingEnabled(false);
      setMappingTtlSeconds("120");
      setDocumentsEnabled(true);
      setMaxDocumentMiB("10");
      setMaxDocumentPages("100");
      setMaskingConfigPackId(targetPackId);
    });
    return () => { cancelled = true; };
  }, [targetPackId]);

  useEffect(() => {
    if (!scopedVersionId) {
      setScopedRules([]);
      return;
    }

    setLoadingScopedRules(true);
    api
      .getPolicyVersionScopedRules(scopedVersionId)
      .then((payload) => {
        const forms = (payload.scoped_rules || []).map((rule, index) => toScopedRuleForm(rule, index));
        setScopedRules(forms);
      })
      .catch((err) => {
        setScopedRules([]);
        toast.error(err instanceof Error ? err.message : "Failed to load scoped rules");
      })
      .finally(() => setLoadingScopedRules(false));
  }, [scopedVersionId]);

  function updateScopedRule(index: number, patch: Partial<ScopedRuleForm>) {
    setScopedRules((current) => current.map((item, idx) => (idx === index ? { ...item, ...patch } : item)));
  }

  function addScopedRule() {
    setScopedRules((current) => [...current, defaultScopedRuleForm(current.length + 1)]);
  }

  function removeScopedRule(index: number) {
    setScopedRules((current) => current.filter((_, idx) => idx !== index));
  }

  async function reloadScopedRules() {
    if (!scopedVersionId) return;
    setLoadingScopedRules(true);
    try {
      const payload = await api.getPolicyVersionScopedRules(scopedVersionId);
      setScopedRules((payload.scoped_rules || []).map((rule, index) => toScopedRuleForm(rule, index)));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to reload scoped rules");
    } finally {
      setLoadingScopedRules(false);
    }
  }

  async function saveScopedRules() {
    if (!scopedVersionId) {
      toast.error("Select a policy version first");
      return;
    }

    const normalized: PolicyScopedRule[] = [];
    for (const [index, rule] of scopedRules.entries()) {
      let metadata: Record<string, unknown> = {};
      const rawMetadata = rule.metadata_json.trim();
      if (rawMetadata) {
        try {
          const parsed = JSON.parse(rawMetadata);
          if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
            throw new Error("Metadata must be a JSON object");
          }
          metadata = parsed as Record<string, unknown>;
        } catch {
          toast.error(`Rule ${rule.rule_id || index + 1}: metadata must be valid JSON object`);
          return;
        }
      }

      normalized.push({
        rule_id: rule.rule_id.trim() || `scoped_rule_${index + 1}`,
        enabled: rule.enabled,
        priority: Number.isFinite(rule.priority) ? Number(rule.priority) : 100,
        description: rule.description.trim() || undefined,
        subjects: {
          user_ids: parseCsv(rule.user_ids),
          roles: parseCsvLower(rule.roles),
          departments: parseCsvLower(rule.departments),
          actor_types: parseCsvLower(rule.actor_types),
          agent_ids: parseCsv(rule.agent_ids),
          endpoint_ids: parseCsv(rule.endpoint_ids),
          source_surfaces: parseCsvLower(rule.source_surfaces),
        },
        resources: {
          ai_system_ids: parseCsv(rule.ai_system_ids),
          domains: parseCsvLower(rule.domains),
          tools: parseCsvLower(rule.tools),
          providers: parseCsvLower(rule.providers),
          models: parseCsvLower(rule.models),
        },
        actions: {
          types: parseCsvLower(rule.action_types),
          operations: parseCsvLower(rule.action_operations),
        },
        conditions: {
          data_classifications: parseCsvLower(rule.data_classifications),
          risk_tiers: parseCsv(rule.risk_tiers).map((item) => item.toUpperCase()),
          contains_sensitive:
            rule.contains_sensitive === "any"
              ? null
              : rule.contains_sensitive === "true",
        },
        effect: {
          decision: rule.decision,
          reason_code: rule.reason_code.trim() || undefined,
          explanation: rule.explanation.trim() || undefined,
          recommended_action: rule.recommended_action.trim() || undefined,
          priority: Number.isFinite(rule.priority) ? Number(rule.priority) : 100,
        },
        metadata,
      });
    }

    setSavingScopedRules(true);
    try {
      const payload = await api.updatePolicyVersionScopedRules(scopedVersionId, normalized);
      setScopedRules((payload.scoped_rules || []).map((rule, index) => toScopedRuleForm(rule, index)));
      toast.success(`Scoped rules saved (${payload.rule_count})`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to save scoped rules");
    } finally {
      setSavingScopedRules(false);
    }
  }

  async function createPack(e: FormEvent) {
    e.preventDefault();
    try {
      await api.createPolicyPack({
        name,
        description: "Policy pack for runtime guardrails.",
        status: "draft",
      });
      toast.success("Policy pack created");
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to create policy pack");
    }
  }

  async function ensurePilotPolicyPack() {
    setSeedingPilotPack(true);
    try {
      const result = await api.ensurePilotPolicyPack({ activate: true });
      toast.success(
        result.applied === "created"
          ? "Pilot policy pack created and activated"
          : "Pilot policy pack updated and activated"
      );
      await load();
      setTargetPackId(result.pack.id);
      setScopedPackId(result.pack.id);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to apply pilot policy pack");
    } finally {
      setSeedingPilotPack(false);
    }
  }

  async function updateStatus(pack: PolicyPack, status: string) {
    try {
      await api.updatePolicyPack(pack.id, { status });
      toast.success(`Policy pack set to ${status}`);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to update policy pack");
    }
  }

  async function publishTunedVersion(e: FormEvent) {
    e.preventDefault();
    if (!targetPackId) {
      toast.error("Select a target policy pack first");
      return;
    }
    const versionLabel = newVersion.trim();
    if (!versionLabel) {
      toast.error("Version label is required");
      return;
    }

    setPublishing(true);
    try {
      const versionsPayload = await api.listPolicyVersions(targetPackId);
      const sortedVersions = sortVersionsByCreatedAt(versionsPayload.items || []);
      const base = sortedVersions[0];

      if (!base) {
        toast.error("No base policy version found in the selected pack");
        return;
      }

      const tunePayload: TunePayload = {
        blockedKeywords: parseCsv(blockedKeywordsInput),
        highRiskTerms: parseCsv(highRiskTermsInput),
        sensitivePatterns: parseCsv(sensitivePatternsInput),
      };

      const tunedGuardians = applyGuardianTuning(
        Array.isArray(base.guardian_contracts) ? base.guardian_contracts : [],
        tunePayload
      );

      const tunedDefaults: Record<string, unknown> = {
        ...(base.enforcement_defaults || {}),
        default_decision: defaultDecision,
        escalation,
      };

      const baseScope = recordOf(base.scope);
      const gatewaySecurity = recordOf(baseScope.llm_gateway_security);
      const reversibleMasking = canAdministerMasking
        ? {
            ...recordOf(gatewaySecurity.reversible_masking),
            enabled: reversibleMaskingEnabled,
            restore_to_authenticated_caller: true,
            mapping_ttl_seconds: Math.min(300, Math.max(30, Number(mappingTtlSeconds) || 120)),
            max_text_chars: 60000,
            documents_enabled: documentsEnabled,
            max_document_bytes: Math.min(10, Math.max(1, Number(maxDocumentMiB) || 10)) * 1048576,
            max_document_pages: Math.min(100, Math.max(1, Number(maxDocumentPages) || 100)),
          }
        : recordOf(gatewaySecurity.reversible_masking);
      const nextScope = {
        ...baseScope,
        ...(canAdministerMasking
          ? { llm_gateway_security: { ...gatewaySecurity, reversible_masking: reversibleMasking } }
          : {}),
      };

      await api.createPolicyVersion(targetPackId, {
        version: versionLabel,
        scope: Object.keys(baseScope).length ? nextScope : {
          applies_to_risk_tiers: ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
          applies_to_ai_system_ids: null,
          applies_to_actor_types: ["human", "agent", "system"],
          ...(canAdministerMasking
            ? { llm_gateway_security: { reversible_masking: reversibleMasking } }
            : {}),
        },
        enforcement_defaults: tunedDefaults,
        guardian_contracts: tunedGuardians,
      });

      const pack = packs.find((item) => item.id === targetPackId);
      if (pack && String(pack.status || "").toLowerCase() !== "active") {
        await api.updatePolicyPack(pack.id, { status: "active" });
      }

      toast.success("Policy version published and available for runtime enforcement");
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to publish tuned policy version");
    } finally {
      setPublishing(false);
    }
  }

  const statusOptions = useMemo(
    () => Array.from(new Set(packs.map((item) => String(item.status || "")))).filter(Boolean).sort(),
    [packs]
  );

  const filteredPacks = useMemo(
    () =>
      packs.filter((item) => {
        if (statusFilter && String(item.status || "") !== statusFilter) return false;
        if (search) {
          const hay = `${item.name} ${item.description} ${item.id}`.toLowerCase();
          if (!hay.includes(search.toLowerCase())) return false;
        }
        return true;
      }),
    [packs, statusFilter, search]
  );

  const activeCount = useMemo(
    () => packs.filter((item) => String(item.status).toLowerCase() === "active").length,
    [packs]
  );

  const draftCount = useMemo(
    () => packs.filter((item) => String(item.status).toLowerCase() === "draft").length,
    [packs]
  );

  const retiredCount = useMemo(
    () => packs.filter((item) => String(item.status).toLowerCase() === "retired").length,
    [packs]
  );

  return (
    <AppShell>
      <div className="space-y-6">
        <PageHeader
          eyebrow="Policies"
          title="Policies"
          description="Choose who and what policies reach, review decisions, publish changes, and test coverage."
          actions={
            <div className="flex items-center gap-2">
              <Link href="/protect" className="rounded-md bg-orange-500 px-3 py-2 text-sm font-semibold text-slate-950 transition hover:bg-orange-400">Create policy</Link>
              <Button variant="outline" onClick={() => load()}>
                Refresh
              </Button>
            </div>
          }
        />

        <nav aria-label="Policy tasks" className="grid gap-2 rounded-xl border border-white/[0.08] bg-[#0a0f16] p-3 sm:grid-cols-2 lg:grid-cols-4">
          <Link href="/protect" className="rounded-lg border border-orange-400/25 bg-orange-400/[0.08] px-3 py-2 text-xs font-semibold text-orange-100 transition hover:bg-orange-400/[0.14]">Create policy</Link>
          {[ ["#policy-assignments", "Assignments"], ["#running-policies", "Running policies"], ["#policy-tuning-tools", "Fine-tune and publish"], ["#scoped-policy-tools", "Scoped rules"], ["/simulations", "Simulations"], ["#policy-pack-tools", "Policy packs"], ["/governance", "Approvals and rollout"], ["/validation/coverage", "Validation coverage"] ].map(([href, label]) => <Link key={label} href={href} className="rounded-lg border border-white/[0.06] px-3 py-2 text-xs font-semibold text-slate-300 transition hover:border-orange-400/25 hover:text-orange-200">{label}</Link>)}
        </nav>

        <PageSection title="Running Policies (Live Enforcement)" description="Current active versions available to runtime evaluation now.">
          <span id="running-policies" className="sr-only">Running policies</span>
          <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
            <p className="text-sm text-slate-400">{runningState === "error" ? "Running policy status is unavailable." : `${running?.running_versions.length ?? 0} running policy version${running?.running_versions.length === 1 ? "" : "s"} reported.`}</p>
            <details className="text-xs text-slate-500"><summary className="cursor-pointer font-medium text-slate-300">Technical enforcement details</summary><p className="mt-2 font-mono">Enforced policy version ID: {running?.enforced_policy_version_id || "Unavailable"}</p></details>
          </div>
          <SimpleTable
            columns={["Pack", "Version", "Created", "Guardians", "Default Decision", "Escalation", "Currently Enforced"]}
            rows={(running?.running_versions || []).map((item) => [
              `${item.pack_name} (${item.pack_status})`,
              item.version,
              new Date(item.created_at).toLocaleString(),
              String(item.guardian_count),
              item.default_decision,
              item.escalation,
              item.id === running?.enforced_policy_version_id ? "yes" : "no",
            ])}
            emptyLabel={runningState === "error" ? "Unavailable: running policy status did not respond." : "No running policies are currently reported."}
          />
        </PageSection>

        <KpiStrip
          items={[
            { label: "Policy Packs", value: packsState === "error" ? "Unavailable" : packs.length, tone: "info" },
            { label: "Active Packs", value: packsState === "error" ? "Unavailable" : activeCount, tone: "success" },
            {
              label: "Running Policy Versions",
              value: runningState === "error" ? "Unavailable" : running?.running_versions.length ?? 0,
              tone: running?.running_versions.length ? "info" : "warning",
              hint: running?.enforced_policy_version_id ? "An enforced version is reported" : "No enforced version reported",
            },
            {
              label: "Runtime Mode",
              value: runningState === "error" ? "Unavailable" : running?.platform_mode || "unknown",
              tone: running?.platform_mode === "enforce" ? "critical" : "warning",
            },
            { label: "Draft / Retired", value: packsState === "error" ? "Unavailable" : `${draftCount} / ${retiredCount}`, tone: "default" },
          ]}
        />

        <details id="policy-administration-tools" className="group overflow-hidden rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer list-none px-5 py-4 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.025]">Policy packs, assignments, and rollout</summary>
          <div className="space-y-6 border-t border-white/[0.07] p-4">
            <div className="flex flex-wrap items-center justify-between gap-3 rounded-lg border border-cyan-400/15 bg-cyan-400/[0.035] p-4">
              <div><p className="text-sm font-semibold text-slate-100">Administration</p><p className="mt-1 text-xs leading-5 text-slate-400">Apply the maintained pilot defaults to a policy pack when you are ready to configure a starting point.</p></div>
              <Button variant="outline" onClick={ensurePilotPolicyPack} disabled={seedingPilotPack}>{seedingPilotPack ? "Applying pilot policy defaults..." : "Apply pilot policy defaults"}</Button>
            </div>

        <PolicyPackPlatformWorkspace />

        <PageSection
          title="Who and what this policy reaches"
          description="Use the existing Policy Packs workflow for assignments, simulation, approvals, exceptions, and rollout. User-specific effective policy sources remain visible from User 360."
        >
          <span id="policy-assignments" className="sr-only">Assignments</span><div className="grid gap-3 md:grid-cols-3">
            <Link href="/users" className="rounded-lg border border-[#2a3348] bg-[#0d131d] p-4 transition hover:border-cyan-300/35 hover:bg-cyan-300/[0.04]">
              <p className="text-sm font-semibold text-slate-100">Open Users &amp; Policy Assignments</p>
              <p className="mt-1 text-xs leading-5 text-slate-500">Review the organization, department, group, and direct-user sources that appear in a user’s effective policy stack.</p>
            </Link>
            <Link href="/validation/coverage" className="rounded-lg border border-[#2a3348] bg-[#0d131d] p-4 transition hover:border-cyan-300/35 hover:bg-cyan-300/[0.04]">
              <p className="text-sm font-semibold text-slate-100">Open Control Coverage</p>
              <p className="mt-1 text-xs leading-5 text-slate-500">Inspect current, partial, stale, regressed, unsupported, and unknown deployment-surface evidence.</p>
            </Link>
            <Link href="/runtime-intelligence/activity-map" className="rounded-lg border border-[#2a3348] bg-[#0d131d] p-4 transition hover:border-cyan-300/35 hover:bg-cyan-300/[0.04]">
              <p className="text-sm font-semibold text-slate-100">Open Investigation &amp; AI Activity Lineage</p>
              <p className="mt-1 text-xs leading-5 text-slate-500">Follow authoritative action, decision, execution, and evidence references without creating a second lineage view.</p>
            </Link>
          </div>
        </PageSection>

        <details className="rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer px-4 py-3 text-sm font-semibold text-slate-200">Policy analytics</summary>
          <div className="border-t border-white/[0.07] p-4">
        <ModuleReportPanel
          footprintTitle="Policy Footprint"
          analyticsTitle="Policy Analytics"
          footprintItems={[
            { label: "Total Packs", value: packsState === "error" ? "Unavailable" : packs.length, tone: "info" },
            { label: "Active Coverage", value: packsState === "error" ? "Unavailable" : activeCount, tone: activeCount ? "success" : "warning" },
            { label: "Draft Backlog", value: packsState === "error" ? "Unavailable" : draftCount, tone: draftCount ? "warning" : "success" },
            { label: "Retired Packs", value: packsState === "error" ? "Unavailable" : retiredCount, tone: "default" },
          ]}
          analyticsItems={[
            { label: "Activation Rate", value: packsState === "error" ? "Unavailable" : `${packs.length ? Math.round((activeCount / packs.length) * 100) : 0}%`, tone: "info" },
            {
              label: "Running Versions",
              value: runningState === "error" ? "Unavailable" : running?.running_versions.length ?? 0,
              tone: "default",
              hint: "Active pack versions visible to runtime",
            },
            { label: "Filtered Results", value: packsState === "error" ? "Unavailable" : filteredPacks.length, tone: "default", hint: "Current view from filters" },
            { label: "Search Coverage", value: search ? "Scoped" : "Global", tone: search ? "warning" : "success" },
          ]}
        />
          </div>
        </details>

        <details id="policy-tuning-tools" className="group overflow-hidden rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer list-none px-5 py-4 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.025]">Fine-tune and publish <span className="ml-2 text-xs font-normal text-slate-600">Version defaults and keyword controls</span></summary>
          <div className="border-t border-white/[0.07] p-4">
        <PageSection title="Fine-Tune + Publish Policy Version" description="Create a tuned version and enforce it immediately by activating the pack.">
          <form className="grid gap-3 lg:grid-cols-2" onSubmit={publishTunedVersion}>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Target Pack</label>
              <select
                className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100"
                value={targetPackId}
                onChange={(e) => setTargetPackId(e.target.value)}
              >
                {packs.map((pack) => (
                  <option key={pack.id} value={pack.id}>
                    {pack.name} ({pack.status})
                  </option>
                ))}
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.08em] text-slate-500">New Version Label</label>
              <Input value={newVersion} onChange={(e) => setNewVersion(e.target.value)} placeholder="2.1.0 or tuned-2026-04-01" />
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Default Decision</label>
              <select
                className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100"
                value={defaultDecision}
                onChange={(e) => setDefaultDecision(e.target.value)}
              >
                <option value="allow">allow</option>
                <option value="warn">warn</option>
                <option value="block">block</option>
              </select>
            </div>
            <div className="space-y-2">
              <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Escalation</label>
              <select
                className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100"
                value={escalation}
                onChange={(e) => setEscalation(e.target.value)}
              >
                <option value="notify">notify</option>
                <option value="approval">approval</option>
                <option value="block">block</option>
              </select>
            </div>
            <div className="space-y-2 lg:col-span-2">
              <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Blocked Keywords (comma separated)</label>
              <Input
                value={blockedKeywordsInput}
                onChange={(e) => setBlockedKeywordsInput(e.target.value)}
                placeholder="ignore previous instructions,jailbreak,..."
              />
            </div>
            <div className="space-y-2 lg:col-span-2">
              <label className="text-xs uppercase tracking-[0.08em] text-slate-500">High Risk Terms (comma separated)</label>
              <Input
                value={highRiskTermsInput}
                onChange={(e) => setHighRiskTermsInput(e.target.value)}
                placeholder="bypass policy,override policy,..."
              />
            </div>
            <div className="space-y-2 lg:col-span-2">
              <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Sensitive Regex Patterns (comma separated)</label>
              <Input
                value={sensitivePatternsInput}
                onChange={(e) => setSensitivePatternsInput(e.target.value)}
                placeholder="(?i)emirates\\s*id,(?i)iban,..."
              />
            </div>
            {canAdministerMasking ? (
              <div className="space-y-4 rounded-lg border border-cyan-400/20 bg-cyan-400/[0.035] p-4 lg:col-span-2">
                <div>
                  <p className="text-sm font-semibold text-slate-100">Reversible sensitive data masking</p>
                  <p className="mt-1 text-xs leading-5 text-slate-400">
                    Saved on this new immutable policy version. Restored values are returned only to the authenticated caller after response controls allow the result. Requests cannot enable masking themselves.
                  </p>
                </div>
                <label className="flex items-start gap-3 text-sm text-slate-200">
                  <input
                    aria-label="Enable reversible masking"
                    type="checkbox"
                    checked={reversibleMaskingEnabled}
                    onChange={(e) => setReversibleMaskingEnabled(e.target.checked)}
                    className="mt-1 accent-cyan-300"
                  />
                  <span>Enable reversible masking for this policy version <span className="block text-xs text-slate-500">Off by default. Requires the request to pass existing policy and response controls.</span></span>
                </label>
                <div className="grid gap-3 md:grid-cols-3">
                  <div className="space-y-2">
                    <label className="text-xs uppercase tracking-[0.08em] text-slate-500" htmlFor="masking-ttl">Mapping lifetime (seconds)</label>
                    <Input id="masking-ttl" type="number" min={30} max={300} value={mappingTtlSeconds} onChange={(e) => setMappingTtlSeconds(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs uppercase tracking-[0.08em] text-slate-500" htmlFor="masking-document-size">Maximum document size (MiB)</label>
                    <Input id="masking-document-size" type="number" min={1} max={10} value={maxDocumentMiB} onChange={(e) => setMaxDocumentMiB(e.target.value)} />
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs uppercase tracking-[0.08em] text-slate-500" htmlFor="masking-document-pages">Maximum PDF pages</label>
                    <Input id="masking-document-pages" type="number" min={1} max={100} value={maxDocumentPages} onChange={(e) => setMaxDocumentPages(e.target.value)} />
                  </div>
                </div>
                <label className="flex items-center gap-3 text-sm text-slate-200">
                  <input type="checkbox" checked={documentsEnabled} onChange={(e) => setDocumentsEnabled(e.target.checked)} className="accent-cyan-300" />
                  Enable PDF and DOCX document processing
                </label>
                <p className="text-xs leading-5 text-amber-200/80">Pilot support covers text-based PDF and DOCX files up to 10 MiB. Scanned/image-only, encrypted, and legacy .doc files are unsupported. PDF layout may reflow.</p>
              </div>
            ) : null}
            <div className="lg:col-span-2">
              <Button type="submit" disabled={publishing || !targetPackId || (canAdministerMasking && maskingConfigPackId !== targetPackId)}>
                {publishing ? "Publishing..." : "Publish Tuned Version (Realtime)"}
              </Button>
            </div>
          </form>
        </PageSection>
          </div>
        </details>

        <details id="scoped-policy-tools" className="group overflow-hidden rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer list-none px-5 py-4 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.025]">Edit scoped rules <span className="ml-2 text-xs font-normal text-slate-600">Advanced identity, resource, and action matching</span></summary>
          <div className="border-t border-white/[0.07] p-4">
        <PageSection
          title="Scoped Rules Editor"
          description="Manage user/role/domain scoped enforcement rules without raw JSON API calls."
        >
          <div className="space-y-4">
            <div className="grid gap-3 xl:grid-cols-4">
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Policy Pack</label>
                <select
                  className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100"
                  value={scopedPackId}
                  onChange={(e) => setScopedPackId(e.target.value)}
                >
                  {packs.map((pack) => (
                    <option key={`scoped-pack-${pack.id}`} value={pack.id}>
                      {pack.name} ({pack.status})
                    </option>
                  ))}
                </select>
              </div>
              <div className="space-y-2">
                <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Policy Version</label>
                <select
                  className="h-9 rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100"
                  value={scopedVersionId}
                  onChange={(e) => setScopedVersionId(e.target.value)}
                >
                  {scopedVersions.map((version) => (
                    <option key={`scoped-version-${version.id}`} value={version.id}>
                      {version.version} ({new Date(version.created_at).toLocaleString()})
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-end gap-2 xl:col-span-2">
                <Button variant="outline" onClick={reloadScopedRules} disabled={!scopedVersionId || loadingScopedRules}>
                  Reload Rules
                </Button>
                <Button variant="outline" onClick={addScopedRule} disabled={!scopedVersionId || loadingScopedRules}>
                  Add Rule
                </Button>
                <Button onClick={saveScopedRules} disabled={!scopedVersionId || savingScopedRules || loadingScopedRules}>
                  {savingScopedRules ? "Saving..." : "Save Scoped Rules"}
                </Button>
              </div>
            </div>

            {loadingScopedRules ? (
              <div className="rounded-md border border-slate-800 bg-slate-950/70 px-3 py-2 text-sm text-slate-300">
                Loading scoped rules...
              </div>
            ) : null}

            {!loadingScopedRules && !scopedRules.length ? (
              <div className="rounded-md border border-slate-800 bg-slate-950/70 px-3 py-3 text-sm text-slate-300">
                No scoped rules configured for this policy version.
              </div>
            ) : null}

            <div className="space-y-4">
              {scopedRules.map((rule, index) => (
                <div key={`${rule.rule_id}-${index}`} className="space-y-3 rounded-lg border border-[#2a3348] p-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-slate-100">Rule {index + 1}</p>
                    <Button variant="outline" onClick={() => removeScopedRule(index)}>
                      Remove
                    </Button>
                  </div>

                  <div className="grid gap-3 lg:grid-cols-4">
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Rule ID</label>
                      <Input value={rule.rule_id} onChange={(e) => updateScopedRule(index, { rule_id: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Priority</label>
                      <Input
                        type="number"
                        value={String(rule.priority)}
                        onChange={(e) => updateScopedRule(index, { priority: Number(e.target.value || "100") })}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Decision</label>
                      <select
                        className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100"
                        value={rule.decision}
                        onChange={(e) => updateScopedRule(index, { decision: e.target.value as ScopedRuleDecision })}
                      >
                        {SCOPED_RULE_DECISIONS.map((decision) => (
                          <option key={`${rule.rule_id}-${decision}`} value={decision}>
                            {decision}
                          </option>
                        ))}
                      </select>
                    </div>
                    <label className="flex items-end gap-2 pb-2 text-sm text-slate-300">
                      <input
                        type="checkbox"
                        checked={rule.enabled}
                        onChange={(e) => updateScopedRule(index, { enabled: e.target.checked })}
                      />
                      Enabled
                    </label>
                  </div>

                  <div className="grid gap-3 lg:grid-cols-3">
                    <div className="space-y-2 lg:col-span-3">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Description</label>
                      <Input value={rule.description} onChange={(e) => updateScopedRule(index, { description: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Reason Code</label>
                      <Input value={rule.reason_code} onChange={(e) => updateScopedRule(index, { reason_code: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Recommended Action</label>
                      <Input
                        value={rule.recommended_action}
                        onChange={(e) => updateScopedRule(index, { recommended_action: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Contains Sensitive</label>
                      <select
                        className="h-9 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100"
                        value={rule.contains_sensitive}
                        onChange={(e) =>
                          updateScopedRule(index, {
                            contains_sensitive: e.target.value as ScopedRuleForm["contains_sensitive"],
                          })
                        }
                      >
                        <option value="any">any</option>
                        <option value="true">true</option>
                        <option value="false">false</option>
                      </select>
                    </div>
                    <div className="space-y-2 lg:col-span-3">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Explanation</label>
                      <Input value={rule.explanation} onChange={(e) => updateScopedRule(index, { explanation: e.target.value })} />
                    </div>
                  </div>

                  <div className="grid gap-3 lg:grid-cols-3">
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Roles (CSV)</label>
                      <Input value={rule.roles} onChange={(e) => updateScopedRule(index, { roles: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Departments (CSV)</label>
                      <Input value={rule.departments} onChange={(e) => updateScopedRule(index, { departments: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">User IDs (CSV)</label>
                      <Input value={rule.user_ids} onChange={(e) => updateScopedRule(index, { user_ids: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Actor Types (CSV)</label>
                      <Input value={rule.actor_types} onChange={(e) => updateScopedRule(index, { actor_types: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Agent IDs (CSV)</label>
                      <Input value={rule.agent_ids} onChange={(e) => updateScopedRule(index, { agent_ids: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Endpoint IDs (CSV)</label>
                      <Input value={rule.endpoint_ids} onChange={(e) => updateScopedRule(index, { endpoint_ids: e.target.value })} />
                    </div>
                    <div className="space-y-2 lg:col-span-3">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Source Surfaces (CSV)</label>
                      <Input
                        value={rule.source_surfaces}
                        onChange={(e) => updateScopedRule(index, { source_surfaces: e.target.value })}
                        placeholder="browser, gateway, connector..."
                      />
                    </div>
                  </div>

                  <div className="grid gap-3 lg:grid-cols-3">
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Domains (CSV)</label>
                      <Input value={rule.domains} onChange={(e) => updateScopedRule(index, { domains: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">AI System IDs (CSV)</label>
                      <Input value={rule.ai_system_ids} onChange={(e) => updateScopedRule(index, { ai_system_ids: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Tools (CSV)</label>
                      <Input value={rule.tools} onChange={(e) => updateScopedRule(index, { tools: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Providers (CSV)</label>
                      <Input value={rule.providers} onChange={(e) => updateScopedRule(index, { providers: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Models (CSV)</label>
                      <Input value={rule.models} onChange={(e) => updateScopedRule(index, { models: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Action Types (CSV)</label>
                      <Input value={rule.action_types} onChange={(e) => updateScopedRule(index, { action_types: e.target.value })} />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Action Operations (CSV)</label>
                      <Input
                        value={rule.action_operations}
                        onChange={(e) => updateScopedRule(index, { action_operations: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Data Classifications (CSV)</label>
                      <Input
                        value={rule.data_classifications}
                        onChange={(e) => updateScopedRule(index, { data_classifications: e.target.value })}
                      />
                    </div>
                    <div className="space-y-2">
                      <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Risk Tiers (CSV)</label>
                      <Input value={rule.risk_tiers} onChange={(e) => updateScopedRule(index, { risk_tiers: e.target.value })} />
                    </div>
                  </div>

                  <div className="space-y-2">
                    <label className="text-xs uppercase tracking-[0.08em] text-slate-500">Metadata JSON</label>
                    <Input
                      value={rule.metadata_json}
                      onChange={(e) => updateScopedRule(index, { metadata_json: e.target.value })}
                      placeholder='{"owner":"security-team"}'
                    />
                  </div>
                </div>
              ))}
            </div>
          </div>
        </PageSection>
          </div>
        </details>

        <TableFilters
          actions={
            <Button
              variant="outline"
              onClick={() => {
                setStatusFilter("");
                setSearch("");
              }}
            >
              Clear Filters
            </Button>
          }
        >
          <FilterLabel label="Status">
            <FilterSelect
              value={statusFilter}
              onChange={setStatusFilter}
              options={[{ value: "", label: "All" }, ...statusOptions.map((value) => ({ value, label: value }))]}
            />
          </FilterLabel>
          <FilterLabel label="Search">
            <FilterInput value={search} onChange={setSearch} placeholder="Name, description, id..." />
          </FilterLabel>
        </TableFilters>

        <details id="policy-pack-tools" className="group overflow-hidden rounded-xl border border-white/[0.08] bg-[#0a0f16]">
          <summary className="cursor-pointer list-none px-5 py-4 text-sm font-semibold text-slate-200 transition hover:bg-white/[0.025]">Create policy pack <span className="ml-2 text-xs font-normal text-slate-600">Create a reusable policy pack for governance workflows</span></summary>
          <div className="border-t border-white/[0.07] p-4">
        <PageSection title="Create Policy Pack" description="Create a reusable policy pack for governance workflows.">
          <form className="flex gap-2" onSubmit={createPack}>
            <Input value={name} onChange={(e) => setName(e.target.value)} placeholder="Policy pack name" />
            <Button type="submit">Create Pack</Button>
          </form>
        </PageSection>
          </div>
        </details>

        <PageSection title="Policy packs" description={packsState === "error" ? "Policy pack source unavailable" : `${filteredPacks.length} policy packs`}>
          <SimpleTable
            columns={["Name", "Status", "Description", "Actions"]}
            rows={filteredPacks.map((p) => [
              p.name,
              p.status,
              p.description,
              <div key={p.id} className="flex flex-wrap items-center gap-2"><details className="text-xs text-slate-500"><summary className="cursor-pointer">Technical details</summary><p className="mt-1 font-mono">Pack ID: {p.id}</p></details><RowActions
                actions={[
                  { label: "Activate", onClick: () => updateStatus(p, "active"), variant: "default" },
                  { label: "Draft", onClick: () => updateStatus(p, "draft"), variant: "outline" },
                  { label: "Retire", onClick: () => updateStatus(p, "retired"), variant: "destructive" },
                ]}
              /></div>,
            ])}
            emptyLabel={packsState === "error" ? "Unavailable: policy pack source did not respond." : "No policy packs match this view."}
          />
        </PageSection>
          </div>
        </details>
      </div>
    </AppShell>
  );
}
