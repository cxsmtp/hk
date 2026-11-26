"use client";

import "../ftr-settings.css";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import {
  SCOPE_HINTS,
  SCOPE_LABELS,
  SCOPE_ORDER,
  TIER_LABELS,
  TIER_ORDER,
  grantLine,
  hoursLabel,
  policyChanged,
  policyPayload,
  progressLabel,
  refusalMessage,
  ruleProblems,
  ruleSummary,
  withRuleChange,
} from "@/lib/ai-system-approvals";
import type { ApprovalGrantView, ApprovalPolicy, ApprovalPolicyView, ApprovalRequestView, ApprovalScope, ApprovalTier, TierRule } from "@/lib/ai-system-approvals";

const message = (error: unknown) => refusalMessage(error instanceof Error ? error.message : String(error ?? ""));

type Line = { text: string; bad: boolean };
type Choice = { scope: ApprovalScope; hours: string };

/**
 * Settings → AI system approvals (Workflow): the approval policy by risk tier, the requests waiting for a decision,
 * and the standing approvals. Owners and admins change the policy; whoever sees the inventory reads it, and approves,
 * denies or revokes what their role may (app/api/routers/ai_system_approvals.py).
 */
export default function AiSystemApprovalsPage() {
  const [view, setView] = useState<ApprovalPolicyView | null>(null);
  const [form, setForm] = useState<ApprovalPolicy | null>(null);
  const [requests, setRequests] = useState<ApprovalRequestView[]>([]);
  const [grants, setGrants] = useState<ApprovalGrantView[]>([]);
  const [choices, setChoices] = useState<Record<string, Choice>>({});
  const [loadError, setLoadError] = useState("");
  const [status, setStatus] = useState<Line>({ text: "", bad: false });
  const [decisionLine, setDecisionLine] = useState<Line>({ text: "", bad: false });

  const loadQueues = useCallback(async () => {
    const [pending, standing] = await Promise.all([api.listAiSystemApprovals("pending"), api.listAiSystemApprovalGrants("ACTIVE")]);
    setRequests(pending.items);
    setGrants(standing.items);
  }, []);

  const load = useCallback(async () => {
    try {
      const next = await api.getApprovalPolicy();
      setView(next);
      setForm(next.policy);
      await loadQueues();
      setLoadError("");
    } catch (error) {
      setLoadError(message(error));
    }
  }, [loadQueues]);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  function changeRule(tier: ApprovalTier, patch: Partial<TierRule>) {
    setForm((current) => (current ? { ...current, tiers: { ...current.tiers, [tier]: withRuleChange(current.tiers[tier], patch) } } : current));
  }

  function toggle<T extends string>(list: T[], item: T, on: boolean): T[] {
    return on ? (list.includes(item) ? list : [...list, item]) : list.filter((x) => x !== item);
  }

  const problems = form && view ? TIER_ORDER.flatMap((tier) => ruleProblems(form.tiers[tier], view.roles).map((p) => `${TIER_LABELS[tier]}: ${p}`)) : [];

  async function save(next: ApprovalPolicy) {
    if (problems.length && next === form) return setStatus({ text: problems[0], bad: true });
    setStatus({ text: "Saving…", bad: false });
    try {
      const saved = await api.saveApprovalPolicy(policyPayload(next));
      setView(saved);
      setForm(saved.policy);
      setStatus({ text: "Saved. Requests made from now on follow it; a request already waiting keeps the rule it was made under.", bad: false });
    } catch (error) {
      setStatus({ text: message(error), bad: true });
    }
  }

  function choiceFor(request: ApprovalRequestView): Choice {
    return choices[request.id] ?? { scope: request.scope, hours: String(request.duration_hours ?? "") };
  }

  async function decide(request: ApprovalRequestView, decision: "approve" | "deny") {
    const choice = choiceFor(request);
    let reason = "";
    if (decision === "deny") {
      const typed = window.prompt(`Deny the approval of ${request.ai_system_name || "this AI system"}? Say why (kept in the audit log).`, "");
      if (typed === null) return;
      reason = typed;
    }
    const body =
      decision === "approve" && !request.scope_fixed
        ? { decision, scope: choice.scope, ...(choice.scope === "time_bound" && choice.hours ? { duration_hours: Number(choice.hours) } : {}) }
        : { decision, ...(reason ? { reason } : {}) };
    setDecisionLine({ text: "Saving…", bad: false });
    try {
      const result = await api.decideAiSystemApproval(request.id, body);
      setDecisionLine({
        text:
          result.request.status === "approved"
            ? `${request.ai_system_name || "The AI system"} is approved (${SCOPE_LABELS[result.request.scope]}).`
            : result.request.status === "denied"
              ? "Denied."
              : `Your approval is recorded: ${progressLabel(result.request)}.`,
        bad: false,
      });
      await loadQueues();
    } catch (error) {
      setDecisionLine({ text: message(error), bad: true });
    }
  }

  async function revoke(grant: ApprovalGrantView) {
    const reason = window.prompt(`Revoke the approval of ${grant.ai_system_name || "this AI system"}? It goes back to pending re-approval at once. Say why.`, "");
    if (reason === null) return;
    setDecisionLine({ text: "Revoking…", bad: false });
    try {
      await api.revokeAiSystemApproval(grant.id, reason);
      setDecisionLine({ text: "Revoked. The AI system needs a new approval.", bad: false });
      await loadQueues();
    } catch (error) {
      setDecisionLine({ text: message(error), bad: true });
    }
  }

  const manage = Boolean(view?.may_manage);

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-approvals">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">AI system approvals</h1>
            <span className="crumbs">Workflow · who approves an AI system, and for how long · Owners and admins change the policy</span>
          </div>
        </div>
        <div id="tab">
          {loadError ? (
            <div className="panel">
              <div className="empty">
                <b>{loadError}</b>
              </div>
            </div>
          ) : null}
          {!view && !loadError ? <p className="muted">Loading…</p> : null}
          {view && form ? (
            <>
              <div className="panel" id="approval-requests">
                <h2>
                  Waiting for a decision <small>{requests.length ? `${requests.length} request${requests.length === 1 ? "" : "s"}` : "none"}</small>
                </h2>
                {requests.length === 0 ? <p className="muted small">No AI system is waiting for an approval.</p> : null}
                {requests.length ? (
                  <div className="tw">
                    <table>
                      <thead>
                        <tr>
                          <th>AI system</th>
                          <th>Tier</th>
                          <th>Approvals</th>
                          <th>Scope</th>
                          <th>Decide</th>
                        </tr>
                      </thead>
                      <tbody>
                        {requests.map((request) => {
                          const choice = choiceFor(request);
                          return (
                            <tr key={request.id} data-request={request.id}>
                              <td>
                                <b>{request.ai_system_name || request.ai_system_id}</b>
                                {request.renewal ? <span className="chip">renewal</span> : null}
                                {request.reason ? <div className="small muted">{request.reason}</div> : null}
                              </td>
                              <td className="small">{request.tier ? TIER_LABELS[request.tier] : request.risk_tier}</td>
                              <td className="small">
                                {progressLabel(request)}
                                <div className="muted">by {request.approver_roles.join(", ")}</div>
                              </td>
                              <td className="small">
                                {request.scope_fixed || !request.may_approve ? (
                                  <>
                                    {SCOPE_LABELS[request.scope]}
                                    {request.scope === "time_bound" && request.duration_hours ? `, ${hoursLabel(request.duration_hours)}` : ""}
                                  </>
                                ) : (
                                  <div className="row">
                                    <select
                                      aria-label="Scope"
                                      value={choice.scope}
                                      onChange={(event) => setChoices({ ...choices, [request.id]: { ...choice, scope: event.target.value as ApprovalScope } })}
                                    >
                                      {request.allowed_scopes.map((scope) => (
                                        <option key={scope} value={scope}>
                                          {SCOPE_LABELS[scope]}
                                        </option>
                                      ))}
                                    </select>
                                    {choice.scope === "time_bound" ? (
                                      <input
                                        aria-label="Hours"
                                        type="number"
                                        min={1}
                                        max={request.max_duration_hours ?? undefined}
                                        value={choice.hours}
                                        onChange={(event) => setChoices({ ...choices, [request.id]: { ...choice, hours: event.target.value } })}
                                      />
                                    ) : null}
                                  </div>
                                )}
                              </td>
                              <td>
                                <div className="flex">
                                  <button type="button" className="primary" disabled={!request.may_approve} onClick={() => decide(request, "approve")}>
                                    Approve
                                  </button>
                                  <button type="button" className="ghost danger" disabled={!request.may_deny} onClick={() => decide(request, "deny")}>
                                    Deny
                                  </button>
                                </div>
                                {!request.may_approve && request.may_deny ? <div className="small muted">You asked for it: someone else approves.</div> : null}
                              </td>
                            </tr>
                          );
                        })}
                      </tbody>
                    </table>
                  </div>
                ) : null}
                <p className={decisionLine.bad ? "err" : "small muted"} role="status">
                  {decisionLine.text}
                </p>
              </div>

              <div className="panel" id="approval-grants">
                <h2>
                  Standing approvals <small>{grants.length}</small>
                </h2>
                {grants.length === 0 ? <p className="muted small">No AI system holds an approval.</p> : null}
                {grants.length ? (
                  <div className="tw">
                    <table>
                      <tbody>
                        {grants.map((grant) => (
                          <tr key={grant.id}>
                            <td>
                              <b>{grant.ai_system_name || grant.ai_system_id}</b>
                            </td>
                            <td className="small">{grant.risk_tier}</td>
                            <td className="small">{grantLine(grant)}</td>
                            <td>
                              <button type="button" className="ghost danger" onClick={() => revoke(grant)}>
                                Revoke
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </div>

              <div className="panel" id="approval-policy">
                <h2>
                  Approval policy by risk tier{" "}
                  {view.revision ? (
                    <small>
                      saved{view.updated_by ? ` by ${view.updated_by}` : ""}
                    </small>
                  ) : (
                    <span className="chip ok">
                      <i />
                      Defaults
                    </span>
                  )}
                </h2>
                <p className="muted small">
                  Setting an AI system to approved goes through this policy: someone asks, and the number of different people below approve. With two or more, the person who asked
                  is never one of them. {view.not_approvable_tiers.join(", ")} systems are never approved; a tier not listed here is treated as{" "}
                  {TIER_LABELS[view.unknown_tier_reads_as]}. <Link href="/settings/guide/ai-system-approvals">How approvals work</Link>
                </p>
                <form className="form" onSubmit={(event) => event.preventDefault()}>
                  {TIER_ORDER.map((tier) => {
                    const rule = form.tiers[tier];
                    return (
                      <fieldset key={tier} data-tier={tier} disabled={!manage}>
                        <h3>
                          {TIER_LABELS[tier]} <small className="muted">{ruleSummary(rule)}</small>
                        </h3>
                        <div className="row">
                          <label className="f">
                            Different people who approve
                            <select value={rule.min_approvers} onChange={(event) => changeRule(tier, { min_approvers: Number(event.target.value) })}>
                              {[1, 2, 3, 4, 5].map((n) => (
                                <option key={n} value={n}>
                                  {n}
                                </option>
                              ))}
                            </select>
                          </label>
                          <label className="f">
                            Default scope
                            <select value={rule.default_scope} onChange={(event) => changeRule(tier, { default_scope: event.target.value as ApprovalScope })}>
                              {rule.allowed_scopes.map((scope) => (
                                <option key={scope} value={scope}>
                                  {SCOPE_LABELS[scope]}
                                </option>
                              ))}
                            </select>
                          </label>
                          <label className="f">
                            Time-bound by default (hours)
                            <input type="number" min={1} max={rule.max_duration_hours} value={rule.default_duration_hours} onChange={(event) => changeRule(tier, { default_duration_hours: Number(event.target.value) })} />
                          </label>
                          <label className="f">
                            Longest time-bound (hours)
                            <input type="number" min={1} max={8760} value={rule.max_duration_hours} onChange={(event) => changeRule(tier, { max_duration_hours: Number(event.target.value) })} />
                          </label>
                        </div>
                        <label className="check">
                          <input
                            type="checkbox"
                            checked={rule.allow_self_approval}
                            disabled={rule.min_approvers > 1}
                            onChange={(event) => changeRule(tier, { allow_self_approval: event.target.checked })}
                          />
                          <span>The person who asked may approve it themselves (only with one approver)</span>
                        </label>
                        <div className="row">
                          <span className="small">Scopes an approver may choose:</span>
                          {SCOPE_ORDER.map((scope) => (
                            <label className="check" key={scope} title={SCOPE_HINTS[scope]}>
                              <input
                                type="checkbox"
                                checked={rule.allowed_scopes.includes(scope)}
                                onChange={(event) => changeRule(tier, { allowed_scopes: toggle(rule.allowed_scopes, scope, event.target.checked) })}
                              />
                              <span>{SCOPE_LABELS[scope]}</span>
                            </label>
                          ))}
                        </div>
                        <div className="row">
                          <span className="small">Roles that approve:</span>
                          {view.roles.map((role) => (
                            <label className="check" key={role}>
                              <input
                                type="checkbox"
                                checked={rule.approver_roles.includes(role)}
                                onChange={(event) => changeRule(tier, { approver_roles: toggle(rule.approver_roles, role, event.target.checked) })}
                              />
                              <span>{role}</span>
                            </label>
                          ))}
                        </div>
                      </fieldset>
                    );
                  })}
                  <label className="f">
                    A request waits for a decision this long (hours), then expires
                    <input
                      type="number"
                      min={1}
                      max={720}
                      disabled={!manage}
                      value={form.request_ttl_hours}
                      onChange={(event) => setForm({ ...form, request_ttl_hours: Number(event.target.value) })}
                    />
                  </label>
                  {problems.length ? (
                    <ul className="small">
                      {problems.map((problem) => (
                        <li key={problem} className="warn-t">
                          ! {problem}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                  {manage ? (
                    <div className="flex">
                      <button type="button" className="primary" disabled={!policyChanged(view.policy, form) || problems.length > 0} onClick={() => save(form)}>
                        Save
                      </button>
                      <button type="button" className="ghost" disabled={!policyChanged(view.policy, form)} onClick={() => setForm(view.policy)}>
                        Back to what was saved
                      </button>
                      <button
                        type="button"
                        className="ghost"
                        onClick={() => {
                          if (window.confirm("Go back to the defaults for every tier?")) save(view.defaults).catch(() => undefined);
                        }}
                      >
                        Use the defaults
                      </button>
                      <span className={status.bad ? "err" : "small muted"} role="status">
                        {status.text}
                      </span>
                    </div>
                  ) : (
                    <p className="small muted">Only owners and admins change the policy.</p>
                  )}
                </form>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
