"use client";

import Link from "next/link";
import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { toast } from "sonner";

import { api } from "@/lib/api";
import {
  APPLICABILITY_LABELS,
  CONTROL_CHIP,
  CONTROL_LABELS,
  evidenceQuery,
  filterRequirements,
  fixFor,
  packLine,
  REQUIREMENT_CHIP,
  REQUIREMENT_LABELS,
  STATUS_FILTERS,
} from "@/lib/compliance";
import type { Applicability, PackRequirement, PacksOverview, PackView, StatusFilter } from "@/lib/compliance";
import { errorMessageFrom } from "@/lib/licence";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const WHO: Array<Applicability | "all"> = ["all", "product", "customer", "organisational"];

function save(blob: Blob, name: string) {
  const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 10_000);
}

/** What an owner or admin records about one requirement: in place (where its evidence is) or not applicable. */
function RecordForm({ pack, item, onSaved }: { pack: PackView; item: PackRequirement; onSaved: (next: PackView) => void }) {
  const [status, setStatus] = useState<"in_place" | "not_applicable">(item.attestation?.status ?? "in_place");
  const [note, setNote] = useState(item.attestation?.note ?? "");
  const [reference, setReference] = useState(item.attestation?.reference ?? "");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent) {
    event.preventDefault();
    setBusy(true);
    try {
      onSaved(await api.recordRequirement(pack.id, item.id, { status, note, reference }));
      toast.success("Recorded. It is due for review in a year.");
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  async function remove() {
    setBusy(true);
    try {
      onSaved(await api.removeRequirementRecord(pack.id, item.id));
      toast.success("Record removed.");
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  return (
    <form className="form mt" onSubmit={submit} data-ui="pack-record-form">
      <div className="seg">
        <button type="button" className={status === "in_place" ? "primary" : ""} onClick={() => setStatus("in_place")}>
          In place
        </button>
        <button type="button" className={status === "not_applicable" ? "primary" : ""} onClick={() => setStatus("not_applicable")}>
          Not applicable
        </button>
      </div>
      <label className="f">
        {status === "in_place" ? "What is in place, and where its evidence is" : "Why it does not apply"}
        <input value={note} maxLength={2000} onChange={(e) => setNote(e.target.value)} />
      </label>
      <label className="f">
        Reference (document, ticket or link; optional)
        <input value={reference} maxLength={500} onChange={(e) => setReference(e.target.value)} />
      </label>
      <div className="flex">
        <button className="btn" type="submit" disabled={busy || !note.trim()}>
          Record
        </button>
        {item.attestation ? (
          <button className="btn ghost" type="button" disabled={busy} onClick={remove}>
            Remove the record
          </button>
        ) : null}
      </div>
    </form>
  );
}

/**
 * The framework packs of Settings → Compliance (apps/api/app/services/compliance_packs): a picker of every pack with its
 * counts; for the chosen pack each requirement with its status, who does it (Hawk AI, the customer with Hawk AI, or the
 * organisation), the Hawk AI controls behind it and a link to the setting that closes a gap; records of organisational
 * requirements; and the signed evidence bundle for a window.
 */
export function FrameworkPacks() {
  const [overview, setOverview] = useState<PacksOverview | null>(null);
  const [current, setCurrent] = useState("");
  const [pack, setPack] = useState<PackView | null>(null);
  const [who, setWho] = useState<Applicability | "all">("all");
  const [filter, setFilter] = useState<StatusFilter>("all");
  const [open, setOpen] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [busy, setBusy] = useState(false);
  const [loadError, setLoadError] = useState("");

  useEffect(() => {
    api
      .getCompliancePacks()
      .then((next) => {
        setOverview(next);
        setCurrent((id) => id || next.packs[0]?.id || "");
      })
      .catch((error) => setLoadError(message(error)));
  }, []);

  const showPack = useCallback((next: PackView) => {
    setPack(next);
    setOverview((prev) => (prev ? { ...prev, packs: prev.packs.map((p) => (p.id === next.id ? { ...p, counts: next.summary } : p)) } : prev));
  }, []);

  useEffect(() => {
    if (!current) return;
    setPack(null);
    setOpen("");
    api
      .getCompliancePack(current)
      .then(showPack)
      .catch((error) => toast.error(message(error)));
  }, [current, showPack]);

  async function download() {
    if (!pack) return;
    setBusy(true);
    try {
      const blob = await api.packEvidence(pack.id, evidenceQuery(from, to));
      save(blob, `hawk-${pack.id}-evidence.zip`);
      toast.success("Downloaded. Check it offline with tools/verify_evidence.py and the public keys.");
    } catch (error) {
      toast.error(message(error));
    }
    setBusy(false);
  }

  if (loadError) {
    return (
      <div className="panel">
        <div className="empty">
          <b>{loadError}</b>
        </div>
      </div>
    );
  }
  if (!overview) return <p className="muted">Loading the packs…</p>;

  const items = pack ? filterRequirements(pack.requirements, who, filter) : [];

  return (
    <div data-ui="compliance-packs">
      <div className="callout warn" data-ui="packs-disclaimer">
        {overview.disclaimer}
      </div>
      <div className="panel mt">
        <h2>
          Framework packs <small>pick one: requirements, Hawk AI&apos;s controls and their status now</small>
        </h2>
        {/* On a phone: one list to choose from instead of a wall of buttons (globals: .pack-select under 640 px). */}
        <label className="pack-select f">
          <span className="sr-only">Framework pack</span>
          <select value={current} onChange={(event) => setCurrent(event.target.value)} data-ui="pack-select">
            {overview.packs.map((p) => (
              <option key={p.id} value={p.id}>
                {p.framework.short}
                {p.optional ? " (optional)" : ""}
                {p.counts.gap ? ` · ${p.counts.gap} gaps` : ""}
              </option>
            ))}
          </select>
        </label>
        <div className="seg" role="tablist" aria-label="Framework packs" data-ui="pack-picker">
          {overview.packs.map((p) => (
            <button key={p.id} type="button" role="tab" aria-selected={p.id === current} className={p.id === current ? "primary" : ""} data-pack={p.id} title={`${p.framework.name} — ${packLine(p.counts)}`} onClick={() => setCurrent(p.id)}>
              {p.framework.short}
              {p.optional ? " (optional)" : ""}
              {p.counts.gap ? ` · ${p.counts.gap} gaps` : ""}
            </button>
          ))}
        </div>
      </div>
      {!pack ? <p className="muted mt">Loading…</p> : null}
      {pack ? (
        <>
          <div className="panel mt" data-ui="pack-head">
            <h2>
              <a href={pack.framework.url} target="_blank" rel="noreferrer noopener">
                {pack.framework.name}
              </a>{" "}
              <small>
                {pack.framework.version} · {pack.framework.publisher} · {pack.framework.jurisdiction} · pack {pack.version}
              </small>
            </h2>
            <p className="small">{overview.packs.find((p) => p.id === pack.id)?.summary}</p>
            <p className="small muted">{pack.scope}</p>
            <div className="kpis">
              {(["met", "partly", "gap", "yours", "attested", "not_applicable"] as const).map((s) => (
                <div className="kpi" key={s}>
                  <div className="k">{REQUIREMENT_LABELS[s]}</div>
                  <div className="v">{pack.summary[s]}</div>
                </div>
              ))}
            </div>
            <p className="small muted mt">
              {(["product", "customer", "organisational"] as const).map((a) => `${APPLICABILITY_LABELS[a]}: ${pack.summary.byApplicability[a].total}`).join(" · ")}
            </p>
          </div>
          <div className="panel mt">
            <div className="flex">
              <div className="seg" aria-label="Who does it" data-ui="pack-filter-who">
                {WHO.map((w) => (
                  <button key={w} type="button" className={who === w ? "primary" : ""} onClick={() => setWho(w)}>
                    {w === "all" ? "Everyone" : APPLICABILITY_LABELS[w]}
                  </button>
                ))}
              </div>
              <div className="seg" aria-label="Status" data-ui="pack-filter-status">
                {STATUS_FILTERS.map((f) => (
                  <button key={f.key} type="button" className={filter === f.key ? "primary" : ""} onClick={() => setFilter(f.key)}>
                    {f.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="tw mt">
              <table data-ui="pack-requirements">
                <thead>
                  <tr>
                    <th>Requirement</th>
                    <th>Who</th>
                    <th>Status</th>
                    <th>Hawk AI controls now</th>
                    <th>Next step</th>
                  </tr>
                </thead>
                <tbody>
                  {items.map((item) => {
                    const fix = fixFor(item);
                    return (
                      <tr key={item.id} data-requirement={item.id}>
                        <td>
                          <b>{item.id}</b> {item.title}
                          {item.note ? <span className="sub small muted">{item.note}</span> : null}
                        </td>
                        <td className="small nowrap">{APPLICABILITY_LABELS[item.applicability]}</td>
                        <td className="nowrap">
                          <span className={`chip ${REQUIREMENT_CHIP[item.status]}`}>
                            <i />
                            {REQUIREMENT_LABELS[item.status]}
                          </span>
                          <span className="sub small muted">{item.why}</span>
                        </td>
                        <td className="small">
                          {item.controls.length ? (
                            <ul className="small">
                              {item.controls.map((c) => (
                                <li key={c.id}>
                                  <span className={`chip ${CONTROL_CHIP[c.status]}`}>
                                    <i />
                                    {CONTROL_LABELS[c.status]}
                                  </span>{" "}
                                  <b>{c.title}</b> — {c.reason}
                                </li>
                              ))}
                            </ul>
                          ) : (
                            <span className="muted">No Hawk AI control: your organisation&apos;s own process.</span>
                          )}
                        </td>
                        <td className="small">
                          {fix ? (
                            <Link href={fix.href} data-ui="pack-fix">
                              {fix.label}
                            </Link>
                          ) : null}
                          {item.controls.some((c) => c.planned && c.status !== "met") ? <span className="sub muted">Part of it is not built yet.</span> : null}
                          {pack.mayRecord ? (
                            <button className="btn ghost mt" type="button" onClick={() => setOpen(open === item.id ? "" : item.id)} data-ui="pack-record">
                              {item.attestation ? "Change the record" : "Record"}
                            </button>
                          ) : null}
                          {item.attestation ? (
                            <span className="sub muted">
                              Recorded by {item.attestation.by || "an administrator"}
                              {item.attestation.reference ? ` (${item.attestation.reference})` : ""}
                              {item.attestation.current ? "" : " — due for review"}
                            </span>
                          ) : null}
                          {open === item.id ? (
                            <RecordForm
                              pack={pack}
                              item={item}
                              onSaved={(next) => {
                                showPack(next);
                                setOpen("");
                              }}
                            />
                          ) : null}
                        </td>
                      </tr>
                    );
                  })}
                  {!items.length ? (
                    <tr>
                      <td colSpan={5} className="muted">
                        Nothing matches these filters.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </div>
          <div className="grid g2 mt">
            <div className="panel">
              <h2>Signed evidence</h2>
              <p className="small muted">
                One zip for this pack: each requirement&apos;s status, the controls behind it, the settings in force, the audit entries of the window (with their sequence numbers and MACs), licence acceptances, AI approvals and inventory, and your records, with a manifest of every file&apos;s SHA-256 signed by this installation&apos;s evidence key. Never passwords, secrets or prompt text. The last 30 days by default, at most a year.
              </p>
              <div className="flex">
                <label className="f">
                  From
                  <input type="date" value={from} onChange={(e) => setFrom(e.target.value)} />
                </label>
                <label className="f">
                  To
                  <input type="date" value={to} onChange={(e) => setTo(e.target.value)} />
                </label>
              </div>
              {pack.mayExport ? (
                <button className="btn mt" type="button" disabled={busy} onClick={download} data-ui="pack-evidence">
                  Download signed evidence
                </button>
              ) : (
                <p className="small muted">People who may export the audit log download it.</p>
              )}
              <p className="small muted mt">
                Check it offline: unzip, then <span className="mono">python3 tools/verify_evidence.py manifest.json --keys hawk-evidence-keys.json</span>.
              </p>
            </div>
            <div className="panel">
              <h2>Sources and notes</h2>
              <ul className="small">
                {pack.sources.map((s) => (
                  <li key={s.url}>
                    <a href={s.url} target="_blank" rel="noreferrer noopener">
                      {s.title}
                    </a>
                  </li>
                ))}
              </ul>
              {pack.notes.map((n) => (
                <p className="small" key={n.id}>
                  <b>{n.title}.</b> {n.text}
                </p>
              ))}
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}
