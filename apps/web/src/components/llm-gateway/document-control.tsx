"use client";

import { FormEvent, useEffect, useState } from "react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { loadGatewayChoiceLists, loadGatewayPolicyVersions } from "@/components/llm-gateway/document-control-load-state.mjs";
import type { GatewayListStatus } from "@/components/llm-gateway/document-control-load-state.mjs";
import { api } from "@/lib/api";
import type { AISystem, PolicyPack, PolicyVersion } from "@/lib/types";

const MAX_DOCUMENT_BYTES = 10 * 1024 * 1024;
const PDF_MEDIA_TYPE = "application/pdf";
const DOCX_MEDIA_TYPE = "application/vnd.openxmlformats-officedocument.wordprocessingml.document";

const DOCUMENT_ERROR_COPY: Record<string, string> = {
  unsupported_file_type: "Choose a PDF or DOCX file.",
  unsupported_document_type: "This file format is not supported. Choose a PDF or DOCX file.",
  unsupported_document_format: "This file format is not supported. Choose a PDF or DOCX file.",
  file_type_mismatch: "The file content does not match its PDF or DOCX filename.",
  document_too_large: "This file exceeds the 10 MiB upload limit.",
  document_size_limit_exceeded: "This file exceeds the size limit for the selected policy.",
  document_size_limit: "This document exceeds the size limit configured by the policy.",
  encrypted_pdf: "Password-protected PDFs are unsupported.",
  encrypted_docx: "Password-protected DOCX files are unsupported.",
  encrypted_document: "Password-protected documents are unsupported.",
  password_protected_document: "Password-protected documents are unsupported.",
  scanned_pdf: "Scanned or image-only PDFs are unsupported.",
  image_only_pdf: "Scanned or image-only PDFs are unsupported.",
  scanned_or_image_only_pdf: "Scanned or image-only PDFs are unsupported.",
  macro_enabled_docx: "Macro-enabled Office files are unsupported.",
  malformed_document: "This file could not be read as a valid PDF or DOCX document.",
  document_page_limit_exceeded: "This PDF exceeds the page limit configured by the policy.",
  document_page_limit: "This PDF exceeds the page limit configured by the policy.",
  document_text_limit: "This document exceeds the text limit configured by the policy.",
  document_text_unrenderable: "Some characters cannot be preserved in PDF output. Try DOCX output instead.",
  document_block_limit: "This document exceeds the supported content-block limit.",
  invalid_pdf_document: "This file could not be read as a valid PDF document.",
  invalid_docx_document: "This file could not be read as a valid DOCX document.",
  unsupported_document_content: "This document contains content the pilot cannot safely process.",
  invalid_document_archive: "This DOCX file is malformed or could not be safely inspected.",
  unsafe_document_archive: "This DOCX archive contains unsupported or unsafe content.",
  document_structure_changed: "The returned document did not preserve the required structure. No file was downloaded.",
  document_block_limit_exceeded: "This document exceeds the supported content-block limit.",
  response_not_allowed: "Gateway controls did not allow a downloadable document.",
  invalid_document_response: "The gateway returned an invalid document response. No file was downloaded.",
  document_response_too_large: "The generated document exceeds the 10 MiB download limit.",
};
type ChoiceStatus = GatewayListStatus | "loading";

function fileReadyForMode(mode: "draft" | "transform", file: File | null): boolean {
  return mode === "draft" || Boolean(file);
}

function inputLabel(className = "text-xs uppercase tracking-[0.08em] text-slate-500") {
  return className;
}

function safeDownloadName(value: string, format: "pdf" | "docx"): string {
  const stem = value
    .replace(/[\\/:*?"<>|\u0000-\u001f]/g, "-")
    .replace(/\.(pdf|docx)$/i, "")
    .trim()
    .slice(0, 100) || "gateway-document";
  return `${stem}.${format}`;
}

function decodeAllowedDocument(
  response: Awaited<ReturnType<typeof api.llmGatewayDocumentComplete>>,
  expectedFormat: "pdf" | "docx",
): Blob {
  const decision = String(response?.hawk?.final_decision || "").toLowerCase();
  if (!response?.hawk?.provider_invoked || (decision !== "allow" && decision !== "warn")) {
    throw new Error("response_not_allowed");
  }
  const expectedMediaType = expectedFormat === "pdf" ? PDF_MEDIA_TYPE : DOCX_MEDIA_TYPE;
  const encoded = response.content_base64;
  if (response.document?.format !== expectedFormat || response.media_type !== expectedMediaType) {
    throw new Error("invalid_document_response");
  }
  if (!encoded || encoded.length > Math.ceil(MAX_DOCUMENT_BYTES * 4 / 3) + 8 || encoded.length % 4 !== 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(encoded)) {
    throw new Error("invalid_document_response");
  }
  let binary: string;
  try {
    binary = window.atob(encoded);
  } catch {
    throw new Error("invalid_document_response");
  }
  if (!binary.length || binary.length > MAX_DOCUMENT_BYTES) throw new Error("document_response_too_large");
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
  return new Blob([bytes], { type: expectedMediaType });
}

export function DocumentControl() {
  const [systems, setSystems] = useState<AISystem[]>([]);
  const [packs, setPacks] = useState<PolicyPack[]>([]);
  const [versions, setVersions] = useState<PolicyVersion[]>([]);
  const [systemsStatus, setSystemsStatus] = useState<ChoiceStatus>("loading");
  const [packsStatus, setPacksStatus] = useState<ChoiceStatus>("loading");
  const [versionsStatus, setVersionsStatus] = useState<ChoiceStatus>("loading");
  const [retryChoices, setRetryChoices] = useState(0);
  const [retryVersions, setRetryVersions] = useState(0);
  const [aiSystemId, setAiSystemId] = useState("");
  const [packId, setPackId] = useState("");
  const [policyVersionId, setPolicyVersionId] = useState("");
  const [provider, setProvider] = useState("openai");
  const [model, setModel] = useState("");
  const [mode, setMode] = useState<"draft" | "transform">("draft");
  const [outputFormat, setOutputFormat] = useState<"pdf" | "docx">("docx");
  const [instruction, setInstruction] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [lastMetadata, setLastMetadata] = useState<{
    format: "pdf" | "docx";
    pageCount: number | null;
    blockCount: number;
    masking?: { applied: boolean; restored: boolean; entityTypeCounts: Record<string, number> };
  } | null>(null);

  useEffect(() => {
    let current = true;
    setSystemsStatus("loading");
    setPacksStatus("loading");
    loadGatewayChoiceLists(api.listAISystems, api.listPolicyPacks).then(({ systems: systemsResult, packs: packsResult }) => {
      if (!current) return;
      const nextSystems = systemsResult.items;
      const nextPacks = packsResult.items;
      setSystems(nextSystems);
      setPacks(nextPacks);
      setSystemsStatus(systemsResult.status);
      setPacksStatus(packsResult.status);
      setAiSystemId((selected) => nextSystems.some((item) => item.id === selected) ? selected : nextSystems[0]?.id || "");
      const activePack = nextPacks.find((item) => item.status.toLowerCase() === "active") || nextPacks[0];
      setPackId((selected) => nextPacks.some((item) => item.id === selected) ? selected : activePack?.id || "");
    });
    return () => { current = false; };
  }, [retryChoices]);

  useEffect(() => {
    let current = true;
    setVersions([]);
    setPolicyVersionId("");
    if (!packId) {
      setVersionsStatus("empty");
      return () => { current = false; };
    }
    setVersionsStatus("loading");
    loadGatewayPolicyVersions(api.listPolicyVersions, packId).then((result) => {
      if (!current) return;
      setVersions(result.items);
      setVersionsStatus(result.status);
      setPolicyVersionId(result.items[0]?.id || "");
    });
    return () => { current = false; };
  }, [packId, retryVersions]);

  function selectFile(next: File | null, input?: HTMLInputElement) {
    if (!next) {
      setFile(null);
      return;
    }
    const extensionMatches = /\.(pdf|docx)$/i.test(next.name);
    const supportedMime = !next.type || next.type === PDF_MEDIA_TYPE || next.type === DOCX_MEDIA_TYPE;
    if (!extensionMatches || !supportedMime) {
      setFile(null);
      if (input) input.value = "";
      toast.error(DOCUMENT_ERROR_COPY.unsupported_file_type);
      return;
    }
    if (next.size > MAX_DOCUMENT_BYTES) {
      setFile(null);
      if (input) input.value = "";
      toast.error(DOCUMENT_ERROR_COPY.document_too_large);
      return;
    }
    setFile(next);
  }

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!aiSystemId || !policyVersionId || !instruction.trim()) {
      toast.error("Select an AI system and policy version, then add an instruction.");
      return;
    }
    if (mode === "transform" && !file) {
      toast.error("Choose a PDF or DOCX file to transform.");
      return;
    }
    if (mode === "draft" && file) {
      toast.error("Remove the upload before creating a new document.");
      return;
    }

    setSubmitting(true);
    setLastMetadata(null);
    try {
      const response = await api.llmGatewayDocumentComplete({
        mode,
        output_format: outputFormat,
        ai_system_id: aiSystemId,
        policy_version_id: policyVersionId,
        provider,
        model,
        instruction: instruction.trim(),
        ...(mode === "transform" && file ? { file } : {}),
      });
      const blob = decodeAllowedDocument(response, outputFormat);
      const url = URL.createObjectURL(blob);
      const anchor = document.createElement("a");
      anchor.href = url;
      anchor.download = safeDownloadName(response.file_name, outputFormat);
      document.body.appendChild(anchor);
      anchor.click();
      anchor.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
      const masking = response.hawk.reversible_masking;
      setLastMetadata({
        format: response.document.format,
        pageCount: response.document.page_count,
        blockCount: response.document.block_count,
        masking: masking ? {
          applied: masking.applied,
          restored: masking.restored,
          entityTypeCounts: masking.entity_type_counts,
        } : undefined,
      });
      toast.success(`Downloaded ${response.document.format.toUpperCase()} document after ${response.hawk.final_decision} controls.`);
    } catch (error) {
      const code = error instanceof Error ? error.message : "document_request_failed";
      toast.error(DOCUMENT_ERROR_COPY[code] || code, { description: DOCUMENT_ERROR_COPY[code] ? code : undefined });
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="rounded-xl border border-cyan-300/15 bg-[#0b111a] p-4 md:p-5">
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div>
          <p className="font-mono text-[10px] uppercase tracking-[0.18em] text-cyan-200/70">Document gateway · pilot</p>
          <h3 className="mt-1 text-base font-semibold text-slate-100">Create or transform a document</h3>
          <p className="mt-1 max-w-3xl text-xs leading-5 text-slate-400">Text-based PDF and DOCX only, up to 10 MiB. Scanned/image-only and encrypted files are unsupported. PDF pages may reflow; exact layout is not guaranteed.</p>
        </div>
        <span className="rounded border border-amber-300/20 bg-amber-300/[0.06] px-2 py-1 font-mono text-[9px] uppercase tracking-[0.12em] text-amber-100/80">Synchronous · no streaming</span>
      </div>

      <form className="space-y-4" onSubmit={submit}>
        <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
          <div className="space-y-2">
            <label className={inputLabel()} htmlFor="gateway-document-mode">Operation</label>
            <select id="gateway-document-mode" className="h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100" value={mode} onChange={(event) => { setMode(event.target.value as "draft" | "transform"); if (event.target.value === "draft") setFile(null); }}>
              <option value="draft">Create new</option>
              <option value="transform">Transform upload</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className={inputLabel()} htmlFor="gateway-document-format">Output format</label>
            <select id="gateway-document-format" className="h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100" value={outputFormat} onChange={(event) => setOutputFormat(event.target.value as "pdf" | "docx")}>
              <option value="pdf">PDF</option>
              <option value="docx">DOCX</option>
            </select>
          </div>
          {mode === "transform" ? (
            <div className="space-y-2">
              <label className={inputLabel()} htmlFor="gateway-document-file">PDF or DOCX upload</label>
              <Input id="gateway-document-file" type="file" accept=".pdf,.docx,application/pdf,application/vnd.openxmlformats-officedocument.wordprocessingml.document" className="h-auto cursor-pointer bg-slate-950 p-1 text-slate-200 file:mr-3 file:rounded file:border-0 file:bg-cyan-300/10 file:px-3 file:py-1.5 file:text-xs file:font-semibold file:text-cyan-100 focus-visible:ring-cyan-300/70" onChange={(event) => selectFile(event.target.files?.[0] || null, event.currentTarget)} />
              <p className="text-[11px] text-slate-500">Maximum 10 MiB. Password-protected and legacy .doc files are unsupported.</p>
            </div>
          ) : null}
          <div className="space-y-2">
            <label className={inputLabel()} htmlFor="gateway-document-system">AI system</label>
            <select id="gateway-document-system" disabled={systemsStatus !== "ready"} className="h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 disabled:opacity-50" value={aiSystemId} onChange={(event) => setAiSystemId(event.target.value)}>
              <option value="">Select an AI system</option>
              {systems.map((system) => <option key={system.id} value={system.id}>{system.name}</option>)}
            </select>
          </div>
          <div className="space-y-2">
            <label className={inputLabel()} htmlFor="gateway-document-pack">Policy pack</label>
            <select id="gateway-document-pack" disabled={packsStatus !== "ready"} className="h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 disabled:opacity-50" value={packId} onChange={(event) => { setVersionsStatus("loading"); setVersions([]); setPolicyVersionId(""); setPackId(event.target.value); }}>
              <option value="">Select a policy pack</option>
              {packs.map((pack) => <option key={pack.id} value={pack.id}>{pack.name} · {pack.status}</option>)}
            </select>
          </div>
          <div className="space-y-2">
            <label className={inputLabel()} htmlFor="gateway-document-version">Policy version</label>
            <select id="gateway-document-version" disabled={versionsStatus !== "ready"} className="h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100 disabled:opacity-50" value={policyVersionId} onChange={(event) => setPolicyVersionId(event.target.value)}>
              <option value="">Select a policy version</option>
              {versions.map((version) => <option key={version.id} value={version.id}>{version.version}</option>)}
            </select>
          </div>
          <div className="space-y-2">
            <label className={inputLabel()} htmlFor="gateway-document-provider">Provider</label>
            <select id="gateway-document-provider" className="h-10 w-full rounded-md border border-slate-700 bg-slate-950 px-3 text-sm text-slate-100" value={provider} onChange={(event) => setProvider(event.target.value)}>
              <option value="openai">OpenAI</option><option value="anthropic">Anthropic</option><option value="gemini">Gemini</option><option value="mistral">Mistral</option><option value="ollama">Ollama</option><option value="azure_openai">Azure OpenAI</option><option value="custom">Custom</option><option value="local">Local</option><option value="oss">OSS</option>
            </select>
          </div>
          <div className="space-y-2">
            <label className={inputLabel()} htmlFor="gateway-document-model">Model <span className="normal-case tracking-normal">(optional)</span></label>
            <Input id="gateway-document-model" value={model} onChange={(event) => setModel(event.target.value)} maxLength={120} placeholder="Provider default" />
          </div>
        </div>

        <div className="space-y-2">
          <label className={inputLabel()} htmlFor="gateway-document-instruction">Instruction</label>
          <textarea id="gateway-document-instruction" value={instruction} onChange={(event) => setInstruction(event.target.value)} maxLength={12000} rows={4} required className="w-full resize-y rounded-md border border-slate-700 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none focus:border-cyan-300/50" placeholder={mode === "draft" ? "Describe the document to create…" : "Describe how to transform the uploaded document…"} />
          <p className="text-right text-[10px] text-slate-600">{instruction.length.toLocaleString()} / 12,000 characters</p>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <Button type="submit" disabled={submitting || systemsStatus !== "ready" || packsStatus !== "ready" || versionsStatus !== "ready" || !aiSystemId || !policyVersionId || !fileReadyForMode(mode, file)}>
            {submitting ? "Applying gateway controls…" : mode === "draft" ? "Create document" : "Transform and download"}
          </Button>
          {systemsStatus === "error" || packsStatus === "error" ? (
            <div className="flex flex-wrap items-center gap-2 text-xs text-rose-200" role="alert">
              <span>{systemsStatus === "error" && packsStatus === "error" ? "Could not load AI systems or policy packs." : systemsStatus === "error" ? "Could not load AI systems." : "Could not load policy packs."} Retry to continue.</span>
              <Button type="button" size="sm" variant="outline" onClick={() => { setRetryChoices((attempt) => attempt + 1); setRetryVersions((attempt) => attempt + 1); }}>Retry</Button>
            </div>
          ) : null}
          {systemsStatus === "loading" || packsStatus === "loading" || versionsStatus === "loading" ? <span role="status" className="text-xs text-slate-400">Loading tenant systems and policy versions…</span> : null}
          {systemsStatus === "empty" ? <span className="text-xs text-amber-200/80">No AI systems are configured for this tenant.</span> : null}
          {packsStatus === "empty" ? <span className="text-xs text-amber-200/80">No policy packs are configured for this tenant.</span> : null}
          {versionsStatus === "error" && packId ? (
            <div className="flex flex-wrap items-center gap-2 text-xs text-rose-200" role="alert">
              <span>Could not load versions for this policy pack.</span>
              <Button type="button" size="sm" variant="outline" onClick={() => setRetryVersions((attempt) => attempt + 1)}>Retry versions</Button>
            </div>
          ) : null}
          {versionsStatus === "empty" && packId && packsStatus === "ready" ? <span className="text-xs text-amber-200/80">No policy versions are available for this pack.</span> : null}
          {systemsStatus === "ready" && packsStatus === "ready" && versionsStatus === "ready" ? <span className="text-xs text-slate-500">Choose the existing AI system and policy version for this request.</span> : null}
        </div>
      </form>

      {lastMetadata ? (
        <div className="mt-4 rounded-lg border border-emerald-300/15 bg-emerald-300/[0.035] p-3" aria-live="polite">
          <p className="text-xs font-semibold text-emerald-100">Allowed document returned</p>
          <p className="mt-1 text-xs text-slate-400">{lastMetadata.format.toUpperCase()} · {lastMetadata.pageCount === null ? "page count unavailable" : `${lastMetadata.pageCount} pages`} · {lastMetadata.blockCount} content blocks</p>
          {lastMetadata.masking ? <p className="mt-1 text-xs text-slate-400">Masking applied: {lastMetadata.masking.applied ? "yes" : "no"} · values restored: {lastMetadata.masking.restored ? "yes" : "no"} · entity counts: {Object.entries(lastMetadata.masking.entityTypeCounts).map(([type, count]) => `${type} ${count}`).join(", ") || "0"}</p> : null}
        </div>
      ) : null}
    </div>
  );
}
