"use client";

import { useRef, useState } from "react";

import { api } from "@/lib/api";
import { errorMessageFrom, LICENCE_FILE_EXTENSION, licenceFileProblem } from "@/lib/licence";
import type { LicenceImported } from "@/lib/licence";

/**
 * What Settings → Licence and the deactivation page share (/settings/guide/licence): the installation ID with a copy
 * button, the licence request to download and send to the owner of Hawk AI, and the upload of the .hawkai licence.
 */

/** Copy text: the clipboard where the page may use it (HTTPS), else the selection (plain http, older Safari). */
async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    // Refused: fall back to the selection.
  }
  const area = document.createElement("textarea");
  area.value = text;
  area.setAttribute("readonly", "");
  area.style.position = "fixed";
  area.style.opacity = "0";
  document.body.appendChild(area);
  area.select();
  let copied = false;
  try {
    copied = document.execCommand("copy");
  } catch {
    copied = false;
  }
  document.body.removeChild(area);
  return copied;
}

/** Save a file the API sent (attached to the page first, as Firefox wants). */
export function saveBlob(blob: Blob, name: string) {
  const link = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: name });
  link.style.display = "none";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
}

export function InstallationId({ id }: { id: string }) {
  const [copied, setCopied] = useState("");
  if (!id) return null;
  return (
    <div data-ui="installation-id" className="min-w-0">
      <div className="text-xs text-slate-400">Installation ID</div>
      <div className="mt-1 flex flex-wrap items-center gap-2">
        <code className="min-w-0 break-all rounded-md border border-white/[0.1] bg-[#07090d] px-2.5 py-1.5 font-mono text-sm text-slate-100 select-all">{id}</code>
        <button
          type="button"
          onClick={async () => setCopied((await copyText(id)) ? "Copied" : "Select it and copy")}
          className="min-h-[34px] rounded-lg border border-white/[0.12] px-3 text-sm font-semibold text-slate-200 hover:bg-white/[0.06]"
        >
          Copy
        </button>
        <span role="status" aria-live="polite" className="text-xs text-emerald-400">
          {copied}
        </span>
      </div>
    </div>
  );
}

export function LicenceRequestButton({ installationId }: { installationId: string }) {
  const [problem, setProblem] = useState("");
  const [busy, setBusy] = useState(false);
  async function download() {
    setBusy(true);
    setProblem("");
    try {
      saveBlob(await api.downloadLicenceRequest(), `hawk-ai-${installationId || "installation"}.hawkai-request`);
    } catch (error) {
      setProblem(errorMessageFrom(error instanceof Error ? error.message : "", "The licence request could not be downloaded."));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="min-w-0">
      <button
        type="button"
        data-ui="licence-request"
        onClick={download}
        disabled={busy}
        className="min-h-[38px] rounded-lg border border-white/[0.12] px-4 text-sm font-semibold text-slate-200 hover:bg-white/[0.06] disabled:opacity-60"
      >
        Download licence request
      </button>
      {problem ? <p className="mt-1.5 text-[13px] text-red-400">{problem}</p> : null}
    </div>
  );
}

export function LicenceUpload({ onImported }: { onImported: (result: LicenceImported) => void }) {
  const input = useRef<HTMLInputElement>(null);
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [status, setStatus] = useState<{ text: string; kind: "" | "ok" | "error" }>({ text: "", kind: "" });

  async function upload(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const problem = licenceFileProblem(file);
    if (problem || !file) {
      setStatus({ text: problem, kind: "error" });
      return;
    }
    setBusy(true);
    setStatus({ text: "Checking the licence…", kind: "" });
    try {
      const result = await api.importLicence(file);
      setStatus({ text: `Imported: ${result.imported}.`, kind: "ok" });
      setFile(null);
      if (input.current) input.current.value = "";
      onImported(result);
    } catch (error) {
      setStatus({ text: errorMessageFrom(error instanceof Error ? error.message : ""), kind: "error" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={upload} data-ui="licence-upload" className="min-w-0">
      <label htmlFor="licence-file" className="block text-xs text-slate-400">
        Licence file (.hawkai)
      </label>
      <div className="mt-1.5 flex flex-wrap items-center gap-2.5">
        <input
          ref={input}
          id="licence-file"
          name="file"
          type="file"
          accept={LICENCE_FILE_EXTENSION}
          onChange={(event) => {
            setFile(event.target.files?.[0] ?? null);
            setStatus({ text: "", kind: "" });
          }}
          className="block w-full min-w-0 max-w-full text-sm text-slate-300 file:mr-3 file:min-h-[34px] file:rounded-lg file:border file:border-solid file:border-white/[0.12] file:bg-transparent file:px-3 file:text-sm file:font-semibold file:text-slate-200 sm:w-auto"
        />
        <button
          type="submit"
          disabled={busy}
          className="min-h-[38px] rounded-lg bg-brand-500 px-4 text-sm font-semibold text-black disabled:opacity-60"
        >
          Upload .hawkai licence
        </button>
      </div>
      <p
        role="status"
        aria-live="polite"
        className={`mt-2 min-h-5 break-words text-[13.5px] ${status.kind === "error" ? "text-red-400" : status.kind === "ok" ? "text-emerald-400" : "text-slate-400"}`}
      >
        {status.text}
      </p>
    </form>
  );
}
