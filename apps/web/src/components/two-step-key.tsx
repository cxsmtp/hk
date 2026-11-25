"use client";

import { useMemo, useState } from "react";

import { qrSvgPath } from "@/lib/qr";
import type { TwoStepSetup } from "@/lib/sign-in";

/**
 * The key for an authenticator app (CxMissionZero's showTwoStepKey): as a QR code made here in the page (qr.mjs:
 * nothing is fetched), and as text with a Copy button for a phone that cannot scan it.
 */
export function TwoStepKey({ setup }: { setup: TwoStepSetup }) {
  const [copied, setCopied] = useState("");
  const qr = useMemo(() => {
    try {
      return qrSvgPath(setup.otpauth);
    } catch {
      // Too long for a QR code made here (a very long email address): the key below does the same.
      return null;
    }
  }, [setup.otpauth]);
  async function copy() {
    try {
      await navigator.clipboard.writeText(setup.secret);
      setCopied("Copied.");
    } catch {
      setCopied("Could not copy: select the text and copy it.");
    }
  }
  return (
    <div className="twostep-key" data-ui="two-step-key">
      {qr ? (
        <div className="twostep-qr">
          <svg viewBox={qr.viewBox} role="img" aria-label="QR code for your authenticator app" shapeRendering="crispEdges">
            <path d={qr.d} fill="#000" />
          </svg>
        </div>
      ) : null}
      <div className="twostep-key-text">
        <span className="muted small">The key, if you cannot scan the code:</span>
        <code translate="no">{setup.key}</code>
        <span className="flex">
          <button type="button" className="sm" onClick={copy}>
            Copy the key
          </button>
          <span className="small muted" aria-live="polite">
            {copied}
          </span>
        </span>
      </div>
    </div>
  );
}

/** Recovery codes, shown once: a list, and a Copy button. */
export function RecoveryCodes({ codes }: { codes: string[] }) {
  const [copied, setCopied] = useState("");
  async function copy() {
    try {
      await navigator.clipboard.writeText(codes.join("\n"));
      setCopied("Copied.");
    } catch {
      setCopied("Could not copy: select the text and copy it.");
    }
  }
  return (
    <div data-ui="recovery-codes">
      <ul className="recovery-codes" translate="no">
        {codes.map((code) => (
          <li key={code}>{code}</li>
        ))}
      </ul>
      <div className="flex">
        <button type="button" className="sm" onClick={copy}>
          Copy the codes
        </button>
        <span className="small muted" aria-live="polite">
          {copied}
        </span>
      </div>
    </div>
  );
}
