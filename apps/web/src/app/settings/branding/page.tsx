"use client";

import "../ftr-settings.css";

import { ShieldCheck } from "lucide-react";
import { useEffect, useRef, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { errorMessageFrom } from "@/lib/licence";
import { brandingImage, fileToBase64, setBranding } from "@/lib/settings-console";
import type { BrandingPatch, BrandingView } from "@/lib/settings-console";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");
const MODES = ["light", "dark", "system"] as const;
const ACCEPT = "image/png,image/jpeg,image/svg+xml,image/webp";
type Text = "appName" | "tagline" | "organisationName";

/**
 * Settings → Branding, laid out and worded as FTR Command Center's (public/js/settings.js `branding()`): saved as it
 * changes (names after a pause, a choice at once), a refused change putting back the last saved one. The logo (up to
 * 200 KB) and the browser icon (up to 100 KB) are uploaded and kept on the server; the name and logo head the menu
 * and every email, the icon is the browser tab's, and the look is everyone's.
 */
export default function BrandingSettingsPage() {
  const [good, setGood] = useState<BrandingView | null>(null);
  const [text, setText] = useState<Record<Text, string>>({ appName: "", tagline: "", organisationName: "" });
  const [saved, setSaved] = useState<{ text: string; bad: boolean }>({ text: "All changes are saved.", bad: false });
  const [loadError, setLoadError] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    api
      .getBranding()
      .then((b) => {
        setGood(b);
        setText({ appName: b.appName, tagline: b.tagline, organisationName: b.organisationName });
      })
      .catch((error) => setLoadError(message(error)));
  }, []);

  async function save(patch: BrandingPatch): Promise<boolean> {
    setSaved({ text: "Saving…", bad: false });
    try {
      const b = await api.saveBranding(patch);
      setGood(b);
      setBranding(b);
      setSaved({ text: `All changes are saved ✓ ${new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}`, bad: false });
      return true;
    } catch (error) {
      // Refused: the last good setting stays, and the page shows it again.
      setSaved({ text: `${message(error)} The last saved setting is kept.`, bad: true });
      if (good) setText({ appName: good.appName, tagline: good.tagline, organisationName: good.organisationName });
      return false;
    }
  }

  function typed(name: Text, value: string) {
    setText((current) => ({ ...current, [name]: value }));
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(() => void save({ [name]: value }), 600);
  }

  async function upload(key: "logo" | "icon", file: File | undefined) {
    if (!file || !good) return;
    const limit = good.limits[key];
    if (file.size > limit) {
      setSaved({ text: `${file.name} is ${Math.round(file.size / 1024)} KB: at most ${Math.round(limit / 1024)} KB.`, bad: true });
      return;
    }
    await save({ [key]: { upload: await fileToBase64(file) } });
  }

  const logo = brandingImage(good?.logo ?? null);
  const icon = brandingImage(good?.icon ?? null);

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-branding">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">Branding</h1>
            <span className="crumbs">for the whole of Hawk AI · Owners and admins only</span>
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
          {!good && !loadError ? <p className="muted">Loading…</p> : null}
          {good ? (
            <>
              <div className="saved-banner">✓ Changes save as you type.</div>
              <div className="panel brand-page">
                <h2>Branding</h2>
                <form className="form" id="bf" autoComplete="off" onSubmit={(event) => event.preventDefault()}>
                  <div className="brand-grid">
                    <label className="f">
                      App name
                      <input name="appName" maxLength={40} value={text.appName} onChange={(event) => typed("appName", event.target.value)} />
                    </label>
                    <label className="f">
                      Under the name
                      <input name="tagline" maxLength={40} value={text.tagline} placeholder="AI control plane" onChange={(event) => typed("tagline", event.target.value)} />
                    </label>
                    <label className="f">
                      <span>
                        Company name <small>on every report</small>
                      </span>
                      <input name="organisationName" maxLength={120} value={text.organisationName} onChange={(event) => typed("organisationName", event.target.value)} />
                    </label>
                    {/* FTR keeps the accent colour in the form, hidden: each look has its own. */}
                    <label className="f" hidden>
                      Accent colour
                      <span className="colour">
                        <input type="color" name="accent" defaultValue={good.accent || "#5cb8d0"} onChange={(event) => void save({ accent: event.target.value })} />
                        <span>{good.accent || "From the look"}</span>
                      </span>
                    </label>
                  </div>
                  <div className="brand-grid two">
                    <div className="f">
                      <span>
                        Company logo <small>upload one (PNG, JPEG, SVG or WebP, up to 200 KB)</small>
                      </span>
                      <div className="img-pick">
                        <span className="img-prev" id="logo-prev">
                          {/* eslint-disable-next-line @next/next/no-img-element -- the organisation's own logo, kept on the API */}
                          {logo ? <img src={logo} alt="" /> : <ShieldCheck aria-hidden="true" />}
                        </span>
                        <label className="btn sm">
                          Upload
                          <input type="file" id="logo-file" accept={ACCEPT} hidden onChange={(event) => void upload("logo", event.target.files?.[0])} />
                        </label>
                        {good.logo ? (
                          <button type="button" className="sm ghost" id="logo-rm" onClick={() => void save({ logo: null })}>
                            Remove
                          </button>
                        ) : null}
                      </div>
                    </div>
                    <div className="f">
                      <span>
                        Browser icon <small>upload one (PNG, JPEG, SVG or WebP, up to 100 KB)</small>
                      </span>
                      <div className="img-pick">
                        <span className="img-prev small" id="icon-prev">
                          {/* eslint-disable-next-line @next/next/no-img-element -- the organisation's own icon, kept on the API */}
                          {icon ? <img src={icon} alt="" /> : <ShieldCheck aria-hidden="true" />}
                        </span>
                        <label className="btn sm">
                          Upload
                          <input type="file" id="icon-file" accept={ACCEPT} hidden onChange={(event) => void upload("icon", event.target.files?.[0])} />
                        </label>
                        {good.icon ? (
                          <button type="button" className="sm ghost" id="icon-rm" onClick={() => void save({ icon: null })}>
                            Remove
                          </button>
                        ) : null}
                      </div>
                    </div>
                  </div>
                  <div className="f">
                    <span>
                      Look of the app <small>Everyone&apos;s look: light, dark, or as each person&apos;s device is set.</small>
                    </span>
                  </div>
                  <div className="seg" id="b-modes">
                    {MODES.map((m) => (
                      <button key={m} type="button" data-m={m} className={good.mode === m ? "primary" : ""} onClick={() => void save({ mode: m })}>
                        {m[0].toUpperCase()}
                        {m.slice(1)}
                      </button>
                    ))}
                  </div>
                </form>
              </div>
              <div className={`saved-foot${saved.bad ? " bad" : ""}`} id="bsaved" role="status">
                {saved.text}
              </div>
            </>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
