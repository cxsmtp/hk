"use client";

import "../ftr-settings.css";

import Link from "next/link";
import { useEffect, useRef, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { GUIDE_HREF } from "@/lib/guide";
import { errorMessageFrom } from "@/lib/licence";
import type { SupportChannel } from "@/lib/records";

const message = (error: unknown) => errorMessageFrom(error instanceof Error ? error.message : String(error ?? ""), "Something went wrong.");

/**
 * Settings → Get help, laid out and worded as FTR Command Center's (public/js/settings.js `help()`): saved as it
 * changes, the address requests go to. With CxMissionZero's choice of the support portal here or plain email for an
 * offline installation (/settings/guide/self-check-and-help), which FTR's page offered at CC-01.50.00. Owners and admins only.
 */
export default function GetHelpSettingsPage() {
  const [channel, setChannel] = useState<SupportChannel | null>(null);
  const [mode, setMode] = useState<"portal" | "email">("portal");
  const [email, setEmail] = useState("");
  const [saved, setSaved] = useState<{ text: string; bad: boolean }>({ text: "All changes are saved.", bad: false });
  const [loadError, setLoadError] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    api
      .getSupportSettings()
      .then((c) => {
        setChannel(c);
        setMode(c.chosen ?? c.mode);
        setEmail(c.email);
      })
      .catch((error) => setLoadError(message(error)));
  }, []);

  function save(next: { mode: "portal" | "email"; email: string }, delay = 600) {
    if (timer.current) clearTimeout(timer.current);
    setSaved({ text: "Saving…", bad: false });
    timer.current = setTimeout(async () => {
      try {
        const c = await api.saveSupportSettings(next);
        setChannel(c);
        setSaved({ text: "All changes are saved.", bad: false });
      } catch (error) {
        setSaved({ text: message(error), bad: true });
      }
    }, delay);
  }

  return (
    <AppShell>
      <div className="ftr-settings" data-ui="settings-help">
        <div className="head compact">
          <div className="ht">
            <h1 className="serif">Get help</h1>
            <span className="crumbs">for this organisation · Owners and admins only</span>
          </div>
          <Link className="btn ghost" href={GUIDE_HREF} data-guide-link>
            Administrator&apos;s guide
          </Link>
        </div>
        <div id="tab">
          {loadError ? (
            <div className="panel">
              <div className="empty">
                <b>{loadError}</b>
              </div>
            </div>
          ) : null}
          {!channel && !loadError ? <p className="muted">Loading…</p> : null}
          {channel ? (
            <>
              <div className="saved-banner">✓ Changes save as you type.</div>
              <div className="panel">
                <h2>
                  Get help <small>where the support cases and enhancement requests people send from Get help go</small>
                </h2>
                <form className="form" id="supf" autoComplete="off" onSubmit={(event) => event.preventDefault()}>
                  <label className="check">
                    <input
                      type="radio"
                      name="mode"
                      value="portal"
                      checked={mode === "portal"}
                      onChange={() => {
                        setMode("portal");
                        save({ mode: "portal", email }, 0);
                      }}
                    />
                    <span>
                      <b>Support portal in Hawk AI</b>
                      <small>A form, a numbered queue (SUP-0001, ENH-0001) and email updates. The organisation&apos;s owners and admins answer them here.</small>
                    </span>
                  </label>
                  <label className="check">
                    <input
                      type="radio"
                      name="mode"
                      value="email"
                      checked={mode === "email"}
                      onChange={() => {
                        setMode("email");
                        save({ mode: "email", email }, 0);
                      }}
                    />
                    <span>
                      <b>Email</b>
                      <small>Get help opens each person&apos;s own email app, addressed to the address below, with the details filled in. For a server that cannot send email out of its network.</small>
                    </span>
                  </label>
                  <label className="f">
                    Send requests to
                    <input
                      type="email"
                      name="email"
                      value={email}
                      placeholder="support@company.com"
                      onChange={(event) => {
                        setEmail(event.target.value);
                        save({ mode, email: event.target.value });
                      }}
                    />
                  </label>
                  <p className="muted small">
                    In the portal, each request and every answer is emailed through the email server (Settings → Email (SMTP), once tested); until it is set up and tested, requests are kept and the page says the email did not go. By email, nothing is stored in Hawk AI and the conversation carries on by email; requests raised in the portal before can still be read and answered. Until a valid address is entered, Get help stays on the portal. SUPPORT_MODE=email and SUPPORT_EMAIL set the default when the server starts; a choice made here wins over them.
                  </p>
                </form>
                <div className={`saved-foot${saved.bad ? " bad" : ""}`} id="supsaved" role="status">
                  {saved.text}
                </div>
              </div>
            </>
          ) : null}
        </div>
      </div>
    </AppShell>
  );
}
