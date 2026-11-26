"use client";

import "@/styles/ftr.css";

import { useCallback, useEffect, useRef, useState } from "react";

import { AppShell } from "@/components/app-shell";
import { api } from "@/lib/api";
import { autosave, SAVES_AS_YOU_TYPE } from "@/lib/ftr-autosave";
import { domainList, refusalFrom } from "@/lib/sign-in";
import type { SignInSettings } from "@/lib/sign-in";

/**
 * Settings → Single sign-on, for owners and admins (/settings/guide/people-and-access). The page is FTR Command Center's System →
 * Single sign-on (ftr-cc-dashboard public/js/settings.js `sso()`): its two panels, wording, controls and autosave.
 * FTR's is SAML 2.0; Hawk's is OpenID Connect, so the SAML fields (SSO URL, IdP entity ID, signing certificate,
 * attributes, signed response) are replaced by the identity provider's issuer and client id. Those, the button label
 * and the on/off switch are Hawk's configuration (COMPANY_SSO_ENABLED, OIDC_PROVIDERS_JSON, OIDC_PROVIDER_SECRETS_JSON):
 * shown here, changed on the server. FTR's "Their team" has no Hawk counterpart (a provider belongs to one workspace);
 * CxMissionZero's "Email domains allowed" and "must mark the email address as verified" take its place.
 */
export default function SingleSignOnPage() {
  const [view, setView] = useState<SignInSettings | null>(null);
  const [loadError, setLoadError] = useState("");
  const formRef = useRef<HTMLFormElement>(null);
  const statusRef = useRef<HTMLDivElement>(null);

  const load = useCallback(async () => {
    try {
      setView(await api.getSignInSettings());
      setLoadError("");
    } catch (error) {
      setLoadError(refusalFrom(error instanceof Error ? error.message : "", "Single sign-on settings are for owners and admins.").message);
    }
  }, []);

  useEffect(() => {
    load().catch(() => undefined);
  }, [load]);

  const loaded = Boolean(view);
  useEffect(() => {
    const form = formRef.current;
    if (!form || !loaded) return;
    const saver = autosave(
      form,
      async (f) => {
        const data = new FormData(f);
        const body = {
          sso: {
            provision: data.get("jit") === "on" ? "create" : "existing",
            role: data.get("jitRole"),
            domains: domainList(String(data.get("domains") ?? "")),
            requireVerifiedEmail: data.get("requireVerifiedEmail") === "on",
            passwordAdminsOnly: data.get("passwordSignIn") === "admins",
          },
        };
        try {
          setView(await api.saveSignInSettings(body));
        } catch (error) {
          throw new Error(refusalFrom(error instanceof Error ? error.message : "").message);
        }
      },
      { status: statusRef.current },
    );
    return () => saver.stop();
  }, [loaded]);

  const sso = view?.sso;
  const provider = sso?.providers[0];
  const chip = sso?.enabled ? (
    sso.callbackUrl ? (
      <span className="chip ok">
        <i />
        On
      </span>
    ) : (
      <span className="chip warn">
        <i />
        On, but OIDC_CALLBACK_URL is missing
      </span>
    )
  ) : (
    <span className="chip">
      <i />
      Off
    </span>
  );

  return (
    <AppShell>
      <div className="ftr" data-ui="settings-sso">
        <div className="head compact">
          <div className="ht">
            <h1>Single sign-on</h1>
            <span className="crumbs">sign in at your organisation&apos;s identity provider · for the whole installation</span>
          </div>
        </div>
        <div className="saved-banner">{SAVES_AS_YOU_TYPE}</div>
        {loadError ? <div className="callout warn">{loadError}</div> : null}
        {!view && !loadError ? <p className="muted small">Loading…</p> : null}
        {view && sso ? (
          <div className="grid g2">
            <div className="panel">
              <h2>Identity provider (OpenID Connect) {chip}</h2>
              <form className="form" ref={formRef} autoComplete="off">
                <label className="f">
                  Identity provider address (issuer) <span className="muted">set in OIDC_PROVIDERS_JSON</span>
                  <input value={provider?.issuer ?? ""} placeholder="https://login.microsoftonline.com/<tenant>/v2.0" disabled readOnly />
                </label>
                <div className="row">
                  <label className="f">
                    Client id <span className="muted">OIDC_PROVIDERS_JSON</span>
                    <input value={provider?.clientId ?? ""} disabled readOnly />
                  </label>
                  <label className="f">
                    Client secret <span className="muted">OIDC_PROVIDER_SECRETS_JSON</span>
                    <input value={provider ? "(stored)" : "(not set)"} disabled readOnly />
                  </label>
                </div>
                {sso.providers.length > 1 ? (
                  <div className="small muted">
                    {sso.providers.length} identity providers: {sso.providers.map((p) => `${p.label} (${p.workspace})`).join(", ")}
                  </div>
                ) : null}
                <label className="f">
                  Button on the sign-in page <span className="muted">display_name in OIDC_PROVIDERS_JSON</span>
                  <input value={provider ? `Continue with ${provider.label}` : ""} disabled readOnly />
                </label>
                <label className="check">
                  <input type="checkbox" name="jit" defaultChecked={sso.provision === "create"} />
                  <span>
                    Add people on their first sign-in
                    <small>Otherwise only people already in Hawk AI can sign in. Never as an owner or admin. Needs at least one email domain below.</small>
                  </span>
                </label>
                <div className="row">
                  <label className="f">
                    Their role
                    <select name="jitRole" defaultValue={sso.role}>
                      {sso.roles.map((role) => (
                        <option key={role} value={role}>
                          {role.charAt(0).toUpperCase() + role.slice(1)}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="f">
                    Email domains allowed <span className="muted">such as company.com; none: any</span>
                    <input name="domains" defaultValue={sso.domains.join(", ")} />
                  </label>
                </div>
                <label className="check">
                  <input type="checkbox" name="requireVerifiedEmail" defaultChecked={sso.requireVerifiedEmail} />
                  <span>
                    The identity provider must mark the email address as verified
                    <small>Turn it off only for a provider that never sends that mark. Even then, an owner or admin is not signed in on an unverified address until they are linked.</small>
                  </span>
                </label>
                <label className="f">
                  Who may still sign in with a password
                  <select name="passwordSignIn" defaultValue={sso.passwordAdminsOnly ? "admins" : "everyone"}>
                    <option value="everyone">Everyone</option>
                    <option value="admins">Admins only (a way in if the identity provider is down)</option>
                  </select>
                </label>
                <label className="check">
                  <input type="checkbox" checked={sso.enabled} disabled readOnly />
                  <span>
                    <b>Single sign-on is on</b>
                    <small>COMPANY_SSO_ENABLED on the server.</small>
                  </span>
                </label>
              </form>
              <div className="saved-foot" ref={statusRef}>
                All changes are saved.
              </div>
            </div>
            <div className="panel">
              <h2>This service, for the identity provider</h2>
              {sso.callbackUrl ? (
                <>
                  <dl className="kv">
                    <dt>Redirect URI</dt>
                    <dd className="mono">{sso.callbackUrl}</dd>
                    <dt>Scopes</dt>
                    <dd className="mono">openid email profile</dd>
                    <dt>Flow</dt>
                    <dd className="mono">Authorization code with PKCE (S256), state and nonce</dd>
                    <dt>ID token</dt>
                    <dd className="mono">RS256, PS256 or ES256; amr with mfa</dd>
                  </dl>
                  <div className="callout mt">
                    In your identity provider, register Hawk AI as a web application with the Redirect URI above and the openid, email and profile scopes, and require a second factor. Then put its issuer and client id in OIDC_PROVIDERS_JSON and its client secret, encrypted, in OIDC_PROVIDER_SECRETS_JSON.
                  </div>
                </>
              ) : (
                <div className="callout warn">
                  Set <b>OIDC_CALLBACK_URL</b> to the https address of <code>/auth/oidc/callback</code> on this API, and restart: the identity provider needs it.
                </div>
              )}
            </div>
          </div>
        ) : null}
      </div>
    </AppShell>
  );
}
