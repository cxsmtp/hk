"use client";

import "@/styles/ftr.css";

import Link from "next/link";
import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

import { RecoveryCodes, TwoStepKey } from "@/components/two-step-key";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { setSession } from "@/lib/auth";
import { api } from "@/lib/api";
import { cleanSetupCode, passwordProblem } from "@/lib/access";
import { errorMessageFrom } from "@/lib/licence";
import { defaultRouteForRole } from "@/lib/navigation";
import { isTwoStepChallenge, refusalFrom, ssoRefusal, twoStepHint } from "@/lib/sign-in";
import type { TwoStepChallenge } from "@/lib/sign-in";
import type { LoginResponse } from "@/lib/types";

/** What the sign-in page shows (docs/sign-in.md, CxMissionZero's public/app/session.js). */
type Box = "signin" | "forgot" | "twostep" | "recovery";
type Status = { text: string; kind: "ok" | "error" | "" };

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [workspace, setWorkspace] = useState("acme");
  const [oidcProviders, setOidcProviders] = useState<Array<{ key: string; display_name: string }>>([]);
  // First start with FIRST_ADMIN=setup-code (deploy/README.md): nobody has access yet.
  const [setup, setSetup] = useState(false);
  const [setupCode, setSetupCode] = useState("");
  const [setupName, setSetupName] = useState("");
  const [setupPassword2, setSetupPassword2] = useState("");
  // Sign-in: the lock and the limits are said in the status line; two-step sign-in and "Forgot your password?".
  const [box, setBox] = useState<Box>("signin");
  const [status, setStatus] = useState<Status>({ text: "", kind: "" });
  const [forgotOffered, setForgotOffered] = useState(false);
  const [forgotEmail, setForgotEmail] = useState("");
  const [forgotStatus, setForgotStatus] = useState<Status>({ text: "", kind: "" });
  const [forgotWait, setForgotWait] = useState(false);
  const [challenge, setChallenge] = useState<TwoStepChallenge | null>(null);
  const [useRecovery, setUseRecovery] = useState(false);
  const [twoStepCode, setTwoStepCode] = useState("");
  const [twoStepStatus, setTwoStepStatus] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [pendingLogin, setPendingLogin] = useState<LoginResponse | null>(null);

  useEffect(() => {
    let active = true;
    api.setupStatus().then((result) => {
      if (active) setSetup(Boolean(result?.setup));
    }).catch(() => undefined);
    return () => { active = false; };
  }, []);

  useEffect(() => {
    // Back from the identity provider without a sign-in: say why, and take the code out of the address.
    const said = ssoRefusal(window.location.hash);
    if (said) {
      setStatus({ text: said, kind: "error" });
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    }
    let active = true;
    api.signInOptions().then((options) => {
      if (active) setForgotOffered(Boolean(options?.passwordReset));
    }).catch(() => undefined);
    return () => { active = false; };
  }, []);

  // Joining by oneself (FTR CC-01.116.00): offered only where an Admin turned it on for this workspace.
  const [joinDomains, setJoinDomains] = useState<string[]>([]);
  useEffect(() => {
    let active = true;
    api.joinAvailable(workspace).then((r) => {
      if (active) setJoinDomains(r.available ? r.domains : []);
    }).catch(() => undefined);
    return () => { active = false; };
  }, [workspace]);

  useEffect(() => {
    let active = true;
    api.oidcProviders(workspace).then((result) => {
      if (active) setOidcProviders(result.providers || []);
    }).catch(() => {
      if (active) setOidcProviders([]);
    });
    return () => { active = false; };
  }, [workspace]);

  async function startOIDC(providerKey: string) {
    setLoading(true);
    try {
      const result = await api.oidcStart(providerKey, workspace);
      window.location.assign(result.authorization_url);
    } catch {
      toast.error("Single sign-on is unavailable");
      setLoading(false);
    }
  }

  function signedIn(result: LoginResponse) {
    const tenantId = result.selected_tenant_id || result.tenants?.[0]?.id;
    if (!tenantId) throw new Error("No tenant in login response");
    const tenantRole = result.tenants?.find((item) => item.id === tenantId)?.role;
    setSession({
      accessToken: result.access_token,
      refreshToken: result.refresh_token,
      tenantId,
      userRole: tenantRole,
      user: result.user,
    });
    router.push(defaultRouteForRole(tenantRole));
  }

  async function onSetup(e: FormEvent) {
    e.preventDefault();
    const problem = password !== setupPassword2 ? "The passwords are not the same." : passwordProblem(password);
    if (problem) {
      toast.error(problem);
      return;
    }
    setLoading(true);
    try {
      const result = await api.setup({ code: cleanSetupCode(setupCode), email, name: setupName, password });
      toast.success("Administrator created");
      signedIn(result);
    } catch (err) {
      toast.error(errorMessageFrom(err instanceof Error ? err.message : "", "The administrator could not be created."));
    } finally {
      setLoading(false);
    }
  }

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setLoading(true);
    setStatus({ text: "", kind: "" });
    try {
      const result = await api.login(email, password);
      if (isTwoStepChallenge(result)) {
        // Two-step sign-in: the password was right, and the code (or setting it up) comes before anyone is signed in.
        setChallenge(result);
        setUseRecovery(false);
        setTwoStepCode("");
        setTwoStepStatus("");
        setBox("twostep");
        return;
      }
      toast.success("Signed in");
      signedIn(result);
    } catch (err) {
      // Wrong email or password, the lock after five wrong ones, or too many attempts from this address.
      setStatus({ text: refusalFrom(err instanceof Error ? err.message : "", "Login failed").message, kind: "error" });
    } finally {
      setLoading(false);
    }
  }

  async function onTwoStep(e: FormEvent) {
    e.preventDefault();
    if (!challenge) {
      setBox("signin");
      return;
    }
    setLoading(true);
    setTwoStepStatus("Signing in…");
    try {
      const { recovery_codes: codes, ...result } = await api.twoStep(challenge.ticket, twoStepCode.trim());
      setChallenge(null);
      setTwoStepCode("");
      setTwoStepStatus("");
      if (!codes) {
        signedIn(result);
        return;
      }
      // Set up on the way in: the recovery codes are shown now, once, before the console opens.
      setPendingLogin(result);
      setRecoveryCodes(codes);
      setBox("recovery");
    } catch (err) {
      const refusal = refusalFrom(err instanceof Error ? err.message : "");
      setTwoStepCode("");
      if (refusal.restart || /Too many sign-in attempts/.test(refusal.message)) {
        // The five minutes or the tries are over: back to the password.
        setChallenge(null);
        setBox("signin");
        setStatus({ text: refusal.message, kind: "error" });
      } else {
        setTwoStepStatus(refusal.message);
      }
    } finally {
      setLoading(false);
    }
  }

  async function onForgot(e: FormEvent) {
    e.preventDefault();
    setForgotWait(true);
    setForgotStatus({ text: "Sending…", kind: "" });
    try {
      const answer = await api.askPasswordReset(forgotEmail.trim());
      setForgotStatus({ text: answer.message, kind: "ok" });
      // One link a minute is all the server sends anyway.
      setTimeout(() => setForgotWait(false), 60_000);
    } catch (err) {
      setForgotStatus({ text: refusalFrom(err instanceof Error ? err.message : "").message, kind: "error" });
      setForgotWait(false);
    }
  }

  function backToSignIn() {
    setChallenge(null);
    setBox("signin");
  }

  if (setup) {
    return (
      <main className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md">
          <CardHeader>
            <CardTitle>Create the first administrator</CardTitle>
            <CardDescription>
              Nobody has access yet. Enter the setup code printed in the server log at start-up, and the administrator&apos;s details.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={onSetup} autoComplete="off">
              <div className="space-y-1">
                <label className="text-sm font-medium" htmlFor="setup-code">Setup code (from the server log)</label>
                <Input id="setup-code" value={setupCode} onChange={(e) => setSetupCode(e.target.value)} spellCheck={false} placeholder="ABCD-EFGH-JKLM" required />
              </div>
              <div className="space-y-1">
                <label className="text-sm font-medium" htmlFor="setup-name">Name</label>
                <Input id="setup-name" value={setupName} onChange={(e) => setSetupName(e.target.value)} autoComplete="name" />
              </div>
              <div className="space-y-1">
                <label className="text-sm font-medium" htmlFor="setup-email">Email</label>
                <Input id="setup-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" required />
              </div>
              <div className="space-y-1">
                <label className="text-sm font-medium" htmlFor="setup-password">Password (12+ characters)</label>
                <Input id="setup-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="new-password" minLength={12} required />
              </div>
              <div className="space-y-1">
                <label className="text-sm font-medium" htmlFor="setup-password2">Confirm password</label>
                <Input id="setup-password2" type="password" value={setupPassword2} onChange={(e) => setSetupPassword2(e.target.value)} autoComplete="new-password" minLength={12} required />
              </div>
              <Button className="w-full" disabled={loading}>
                {loading ? "Creating..." : "Create administrator"}
              </Button>
            </form>
          </CardContent>
        </Card>
      </main>
    );
  }

  if (box === "recovery" && recoveryCodes) {
    return (
      <main className="flex min-h-screen items-center justify-center p-4">
        <Card className="ftr w-full max-w-md" data-ui="login-recovery-codes">
          <CardHeader>
            <CardTitle>Recovery codes</CardTitle>
            <CardDescription>
              Two-step sign-in is on. If you lose your phone, one of these recovery codes signs you in instead of a code from the app. Each works once. They are shown only now: keep them somewhere safe, not on the phone itself.
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <RecoveryCodes codes={recoveryCodes} />
            <Button className="w-full" onClick={() => pendingLogin && signedIn(pendingLogin)}>
              I have saved them
            </Button>
          </CardContent>
        </Card>
      </main>
    );
  }

  if (box === "twostep" && challenge) {
    return (
      <main className="flex min-h-screen items-center justify-center p-4">
        <Card className="ftr w-full max-w-md" data-ui="login-two-step">
          <CardHeader>
            <CardTitle>Two-step sign-in</CardTitle>
            {challenge.setup ? (
              <CardDescription>
                An administrator requires two-step sign-in for everyone who signs in with a password. Set it up now: it takes a minute. From then on, you type a code from your phone after your password.
              </CardDescription>
            ) : null}
          </CardHeader>
          <CardContent>
            {challenge.setup ? (
              <>
                <ol className="twostep-steps">
                  <li>Install an authenticator app on your phone, if you have none: Microsoft Authenticator, Google Authenticator, or any other that makes six-digit codes.</li>
                  <li>In the app, add an account and scan this QR code. If you cannot scan it, type the key instead.</li>
                </ol>
                <TwoStepKey setup={challenge.setup} />
              </>
            ) : null}
            <form className="space-y-4" onSubmit={onTwoStep} autoComplete="off">
              <p className="text-sm text-slate-400">{twoStepHint({ setup: Boolean(challenge.setup), recovery: useRecovery })}</p>
              <div className="space-y-1">
                <label className="text-sm font-medium" htmlFor="two-step-code">{useRecovery ? "Recovery code" : "Code"}</label>
                <Input id="two-step-code" value={twoStepCode} onChange={(e) => setTwoStepCode(e.target.value)} inputMode={useRecovery ? "text" : "numeric"} autoComplete="one-time-code" maxLength={20} spellCheck={false} required autoFocus />
              </div>
              <Button className="w-full" disabled={loading}>
                {challenge.setup ? "Turn on and sign in" : "Sign in"}
              </Button>
              <div className="flex flex-wrap items-center gap-3 text-sm">
                {!challenge.setup ? (
                  <button type="button" className="text-sky-300 hover:underline" onClick={() => { setUseRecovery(!useRecovery); setTwoStepCode(""); }}>
                    {useRecovery ? "Use a code from the app" : "Use a recovery code"}
                  </button>
                ) : null}
                <button type="button" className="text-slate-400 hover:underline" onClick={backToSignIn}>
                  Back to sign in
                </button>
              </div>
              <p role="status" aria-live="polite" className="text-sm text-red-400">{twoStepStatus}</p>
            </form>
          </CardContent>
        </Card>
      </main>
    );
  }

  if (box === "forgot") {
    return (
      <main className="flex min-h-screen items-center justify-center p-4">
        <Card className="w-full max-w-md" data-ui="login-forgot">
          <CardHeader>
            <CardTitle>Forgot your password?</CardTitle>
            <CardDescription>
              Enter the email address you sign in with. If it has an account that may reset its password here, a link to choose a new one is sent to that address. It works once, for 30 minutes.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form className="space-y-4" onSubmit={onForgot}>
              <div className="space-y-1">
                <label className="text-sm font-medium" htmlFor="forgot-email">Email</label>
                <Input id="forgot-email" type="email" value={forgotEmail} onChange={(e) => setForgotEmail(e.target.value)} autoComplete="username" required autoFocus />
              </div>
              <Button className="w-full" disabled={forgotWait}>Send the link</Button>
              <button type="button" className="text-sm text-slate-400 hover:underline" onClick={() => setBox("signin")}>
                Back to sign in
              </button>
              <p role="status" aria-live="polite" className={`text-sm ${forgotStatus.kind === "error" ? "text-red-400" : "text-emerald-400"}`}>{forgotStatus.text}</p>
            </form>
          </CardContent>
        </Card>
      </main>
    );
  }

  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md">
        <CardHeader>
          <CardTitle>Enterprise Sign In</CardTitle>
          <CardDescription>Access the AI Control Plane with tenant-scoped credentials.</CardDescription>
        </CardHeader>
        <CardContent>
          <form className="space-y-4" onSubmit={onSubmit}>
            <div className="space-y-1">
              <label className="text-sm font-medium">Workspace</label>
              <Input value={workspace} onChange={(e) => setWorkspace(e.target.value)} autoComplete="organization" />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">Email</label>
              <Input value={email} onChange={(e) => setEmail(e.target.value)} autoComplete="username" />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">Password</label>
              <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="current-password" />
            </div>
            <Button className="w-full" disabled={loading}>
              {loading ? "Signing in..." : "Sign In"}
            </Button>
            {status.text ? (
              <p role="status" aria-live="polite" data-ui="login-status" className={`text-sm ${status.kind === "error" ? "text-red-400" : "text-emerald-400"}`}>
                {status.text}
              </p>
            ) : null}
            {forgotOffered ? (
              <button type="button" data-ui="forgot-link" className="text-sm text-sky-300 hover:underline" onClick={() => { setForgotEmail(email.trim()); setForgotStatus({ text: "", kind: "" }); setBox("forgot"); }}>
                Forgot your password?
              </button>
            ) : null}
            {joinDomains.length ? (
              <p data-ui="join-in" className="text-sm text-slate-400">
                New here, or no password yet?{" "}
                <Link className="text-sky-300 hover:underline" href={`/join?workspace=${encodeURIComponent(workspace)}`}>
                  Join with your {joinDomains.map((d) => `@${d}`).join(" or ")} email
                </Link>
              </p>
            ) : null}
            <p data-ui="onprem-note" className="text-xs text-emerald-400">
              Runs on your own servers and sends your data to no one: it connects only to the services you connect it to. No telemetry, no analytics, nothing calls home. Use of Hawk AI is subject to its terms of use.
            </p>
            {oidcProviders.length > 0 && (
              <div className="space-y-2 border-t pt-4">
                <p className="text-sm font-medium">Company sign in</p>
                {oidcProviders.map((provider) => (
                  <Button key={provider.key} type="button" variant="outline" className="w-full" disabled={loading} onClick={() => startOIDC(provider.key)}>
                    Continue with {provider.display_name}
                  </Button>
                ))}
              </div>
            )}
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
