"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { passwordProblem } from "@/lib/access";
import { refusalFrom, resetLinkToken } from "@/lib/sign-in";

/**
 * Choose a new password from the emailed link (/settings/guide/people-and-access, CxMissionZero's showReset): /login/reset#reset=<token>.
 * The secret is after "#", so browsers never send it to a server or in a Referer; the page takes it out of the
 * address bar at once. Saving signs the account out everywhere, and an email confirms the change.
 */
export default function ResetPasswordPage() {
  const router = useRouter();
  const [token, setToken] = useState("");
  const [forEmail, setForEmail] = useState("");
  const [note, setNote] = useState("Checking the link…");
  const [dead, setDead] = useState(false);
  const [next, setNext] = useState("");
  const [next2, setNext2] = useState("");
  const [status, setStatus] = useState<{ text: string; bad: boolean }>({ text: "", bad: false });
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    const found = resetLinkToken(window.location.hash);
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    if (!found) {
      setNote("This link no longer works: it was used, a newer one was sent, it is more than 30 minutes old, or the password has changed since. Ask for a new one.");
      setDead(true);
      return;
    }
    setToken(found);
    api
      .checkPasswordReset(found)
      .then((link) => {
        setForEmail(link.email);
        setNote("For this account. The link works once, for 30 minutes from when it was sent.");
      })
      .catch((error) => {
        setToken("");
        setNote(refusalFrom(error instanceof Error ? error.message : "").message);
        setDead(true);
      });
  }, []);

  async function save(event: FormEvent) {
    event.preventDefault();
    if (next !== next2) {
      setStatus({ text: "The passwords do not match.", bad: true });
      return;
    }
    const problem = passwordProblem(next);
    if (problem) {
      setStatus({ text: problem, bad: true });
      return;
    }
    setBusy(true);
    setStatus({ text: "Saving…", bad: false });
    try {
      await api.confirmPasswordReset(token, next);
      setToken("");
      setNext("");
      setNext2("");
      setStatus({ text: "Your password was changed. Sign in with the new one.", bad: false });
      setTimeout(() => router.push("/login"), 1500);
    } catch (error) {
      setStatus({ text: refusalFrom(error instanceof Error ? error.message : "").message, bad: true });
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <Card className="w-full max-w-md" data-ui="login-reset">
        <CardHeader>
          <CardTitle>Choose a new password</CardTitle>
          <CardDescription>{note}</CardDescription>
        </CardHeader>
        <CardContent>
          {forEmail ? <p className="mb-4 font-mono text-sm" translate="no">{forEmail}</p> : null}
          {dead ? (
            <Button className="w-full" onClick={() => router.push("/login")}>
              Ask for a new link
            </Button>
          ) : null}
          {token && forEmail ? (
            <form className="space-y-4" onSubmit={save} autoComplete="off">
              <div className="space-y-1">
                <label className="text-sm font-medium" htmlFor="reset-next">New password (12+ characters)</label>
                <Input id="reset-next" type="password" value={next} onChange={(e) => setNext(e.target.value)} autoComplete="new-password" minLength={12} required />
              </div>
              <div className="space-y-1">
                <label className="text-sm font-medium" htmlFor="reset-next2">Confirm</label>
                <Input id="reset-next2" type="password" value={next2} onChange={(e) => setNext2(e.target.value)} autoComplete="new-password" minLength={12} required />
              </div>
              <p className="text-sm text-slate-400">Saving signs this account out everywhere, and an email confirms the change.</p>
              <Button className="w-full" disabled={busy}>Save password</Button>
            </form>
          ) : null}
          <p role="status" aria-live="polite" className={`mt-3 text-sm ${status.bad ? "text-red-400" : "text-emerald-400"}`}>
            {status.text}
          </p>
        </CardContent>
      </Card>
    </main>
  );
}
