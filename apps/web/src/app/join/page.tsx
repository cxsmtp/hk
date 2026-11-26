"use client";

import "@/styles/ftr.css";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useEffect, useState } from "react";
import type { FormEvent } from "react";

import { said } from "@/components/iam/ftr-bits";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import { setSession } from "@/lib/auth";
import type { JoinLink } from "@/lib/iam";
import { defaultRouteForRole } from "@/lib/navigation";
import type { LoginResponse } from "@/lib/types";

/**
 * Join (FTR Command Center CC-01.116.00, public/js/auth.js viewJoin): someone with a work address of the domains an
 * Admin allowed asks for a link; the link (in the address after #token=) lets them give their name, choose their team
 * and role, and a password. Whoever manages people reviews them on Settings → People. Off unless an Admin turns it on.
 */
export default function JoinPage() {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);
  const [workspace, setWorkspace] = useState("acme");
  const [available, setAvailable] = useState<{ available: boolean; domains: string[] } | null>(null);
  const [link, setLink] = useState<JoinLink | null>(null);
  const [message, setMessage] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);
  const [roleWhat, setRoleWhat] = useState("");

  useEffect(() => {
    const found = /token=([A-Za-z0-9_-]{43})/.exec(window.location.hash)?.[1] ?? "";
    const ws = new URLSearchParams(window.location.search).get("workspace");
    if (ws) setWorkspace(ws);
    if (found) {
      // The link's secret is not left in the address bar or the history.
      window.history.replaceState(null, "", window.location.pathname);
      setToken(found);
      api.checkJoinLink(found).then(setLink).catch((error) => setErr(said(error)));
    } else {
      setToken("");
    }
  }, []);

  useEffect(() => {
    if (token !== "") return;
    api.joinAvailable(workspace).then(setAvailable).catch(() => setAvailable({ available: false, domains: [] }));
  }, [token, workspace]);

  async function ask(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setBusy(true);
    try {
      const r = await api.askToJoin(workspace, String(new FormData(e.currentTarget).get("email") || ""));
      setMessage(r.message);
      setErr("");
    } catch (error) {
      setErr(said(error));
    } finally {
      setBusy(false);
    }
  }

  async function finish(e: FormEvent<HTMLFormElement>) {
    e.preventDefault();
    const f = new FormData(e.currentTarget);
    if (f.get("password") !== f.get("again")) {
      setErr("The two passwords are not the same.");
      return;
    }
    setBusy(true);
    try {
      const r = await api.confirmJoin({ token, name: f.get("name"), title: f.get("title"), teamId: f.get("teamId") || null, role: f.get("role"), password: f.get("password") });
      if ("twoStep" in r) {
        setMessage(r.message);
        setLink(null);
        return;
      }
      const result = r as LoginResponse;
      const tenantId = result.selected_tenant_id || result.tenants?.[0]?.id;
      if (!tenantId) throw new Error("No tenant in the answer.");
      const tenantRole = result.tenants?.find((item) => item.id === tenantId)?.role;
      // The tokens are HttpOnly cookies the API set; only who signed in is remembered here.
      setSession({ tenantId, userRole: tenantRole, user: result.user });
      router.push(defaultRouteForRole(tenantRole));
    } catch (error) {
      setErr(said(error));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <Card className="ftr w-full max-w-md" data-ui="join">
        {token && link ? (
          <>
            <CardHeader>
              <CardTitle>Finish joining</CardTitle>
              <CardDescription>
                For <b>{link.email}</b> in {link.workspace}. Choose where you work and what you do: an Admin reviews it, and can change it.
                {link.twoStepRequired ? " Two-step sign-in is required here: you set it up when you first sign in." : ""}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form className="form space-y-4" autoComplete="off" onSubmit={finish}>
                <label className="f">
                  Your name
                  <Input name="name" maxLength={120} required defaultValue={link.name} autoComplete="name" />
                </label>
                <label className="f">
                  Title <span className="muted">optional</span>
                  <Input name="title" maxLength={120} placeholder="Security Analyst" />
                </label>
                {link.teams.length ? (
                  <label className="f">
                    Your team
                    <select name="teamId" required defaultValue="">
                      <option value="">Choose…</option>
                      {link.teams.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.path}
                        </option>
                      ))}
                    </select>
                  </label>
                ) : null}
                <label className="f">
                  Your role
                  <select name="role" required defaultValue="" onChange={(e) => setRoleWhat(link.roles.find((r) => r.id === e.target.value)?.description ?? "")}>
                    <option value="">Choose…</option>
                    {link.roles.map((r) => (
                      <option key={r.id} value={r.id}>
                        {r.name}
                      </option>
                    ))}
                  </select>
                  <small className="muted">{roleWhat}</small>
                </label>
                <label className="f">
                  Password <span className="muted">at least 12 characters</span>
                  <Input type="password" name="password" autoComplete="new-password" minLength={12} required />
                </label>
                <label className="f">
                  Password again
                  <Input type="password" name="again" autoComplete="new-password" minLength={12} required />
                </label>
                <div className="err">{err}</div>
                <Button className="w-full" disabled={busy}>
                  Join
                </Button>
              </form>
            </CardContent>
          </>
        ) : (
          <>
            <CardHeader>
              <CardTitle>Join</CardTitle>
              <CardDescription>
                {available?.available
                  ? `Enter your ${available.domains.map((d) => `@${d}`).join(" or ")} email. If you already have access, you are told how to sign in; if you are new, a link to finish joining: your team, your role and a password.`
                  : token
                    ? ""
                    : "Joining by yourself is not available here: ask an Admin to add you."}
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {message ? <div className="callout mt">{message}</div> : null}
              {err ? <div className="callout warn mt">{err}</div> : null}
              {!token && available?.available && !message ? (
                <form className="form space-y-4" onSubmit={ask}>
                  <label className="f">
                    Work email
                    <Input name="email" type="email" required autoComplete="username" autoFocus />
                  </label>
                  <Button className="w-full" disabled={busy}>
                    Send me a link
                  </Button>
                </form>
              ) : null}
              <p className="text-sm">
                {token ? (
                  <>
                    <Link className="text-sky-300 hover:underline" href={`/join?workspace=${encodeURIComponent(workspace)}`}>
                      Ask for a new link
                    </Link>
                    {" · "}
                  </>
                ) : null}
                <Link className="text-sky-300 hover:underline" href="/login">
                  Sign in
                </Link>
              </p>
            </CardContent>
          </>
        )}
      </Card>
    </main>
  );
}
