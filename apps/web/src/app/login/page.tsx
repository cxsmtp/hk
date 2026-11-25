"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { setSession } from "@/lib/auth";
import { api } from "@/lib/api";
import { cleanSetupCode, passwordProblem } from "@/lib/access";
import { errorMessageFrom } from "@/lib/licence";
import { defaultRouteForRole } from "@/lib/navigation";
import type { LoginResponse } from "@/lib/types";

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

  useEffect(() => {
    let active = true;
    api.setupStatus().then((result) => {
      if (active) setSetup(Boolean(result?.setup));
    }).catch(() => undefined);
    return () => { active = false; };
  }, []);

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
    try {
      const result = (await api.login(email, password)) as LoginResponse;
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

      toast.success("Signed in");
      router.push(defaultRouteForRole(tenantRole));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Login failed");
    } finally {
      setLoading(false);
    }
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
              <Input value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="space-y-1">
              <label className="text-sm font-medium">Password</label>
              <Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <Button className="w-full" disabled={loading}>
              {loading ? "Signing in..." : "Sign In"}
            </Button>
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
