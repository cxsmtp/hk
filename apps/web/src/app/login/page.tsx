"use client";

import { FormEvent, useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { setSession } from "@/lib/auth";
import { api } from "@/lib/api";
import { defaultRouteForRole } from "@/lib/navigation";
import type { LoginResponse } from "@/lib/types";

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [loading, setLoading] = useState(false);
  const [workspace, setWorkspace] = useState("acme");
  const [oidcProviders, setOidcProviders] = useState<Array<{ key: string; display_name: string }>>([]);

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
