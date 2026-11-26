"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { toast } from "sonner";

import { api } from "@/lib/api";
import { setSession } from "@/lib/auth";
import { defaultRouteForRole } from "@/lib/navigation";
import type { LoginResponse } from "@/lib/types";

export default function OIDCCallbackPage() {
  const router = useRouter();
  const [message, setMessage] = useState("Completing company sign in...");
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    const fragment = window.location.hash.startsWith("#") ? window.location.hash.slice(1) : "";
    const ticket = new URLSearchParams(fragment).get("ticket");
    window.history.replaceState(null, "", window.location.pathname + window.location.search);
    if (!ticket) {
      setMessage("Sign in could not be completed.");
      setFailed(true);
      return;
    }
    let active = true;
    api.oidcComplete(ticket).then((result) => {
      if (!active) return;
      const login = result as LoginResponse;
      const tenantId = login.selected_tenant_id || login.tenants?.[0]?.id;
      if (!tenantId) throw new Error("No tenant in login response");
      const role = login.tenants?.find((tenant) => tenant.id === tenantId)?.role;
      // The tokens are HttpOnly cookies the API set; only who signed in is remembered here.
      setSession({ tenantId, userRole: role, user: login.user });
      router.replace(defaultRouteForRole(role));
    }).catch(() => {
      if (active) {
        setMessage("Sign in could not be completed.");
        setFailed(true);
        toast.error("Sign in could not be completed");
      }
    });
    return () => { active = false; };
  }, [router]);

  return (
    <main className="flex min-h-screen items-center justify-center p-4">
      <div className="text-center">
        <p>{message}</p>
        {failed ? (
          <a href="/login" className="mt-4 inline-flex rounded-md border border-slate-300 px-4 py-2 text-sm font-medium text-slate-700 hover:bg-slate-50">
            Return to sign in
          </a>
        ) : null}
      </div>
    </main>
  );
}
