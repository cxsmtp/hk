"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { LicenceBanner } from "@/components/licence-banner";
import { MobileLifecycleNav } from "@/components/mobile-lifecycle-nav";
import { getSession, SESSION_CHANGE_EVENT } from "@/lib/auth";
import { useDevRouteWarmup } from "@/hooks/use-dev-route-warmup";

export function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const [hasSession, setHasSession] = useState(false);
  const [sessionReady, setSessionReady] = useState(false);
  useDevRouteWarmup();

  useEffect(() => {
    const checkSession = () => {
      const session = getSession();
      const active = !!session?.accessToken;
      setHasSession(active);
      setSessionReady(true);
      if (!active) {
        router.push("/login");
      }
    };

    checkSession();
    window.addEventListener(SESSION_CHANGE_EVENT, checkSession);
    window.addEventListener("storage", checkSession);
    return () => {
      window.removeEventListener(SESSION_CHANGE_EVENT, checkSession);
      window.removeEventListener("storage", checkSession);
    };
  }, [router]);

  // Keep server and first client render identical to avoid hydration mismatches.
  if (!sessionReady) return null;
  if (!hasSession) return null;

  return (
    <div className="min-h-screen overflow-x-clip bg-transparent lg:flex">
      <Sidebar />
      <main className="min-w-0 flex-1 overflow-x-clip">
        <LicenceBanner />
        <Topbar />
        <MobileLifecycleNav />
        <div className="mx-auto w-full max-w-[1800px] px-4 pb-8 pt-6 sm:px-6">{children}</div>
      </main>
    </div>
  );
}
