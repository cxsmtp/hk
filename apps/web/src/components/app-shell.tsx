"use client";

import { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";

import "@/app/settings/ftr-settings.css";

import { Sidebar } from "@/components/sidebar";
import { Topbar } from "@/components/topbar";
import { LicenceBanner } from "@/components/licence-banner";
import { BackupNotice } from "@/components/backup-notice";
import { IntegrityNotice } from "@/components/integrity-notice";
import { MobileLifecycleNav } from "@/components/mobile-lifecycle-nav";
import { SettingsNav } from "@/components/settings-nav";
import { useBranding } from "@/lib/settings-console";
import { getSession, SESSION_CHANGE_EVENT } from "@/lib/auth";
import { useDevRouteWarmup } from "@/hooks/use-dev-route-warmup";

export function AppShell({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname() || "";
  // FTR: under Settings, its own menu beside the page (public/js/shell.js .set-wrap).
  const inSettings = pathname.startsWith("/settings/");
  useBranding();
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
        <BackupNotice />
        <IntegrityNotice />
        <Topbar />
        <MobileLifecycleNav />
        {inSettings ? (
          // FTR's .set-wrap: the menu in a column of its own (188 px, 164 px up to 1360 px wide), above the page up to 900 px.
          <div className="set-wrap min-w-0 items-start min-[901px]:grid min-[901px]:grid-cols-[164px_minmax(0,1fr)] min-[1361px]:grid-cols-[188px_minmax(0,1fr)]">
            <div className="ftr-settings set-side min-[901px]:sticky min-[901px]:top-0">
              <SettingsNav />
            </div>
            <div className="set-main mx-auto w-full min-w-0 max-w-[1800px] px-4 pb-8 pt-6 sm:px-6">{children}</div>
          </div>
        ) : (
          <div className="mx-auto w-full max-w-[1800px] px-4 pb-8 pt-6 sm:px-6">{children}</div>
        )}
      </main>
    </div>
  );
}
