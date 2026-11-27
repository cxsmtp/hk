"use client";

import type { ReactNode } from "react";
import { ShieldCheck } from "lucide-react";

import { brandingImage, useBranding } from "@/lib/settings-console";

/**
 * The frame of the pages shown before the console (sign in, forgotten password, a new password, joining, single
 * sign-on coming back): the organisation's name and logo above one centred card, the full height of the window
 * (100dvh, so iOS Safari's address bar does not push the card off the screen), clear of the notch and the home bar.
 */
export function SignInFrame({ children }: { children: ReactNode }) {
  const brand = useBranding();
  const logo = brandingImage(brand.logo);
  return (
    <main className="hawk-signin flex min-h-screen flex-col items-center justify-center gap-6 px-4 py-10">
      <div className="flex items-center gap-3" data-ui="sign-in-brand">
        <span className="grid h-11 w-11 place-items-center overflow-hidden rounded-2xl border border-orange-400/30 bg-orange-400/10 shadow-[0_0_36px_rgba(251,146,60,0.18)]">
          {logo ? (
            // eslint-disable-next-line @next/next/no-img-element -- the organisation's own logo, kept on the API
            <img src={logo} alt="" className="h-full w-full object-contain" />
          ) : (
            <ShieldCheck className="h-5 w-5 text-orange-300" />
          )}
        </span>
        <span className="min-w-0">
          <span className="block text-lg font-semibold tracking-[-0.02em] text-white">{brand.appName}</span>
          {brand.tagline ? <span className="block text-[11px] uppercase tracking-[0.16em] text-slate-500">{brand.tagline}</span> : null}
        </span>
      </div>
      <div className="flex w-full max-w-md flex-col items-center">{children}</div>
    </main>
  );
}
