import type { Metadata, Viewport } from "next";
import { Toaster } from "sonner";

import { AccessGate } from "@/components/access-gate";
import { DemoDataBanner } from "@/components/demo-data-banner";
import { LicenceGate } from "@/components/licence-gate";
import { VersionTag } from "@/components/version-tag";
import { THEME_BOOT } from "@/lib/theme";

import "./globals.css";

export const metadata: Metadata = {
  title: "Hawk AI Observatory",
  description: "Observe every AI surface, signal, event, and autonomous decision from one assurance control plane.",
};

// The phone's own width, no zoom on load, and the page drawn edge to edge (globals.css keeps clear of the notch).
export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  viewportFit: "cover",
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#05070d" },
    { media: "(prefers-color-scheme: light)", color: "#f4f6f9" },
  ],
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="light" suppressHydrationWarning>
      <head>
        {/* The remembered look (light unless this browser chose dark), set before anything is drawn. */}
        <script dangerouslySetInnerHTML={{ __html: THEME_BOOT }} />
      </head>
      <body>
        <DemoDataBanner />
        <LicenceGate>
          <AccessGate>{children}</AccessGate>
        </LicenceGate>
        <VersionTag />
        <Toaster richColors position="top-right" />
      </body>
    </html>
  );
}
