import type { Metadata } from "next";
import { Toaster } from "sonner";

import { LicenceGate } from "@/components/licence-gate";

import "./globals.css";

export const metadata: Metadata = {
  title: "Hawk AI Observatory",
  description: "Observe every AI surface, signal, event, and autonomous decision from one assurance control plane.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <LicenceGate>{children}</LicenceGate>
        <Toaster richColors position="top-right" />
      </body>
    </html>
  );
}
