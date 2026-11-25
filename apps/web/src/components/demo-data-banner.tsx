"use client";

import { useEffect, useState } from "react";

import { demoDataShown, subscribeDemoData } from "@/lib/demo-fallback";

/** In the demo build only: once invented demo data has filled any view, every view says so. Nothing in other builds. */
export function DemoDataBanner() {
  if (process.env.NEXT_PUBLIC_HAWK_DEMO_BUILD !== "1") return null;
  return <DemoDataNotice />;
}

function DemoDataNotice() {
  const [shown, setShown] = useState(false);
  useEffect(() => {
    setShown(demoDataShown());
    return subscribeDemoData(() => setShown(true));
  }, []);
  if (!shown) return null;
  return (
    <div
      role="status"
      data-ui="demo-data-banner"
      className="fixed inset-x-0 top-0 z-[1000] bg-amber-400 px-4 py-1 text-center text-sm font-semibold text-black"
    >
      Demo data: invented sample records are shown where the API failed or had none. Not evidence.
    </div>
  );
}
