"use client";

import { useParams, useRouter } from "next/navigation";
import { useEffect } from "react";

export default function RuntimeChainGraphDeepLinkPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const chainId = decodeURIComponent(String(params.id || "")).trim();

  useEffect(() => {
    router.replace(`/runtime-intelligence/activity-map?chain_id=${encodeURIComponent(chainId)}`);
  }, [chainId, router]);

  return <div className="p-6 text-sm text-slate-400">Opening runtime activity map…</div>;
}
