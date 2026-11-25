const DEFAULT_LOCAL_API_URL = "http://127.0.0.1:8000";

function normalizeApiBaseUrl(raw: string): string {
  const candidate = String(raw || "").trim() || DEFAULT_LOCAL_API_URL;
  // A path on the console's own address, e.g. "/api" behind deploy/compose.yaml's front proxy: one origin, and the
  // same image works whatever name or address people use to reach it.
  if (/^\/(?!\/)/.test(candidate)) return candidate.replace(/\/+$/, "");
  try {
    const url = new URL(candidate);
    // Local dev on macOS can resolve localhost to ::1 while API often binds 127.0.0.1.
    if (url.hostname === "localhost") {
      url.hostname = "127.0.0.1";
    }
    return url.toString().replace(/\/+$/, "");
  } catch {
    return DEFAULT_LOCAL_API_URL;
  }
}

export const API_BASE_URL = normalizeApiBaseUrl(process.env.NEXT_PUBLIC_API_URL || DEFAULT_LOCAL_API_URL);

