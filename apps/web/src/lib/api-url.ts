const DEFAULT_LOCAL_API_URL = "http://127.0.0.1:8000";

function normalizeApiBaseUrl(raw: string): string {
  const candidate = String(raw || "").trim() || DEFAULT_LOCAL_API_URL;
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

