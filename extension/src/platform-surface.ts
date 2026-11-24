export type BrowserSurfaceTarget = {
  domain: string;
  url?: string | null;
  title?: string | null;
  bodyText?: string | null;
};

const HAWK_CONTROL_PLANE_PATH_PREFIXES = [
  "/ai-iam",
  "/auditor",
  "/dashboard",
  "/discovery",
  "/policies",
  "/runtime-intelligence",
];

const HAWK_CONTROL_PLANE_MARKERS = [
  "ai control plane",
  "ai iam",
  "control plane",
  "discovery findings",
  "governance review",
  "notification hub",
  "policy version",
  "runtime intelligence",
  "shadow ai",
];

function normalize(value: string | null | undefined): string {
  return String(value || "").trim().toLowerCase();
}

function normalizeHost(value: string | null | undefined): string {
  return normalize(value).replace(/^www\./, "");
}

function isLoopbackHost(host: string): boolean {
  const normalized = normalizeHost(host);
  return (
    normalized === "localhost"
    || normalized === "127.0.0.1"
    || normalized === "::1"
    || normalized.endsWith(".localhost")
  );
}

function parseUrl(rawUrl: string | null | undefined): URL | null {
  const value = String(rawUrl || "").trim();
  if (!value) return null;
  try {
    return new URL(value);
  } catch {
    return null;
  }
}

function isControlPlaneRoute(pathname: string): boolean {
  const path = normalize(pathname) || "/";
  return HAWK_CONTROL_PLANE_PATH_PREFIXES.some((prefix) => path === prefix || path.startsWith(`${prefix}/`));
}

function countControlPlaneMarkers(text: string): number {
  const normalized = normalize(text);
  return HAWK_CONTROL_PLANE_MARKERS.filter((marker) => normalized.includes(marker)).length;
}

export function isHawkControlPlaneSurface(target: BrowserSurfaceTarget): boolean {
  const parsedUrl = parseUrl(target.url);
  const host = parsedUrl ? normalizeHost(parsedUrl.hostname) : normalizeHost(target.domain);
  if (!isLoopbackHost(host)) return false;

  const title = normalize(target.title);
  if (title.includes("ai control plane")) return true;

  const port = String(parsedUrl?.port || "").trim();
  const isLocalWebUiPort = port === "" || port === "3000";
  if (!isLocalWebUiPort || !isControlPlaneRoute(parsedUrl?.pathname || "")) return false;

  const markerText = [target.title || "", target.bodyText || ""].join("\n");
  return countControlPlaneMarkers(markerText) >= 2;
}
