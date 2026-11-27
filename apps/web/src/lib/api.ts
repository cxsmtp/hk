import { clearSession, getSession, sessionHeaders } from "@/lib/auth";
import { API_BASE_URL } from "@/lib/api-url";
import type { AcmeStatus, HttpsCertificateReport, HttpsMode, HttpsStatus, UploadFile } from "@/lib/https-settings";
import type { BackupEncryption, BackupFile, BackupInfo, BackupKeyShown, BackupNotice, BackupsStatus, Readiness } from "@/lib/backups-settings";
import type { Integrity, IntegrityState, UpdateSettings, UpdatesStatus } from "@/lib/updates-settings";
import type { HandsOffSettings, HandsOffView, LinkAnswer, SelfCheckHealth } from "@/lib/hands-off-settings";
import type { ApprovalDecision, ApprovalGrantView, ApprovalPolicy, ApprovalPolicyView, ApprovalRequestView, ApprovalScope } from "@/lib/ai-system-approvals";
import type { DiagnosticsView } from "@/lib/self-recovery";
import type { AboutView, BrandingPatch, BrandingView, GeneralView, SettingsMe, SmtpSettings, SmtpView } from "@/lib/settings-console";
import type { ComplianceSettings, ComplianceView, PacksOverview, PackView } from "@/lib/compliance";
import type { AuditPage, AuditVerify, ConnectorActivity, EvidenceSigning, Emailed, NetworkCheck, NetworkInfo, SupportChannel, SupportKind, SupportList, SupportRequest, TrustDiagnosis, TrustedCertificate } from "@/lib/records";
import { approvalStatusFilters, mergeApprovalStatusResults } from "@/lib/approval-workflow";
import { demoFallbackRequest, isDemoFallbackEnabled } from "@/lib/demo-fallback";
import { isDeactivatedAnswer, LICENCE_DEACTIVATED_EVENT } from "@/lib/licence";
import { accessNeededFrom, PASSWORD_CHANGE_EVENT, TERMS_REQUIRED_EVENT } from "@/lib/access";
import type { TermsAcceptPayload, TermsAcceptance, TermsAcceptances, TermsState, TermsView } from "@/lib/access";
import type { SignInPerson, SignInSettings, TwoStepChallenge, TwoStepSetup, TwoStepState } from "@/lib/sign-in";
import type { IamJoinSettings, IamRole, IamView, JoinLink } from "@/lib/iam";
import type { AdminLicence, LicenceImported, LicenceStatus, LicenceView } from "@/lib/licence";
import type {
  AIDiscoveryAnomalyEvent,
  ActionIntegrityDetail,
  AIAgentAttackSurface,
  AIAgentBehaviorProfile,
  AIAgentBlastRadius,
  AIAgentDiscoveryOverview,
  AIAgentEnforcementResult,
  AIAgentOWASPCoverage,
  AIAgentSimulationResult,
  AIDiscoveryGraph,
  AIDiscoveryIdentityProfile,
  AIDiscoveryOverview,
  AIDiscoveryUsageEvent,
  AgenticChainDefenseMode,
  AgenticChainRunResponse,
  AgenticChainIntegrityMetrics,
  AgenticChainScenarioListResponse,
  AIOrchestrationResult,
  AIReasoningTicketPayload,
  AIReasoningTrace,
  ActivityAuditEndpoint,
  ActivityAuditSearchResponse,
  ActivityAuditTimeline,
  ActivityAuditUserDetail,
  ActivityAuditUser,
  UserVisibilityAction,
  UserVisibilityDirectorySummary,
  UserVisibilityDepartment,
  UserVisibilityExperienceSection,
  UserVisibilityGroup,
  UserVisibilityGroupDetail,
  UserVisibilityOrganization,
  UserVisibilityPolicyStack,
  UserVisibilityRevealedPrompt,
  UserVisibilityRevealGrant,
  UserVisibilityAccessGrant,
  UserVisibilityUser,
  UserVisibilityUser360,
  ActivityLineageProjection,
  AIIAMIdentityProfile,
  AIToolsUsageWorkspace,
  BrowserExtensionHealth,
  BrowserExtensionRemovalGovernance,
  AgentBlastRadius,
  AuditorControlPostureView,
  BankingCisoSummary,
  BankingTransactionProjection,
  AISystem,
  AgentDetail,
  AgentTouchpoints,
  AuditEvidenceExplanation,
  AguiAction,
  AguiDecision,
  AgentIdentity,
  AuditorExportResponse,
  ApprovalRequest,
  CommandCenterDashboardState,
  Connector,
  ConnectorBootstrapResponse,
  ConnectorEvaluation,
  ConnectorProviderCatalogItem,
  Control,
  ControlExplorerState,
  RuntimeControlViewState,
  SimulationControlViewState,
  ControlConflict,
  ControlTraceabilityRow,
  ControlCoveragePathDetail,
  ControlCoveragePathList,
  ControlCoverageSummary,
  ExecutiveControlCoverageSummary,
  ExecutiveCoverageAssessmentExplanation,
  ExecutiveCoverageAssessmentList,
  ChatGPTDesktopAction,
  ChatGPTDesktopAssetResponse,
  ChatGPTDesktopControlPlan,
  NativeCapabilityMatrix,
  NativeControlPoint,
  NativeControlPointHealth,
  NativeControlPointList,
  NativeControlSelection,
  NativeControlValidationRun,
  DeploymentCoverageSummary,
  EndpointEnforcementFloorSummary,
  EndpointHealthSummary,
  EndpointReenrollmentAuthorization,
  DashboardNotificationsState,
  ExposureScanState,
  ExposureGraphResponse,
  ExposureProjection,
  ExposureTimelineResponse,
  DiscoveryAssetEvidenceList,
  DiscoveryAssetHistory,
  DiscoveryAssetDetail,
  DiscoveryAssetSummary,
  DiscoveryCollectorHealth,
  DiscoveryCoverageProjection,
  DiscoveryEcosystem,
  EcosystemVerificationHistory,
  EcosystemVerificationProjection,
  VerificationPlanResponse,
  ERGEcosystemDetail,
  ERGEcosystemSummary,
  ERGTimeline,
  DiscoveryEstateSummary,
  DiscoveryIntelligenceFinding,
  DiscoveryScanEstimate,
  DiscoveryScanProgress,
  DiscoveryScanResults,
  DiscoveryScanDiagnostics,
  DeepScanCoverage,
  DeepScanLaunch,
  DeepScanLaunchRequest,
  DeepScanPreflight,
  DeepScanPreflightRequest,
  DiscoveryApplication,
  DriftAlert,
  EnterpriseDeveloperAIControl,
  EnterpriseDenominatorStatus,
  GitHubRepositoryDetail,
  GitHubRepositoryInventoryPage,
  GitHubRepositoryProjection,
  GitHubRepositoryRuntimeBinding,
  HMAIRSourceConnection,
  HMAIRSourceConnectionInput,
  SourceConnectionSetupCatalog,
  Finding,
  FindingTicketResponse,
  FindingTraceability,
  FindingValidationPackResponse,
  NotetakerPlatformActionRequest,
  NotetakerPlatformActionResponse,
  EnforcementEvent,
  ExtensionPolicySync,
  EvidenceNode,
  HmairCollectorSummary,
  HmairTargetSummary,
  HmairDiscoveryScan,
  EndpointMetadataInventoryRun,
  JobStatusItem,
  ListEnvelope,
  MicrosoftAppRegistrationTemplate,
  MicrosoftConsentUrlResponse,
  MicrosoftPermissionMode,
  MicrosoftScopeResolution,
  MaturityRow,
  MaturityCurveEffectiveness,
  MaturityCurveOverview,
  MaturityCurvePattern,
  MaturityCurveRecommendation,
  MaturityCurveRollout,
  MaturityCurveScope,
  MaturityCurveScopeDetail,
  MaturityCurveSimulation,
  PolicyPack,
  PolicyPackCapabilityCoverage,
  PolicyPackFrameworkAtlas,
  PolicyPackPlatformDefinition,
  PolicyPackPlatformInstance,
  PolicyPackSimulation,
  PolicyScopedRule,
  PolicyScopedRulesResponse,
  PolicyVersion,
  PilotHealthState,
  PlatformMode,
  PlatformModeResponse,
  RunningPolicyStatus,
  RuntimeAISystemGraph,
  RuntimeActionGraph,
  RuntimeActionTrace,
  RuntimeAgenticChainEvidence,
  RuntimeAgenticChainGraph,
  RuntimeAgentGraph,
  RuntimeAgentChain,
  RuntimeChainGraph,
  RuntimeIntelligenceEvent,
  RuntimeIntelligenceFindingsEnvelope,
  RuntimeIntelligenceRecommendation,
  RuntimeIntelligenceTrigger,
  RuntimePattern,
  RuntimeRecommendation,
  RuntimeTrace,
  RuntimeTimelineEvent,
  ScanTriggerResponse,
  ShadowAIEntity,
  TelemetryImportResult,
  ShadowAIEntityDetail,
  ShadowAISignal,
  SimulationDefinition,
  SimulationExecutor,
  SimulationHeatmap,
  SimulationCatalogCoverage,
  SimulationPolicy,
  SimulationPack,
  SimulationPackRunResult,
  SimulationRun,
  SimulationRunTrace,
  SimulationSeedPackBootstrapSummary,
  SimulationCoverageSummary,
  SimulationTrendSeries,
  UnknownAIItem,
  LoginResponse,
  OIDCProviderList,
  LLMGatewayDocumentCompleteResponse,
} from "@/lib/types";

const API_URL = API_BASE_URL;
// Invented demo data exists only in the demo build (DEMO_BUILD=1, demo-build.mjs). Inlined at compile time: in every
// other build the demo branches below are dead code and @/lib/demo-fallback is a module without data, so an API error
// is shown as an error and an empty result as empty.
const DEMO_BUILD = process.env.NEXT_PUBLIC_HAWK_DEMO_BUILD === "1";
const DEMO_FORCE = DEMO_BUILD && (process.env.NEXT_PUBLIC_DEMO_FORCE || "false").toLowerCase() === "true";
const DEMO_FILL_EMPTY = DEMO_BUILD && (process.env.NEXT_PUBLIC_DEMO_FILL_EMPTY || "true").toLowerCase() !== "false";
const RETRYABLE_MUTATION_PATH_PREFIXES = [
  "/scans/trigger",
  "/discovery/scans",
  "/gateway/mcp/tools/scan",
  "/external-risk/sync",
  "/simulations/runs",
  "/simulations/packs",
  "/ai-orchestration/",
];
const NETWORK_RETRY_BACKOFF_MS = [300, 600, 1200, 1800, 2500, 3200] as const;
const NETWORK_GET_ATTEMPTS = NETWORK_RETRY_BACKOFF_MS.length + 1;
const NETWORK_MUTATION_ATTEMPTS = 4;
const DEFAULT_GET_TIMEOUT_MS = 20000;
const REFRESH_TIMEOUT_MS = 8000;
const TRANSIENT_HTTP_STATUSES = new Set([408, 425, 429, 500, 502, 503, 504]);

// The tokens never reach this code: the API keeps them in HttpOnly cookies (apps/api/app/core/session_cookies.py), sent
// with every request (same origin behind the front proxy; credentials "include" for a developer's API on another
// port), and every request carries the CSRF token (sessionHeaders, @/lib/auth).
const CREDENTIALS: RequestCredentials = "include";
// Before trying a refresh again after a refusal: another tab may have rotated the refresh cookie at that moment.
const REFRESH_RACE_PAUSE_MS = 250;

type RequestBehavior = {
  timeoutMs?: number;
};

let refreshTokenInFlight: Promise<boolean> | null = null;
const inflightGetRequests = new Map<string, Promise<unknown>>();

/**
 * The licence gate's answer (/settings/guide/licence): Hawk AI has been deactivated. Tells the page, which then
 * shows the deactivation screen, and says whether it was that answer (so it is not retried).
 */
function reportDeactivated(status: number, text: string): boolean {
  if (status !== 503) return false;
  let body: unknown = null;
  try {
    body = JSON.parse(text);
  } catch {
    return false;
  }
  if (!isDeactivatedAnswer(status, body)) return false;
  if (typeof window !== "undefined") window.dispatchEvent(new Event(LICENCE_DEACTIVATED_EVENT));
  return true;
}

/** A 403 asking for a new password or the terms of use first (apps/api/app/core/access_gate.py): tell the page. */
function reportAccessNeeded(status: number, text: string): boolean {
  const needed = accessNeededFrom(status, text);
  if (!needed) return false;
  if (typeof window !== "undefined") window.dispatchEvent(new Event(needed === "password" ? PASSWORD_CHANGE_EVENT : TERMS_REQUIRED_EVENT));
  return true;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isLikelyNetworkFetchError(err: unknown): boolean {
  if (err instanceof TypeError) return true;
  if (!(err instanceof Error)) return false;
  const message = String(err.message || "").toLowerCase();
  return (
    message.includes("failed to fetch")
    || message.includes("networkerror")
    || message.includes("network request failed")
    || message.includes("load failed")
  );
}

function shouldRetryOnNetworkError(path: string, init?: RequestInit): boolean {
  const method = String(init?.method || "GET").toUpperCase();
  if (method === "GET" || method === "HEAD" || method === "OPTIONS") return true;
  return RETRYABLE_MUTATION_PATH_PREFIXES.some((prefix) => path.startsWith(prefix));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function shouldUseFallbackForPayload(payload: unknown): boolean {
  if (Array.isArray(payload)) return payload.length === 0;
  if (!isRecord(payload)) return false;

  const keys = Object.keys(payload);
  if (keys.length === 0) return true;

  const items = payload.items;
  if (Array.isArray(items)) {
    const total = typeof payload.total === "number" ? payload.total : items.length;
    return items.length === 0 && total === 0;
  }

  return false;
}

function isTerminalRefreshFailureStatus(statusCode: number): boolean {
  // Auth refresh should only hard-logout on explicit auth failures.
  return statusCode === 401 || statusCode === 403;
}

async function performRefreshToken(): Promise<boolean> {
  for (let refreshAttempt = 0; refreshAttempt < 2; refreshAttempt += 1) {
    if (!getSession()) return false;

    let res: Response;
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), REFRESH_TIMEOUT_MS);
      try {
        // No token in the body: the refresh cookie is sent to this path only.
        res = await fetch(`${API_URL}/auth/refresh`, {
          method: "POST",
          headers: sessionHeaders(new Headers({ "Content-Type": "application/json" })),
          body: "{}",
          credentials: CREDENTIALS,
          cache: "no-store",
          signal: controller.signal,
        });
      } finally {
        clearTimeout(timeout);
      }
    } catch {
      // Keep current session on transient transport failures; caller retries on next poll.
      return false;
    }

    if (!res.ok) {
      if (isTerminalRefreshFailureStatus(res.status)) {
        // Multi-tab rotation race: another tab may have refreshed with the same cookie a moment before, and the
        // browser now holds the new one. One more try tells; a second refusal signs out.
        if (refreshAttempt === 0) {
          await sleep(REFRESH_RACE_PAUSE_MS);
          continue;
        }
        clearSession();
      } else if (TRANSIENT_HTTP_STATUSES.has(res.status)) {
        // Preserve session on transient backend outages/locks/timeouts.
      }
      return false;
    }
    // The new tokens came as cookies; the body has none.
    await res.text().catch(() => "");
    return true;
  }
  return false;
}

async function tryRefreshToken(): Promise<boolean> {
  if (refreshTokenInFlight) return refreshTokenInFlight;
  refreshTokenInFlight = performRefreshToken().finally(() => {
    refreshTokenInFlight = null;
  });
  return refreshTokenInFlight;
}

async function probeApiHealth(): Promise<boolean> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 1500);
  try {
    const res = await fetch(`${API_URL}/health`, {
      method: "GET",
      cache: "no-store",
      signal: controller.signal,
    });
    return res.ok;
  } catch {
    return false;
  } finally {
    clearTimeout(timeout);
  }
}

async function request<T>(
  path: string,
  init?: RequestInit,
  useAuth = true,
  allowRefresh = true,
  behavior?: RequestBehavior,
): Promise<T> {
  const headers = sessionHeaders(new Headers(init?.headers || {}));
  headers.set("Content-Type", "application/json");
  const session = useAuth ? getSession() : null;

  if (useAuth) {
    if (!session?.tenantId) throw new Error("No tenant selected");
    headers.set("X-Tenant-ID", session.tenantId);
  }

  const retryable = shouldRetryOnNetworkError(path, init);
  const method = String(init?.method || "GET").toUpperCase();
  const maxNetworkAttempts = retryable
    ? (method === "GET" || method === "HEAD" || method === "OPTIONS" ? NETWORK_GET_ATTEMPTS : NETWORK_MUTATION_ATTEMPTS)
    : 1;
  const effectiveTimeoutMs = behavior?.timeoutMs ?? ((method === "GET" || method === "HEAD") ? DEFAULT_GET_TIMEOUT_MS : 0);
  const timeoutMs = Math.max(0, Math.floor(Number(effectiveTimeoutMs || 0)));
  const dedupeEligible = method === "GET" && !init?.body;
  // The try after a refresh has a key of its own: it runs inside the first try, which would otherwise wait on itself.
  const dedupeKey = dedupeEligible
    ? `${useAuth ? `${session?.tenantId || ""}:${session?.user?.id || ""}` : "public"}|${allowRefresh ? "" : "refreshed|"}${path}`
    : "";
  if (dedupeEligible) {
    const inflight = inflightGetRequests.get(dedupeKey);
    if (inflight) {
      return inflight as Promise<T>;
    }
  }

  const run = (async (): Promise<T> => {
  let attempt = 0;

  while (attempt < maxNetworkAttempts) {
    let timeoutController: AbortController | null = null;
    let timeoutHandle: ReturnType<typeof setTimeout> | null = null;
    try {
      let signal = init?.signal;
      if (timeoutMs > 0) {
        timeoutController = new AbortController();
        signal = timeoutController.signal;
        timeoutHandle = setTimeout(() => timeoutController?.abort(), timeoutMs);
        if (init?.signal) {
          if (init.signal.aborted) timeoutController.abort();
          else init.signal.addEventListener("abort", () => timeoutController?.abort(), { once: true });
        }
      }

      const res = await fetch(`${API_URL}${path}`, {
        ...init,
        headers,
        credentials: CREDENTIALS,
        cache: "no-store",
        signal,
      });

      if (res.status === 401 && useAuth && allowRefresh) {
        const refreshed = await tryRefreshToken();
        if (refreshed) {
          return request<T>(path, init, useAuth, false, behavior);
        }
      }

      if (res.status === 503) {
        const text = await res.clone().text();
        if (reportDeactivated(res.status, text)) throw new Error(text);
      }

      if (!res.ok) {
        const canRetryStatus = retryable && TRANSIENT_HTTP_STATUSES.has(res.status) && attempt < maxNetworkAttempts - 1;
        if (canRetryStatus) {
          await res.text();
          const backoffMs = NETWORK_RETRY_BACKOFF_MS[Math.min(attempt, NETWORK_RETRY_BACKOFF_MS.length - 1)];
          await sleep(backoffMs);
          attempt += 1;
          continue;
        }
        if (res.status === 403) {
          const text = await res.clone().text();
          if (reportAccessNeeded(res.status, text)) throw new Error(text);
        }
        if (DEMO_BUILD && isDemoFallbackEnabled()) {
          const fallback = demoFallbackRequest(path, init, session);
          if (fallback !== null) return fallback as T;
        }
        const text = await res.text();
        throw new Error(text || `API ${res.status}`);
      }

      const payload = (await res.json()) as T;
      if (DEMO_BUILD && isDemoFallbackEnabled() && (DEMO_FORCE || (DEMO_FILL_EMPTY && shouldUseFallbackForPayload(payload)))) {
        const fallback = demoFallbackRequest(path, init, session);
        if (fallback !== null) return fallback as T;
      }
      return payload;
    } catch (err) {
      if (timeoutController?.signal.aborted && !init?.signal?.aborted) {
        const canRetryTimeout = retryable && attempt < maxNetworkAttempts - 1;
        if (canRetryTimeout) {
          const backoffMs = NETWORK_RETRY_BACKOFF_MS[Math.min(attempt, NETWORK_RETRY_BACKOFF_MS.length - 1)];
          await sleep(backoffMs);
          attempt += 1;
          continue;
        }
        if (DEMO_BUILD && isDemoFallbackEnabled()) {
          const fallback = demoFallbackRequest(path, init, session);
          if (fallback !== null) return fallback as T;
        }
        throw new Error(`Request timed out for ${path}`);
      }
      const canRetry = retryable && isLikelyNetworkFetchError(err) && attempt < maxNetworkAttempts - 1;
      if (canRetry) {
        const backoffMs = NETWORK_RETRY_BACKOFF_MS[Math.min(attempt, NETWORK_RETRY_BACKOFF_MS.length - 1)];
        await sleep(backoffMs);
        attempt += 1;
        continue;
      }
      if (DEMO_BUILD && isDemoFallbackEnabled()) {
        const fallback = demoFallbackRequest(path, init, session);
        if (fallback !== null) return fallback as T;
      }
      if (retryable && isLikelyNetworkFetchError(err)) {
        const apiAlive = await probeApiHealth();
        if (!apiAlive) {
          throw new Error(
            `Failed to fetch: API is temporarily unreachable on ${API_URL}. Keep the API process running and retry.`
          );
        }
      }
      throw err;
    } finally {
      if (timeoutHandle !== null) clearTimeout(timeoutHandle);
    }
  }

  // Defensive fallback; loop should always return or throw.
  throw new Error("Request failed after retry attempts");
  })();

  if (dedupeEligible) {
    inflightGetRequests.set(dedupeKey, run as Promise<unknown>);
  }
  try {
    return await run;
  } finally {
    if (dedupeEligible && inflightGetRequests.get(dedupeKey) === run) {
      inflightGetRequests.delete(dedupeKey);
    }
  }
}

async function requestBlob(path: string, init?: RequestInit, allowRefresh = true, onResponse?: (res: Response) => void): Promise<Blob> {
  const headers = sessionHeaders(new Headers(init?.headers || {}));
  const session = getSession();

  if (!session?.tenantId) throw new Error("No tenant selected");
  headers.set("X-Tenant-ID", session.tenantId);

  const res = await fetch(`${API_URL}${path}`, {
    ...init,
    headers,
    credentials: CREDENTIALS,
    cache: "no-store",
  });

  if (res.status === 401 && allowRefresh) {
    if (await tryRefreshToken()) return requestBlob(path, init, false, onResponse);
  }

  if (!res.ok) {
    const text = await res.text();
    reportDeactivated(res.status, text);
    reportAccessNeeded(res.status, text);
    throw new Error(text || `API ${res.status}`);
  }

  onResponse?.(res);
  return res.blob();
}

/**
 * A .hawkai licence file to POST /licence/import (/settings/guide/licence). Refusals keep the API's own sentence
 * ({"error": ...}) as the error's message, for errorMessageFrom.
 */
async function uploadLicence(file: File, allowRefresh = true): Promise<LicenceImported> {
  const session = getSession();
  if (!session?.tenantId) throw new Error(JSON.stringify({ error: "Sign in first." }));
  const headers = sessionHeaders();
  headers.set("X-Tenant-ID", session.tenantId);
  const form = new FormData();
  form.set("file", file, file.name);
  const res = await fetch(`${API_URL}/licence/import`, { method: "POST", headers, body: form, credentials: CREDENTIALS, cache: "no-store" });
  if (res.status === 401 && allowRefresh && (await tryRefreshToken())) return uploadLicence(file, false);
  const text = await res.text();
  if (!res.ok) throw new Error(text || `API ${res.status}`);
  return JSON.parse(text) as LicenceImported;
}

async function requestMultipart<T>(path: string, form: FormData, allowRefresh = true): Promise<T> {
  const session = getSession();
  if (!session?.tenantId) throw new Error("No tenant selected");
  if (!form.has("tenant_id")) form.set("tenant_id", session.tenantId);

  const headers = sessionHeaders();
  headers.set("X-Tenant-ID", session.tenantId);
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers,
    body: form,
    credentials: CREDENTIALS,
    cache: "no-store",
  });
  if (res.status === 401 && allowRefresh) {
    if (await tryRefreshToken()) return requestMultipart<T>(path, form, false);
  }
  if (!res.ok) {
    let message = `API ${res.status}`;
    if (res.status === 503 && reportDeactivated(res.status, await res.clone().text())) throw new Error(message);
    try {
      const payload = await res.json() as { detail?: unknown; message?: unknown; code?: unknown };
      const detail = payload.detail && typeof payload.detail === "object"
        ? payload.detail as { code?: unknown; message?: unknown }
        : null;
      message = String(detail?.code || payload.code || message);
    } catch {
      // Keep the status code when the server does not return a JSON error envelope.
    }
    throw new Error(message);
  }
  return await res.json() as T;
}

/**
 * Sign out: the API revokes this sign-in's refresh token and clears the session cookies (only it can: they are
 * HttpOnly). What the console remembers goes in any case, even when the API cannot be reached.
 */
export async function signOut(): Promise<void> {
  try {
    await api.signOut();
  } catch {
    // Signed out here all the same; the refresh token ends by itself.
  }
  clearSession();
}

function boundedQuery<T extends object>(params: T): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== null && String(value).trim() !== "") {
      query.set(key, String(value));
    }
  }
  const encoded = query.toString();
  return encoded ? `?${encoded}` : "";
}

/** The signed-in person (/auth/me): with the product licence's end for a tenant's owners and admins. */
export type CurrentUser = {
  id: string;
  email: string;
  full_name: string;
  tenants: { id: string; name: string; role: string }[];
  licence?: AdminLicence | null;
  // A temporary password to change, and the terms of use, first (/settings/guide/install).
  must_change_password?: boolean;
  // That password is the first administrator's, printed by the installer (not one an administrator set).
  password_from_installer?: boolean;
  terms?: TermsState | null;
  version?: string;
  // Two-step sign-in for this person (/settings/guide/people-and-access).
  two_step?: TwoStepState | null;
};

export const api = {
  login: (email: string, password: string) =>
    request<LoginResponse | TwoStepChallenge>("/auth/login", {
      method: "POST",
      body: JSON.stringify({ email, password }),
    }, false),
  // Sign-in (/settings/guide/people-and-access): the second step, "Forgot your password?", one's own two-step sign-in, and the
  // administrator's sign-in rules.
  signInOptions: () => request<{ passwordReset: boolean; ssoPasswordAdminsOnly: boolean; banner?: string }>("/auth/sign-in-options", undefined, false),
  twoStep: (ticket: string, code: string) =>
    request<LoginResponse & { recovery_codes?: string[] }>("/auth/two-step", { method: "POST", body: JSON.stringify({ ticket, code }) }, false),
  askPasswordReset: (email: string) =>
    request<{ message: string }>("/auth/password-reset", { method: "POST", body: JSON.stringify({ email }) }, false),
  checkPasswordReset: (token: string) =>
    request<{ email: string; minutes: number }>("/auth/password-reset/check", { method: "POST", body: JSON.stringify({ token }) }, false),
  confirmPasswordReset: (token: string, password: string) =>
    request<{ email: string }>("/auth/password-reset/confirm", { method: "POST", body: JSON.stringify({ token, password }) }, false),
  twoStepSetup: () => request<TwoStepSetup>("/auth/me/two-step/setup", { method: "POST", body: "{}" }),
  twoStepEnable: (code: string) =>
    request<{ recovery_codes: string[]; two_step: TwoStepState }>("/auth/me/two-step/enable", { method: "POST", body: JSON.stringify({ code }) }),
  twoStepDisable: (code: string) =>
    request<{ two_step: TwoStepState }>("/auth/me/two-step/disable", { method: "POST", body: JSON.stringify({ code }) }),
  twoStepRecoveryCodes: (code: string) =>
    request<{ recovery_codes: string[]; two_step: TwoStepState }>("/auth/me/two-step/recovery-codes", { method: "POST", body: JSON.stringify({ code }) }),
  getSignInSettings: () => request<SignInSettings>("/auth/sign-in-settings"),
  saveSignInSettings: (patch: Record<string, unknown>) =>
    request<SignInSettings>("/auth/sign-in-settings", { method: "PUT", body: JSON.stringify(patch) }),
  sendTestEmail: () =>
    request<SignInSettings & { message: string }>("/auth/sign-in-settings/test-email", { method: "POST", body: "{}" }),
  signInPeople: () => request<{ people: SignInPerson[] }>("/auth/sign-in-settings/people"),
  resetPersonTwoStep: (userId: string) =>
    request<{ people: SignInPerson[] }>(`/auth/sign-in-settings/people/${encodeURIComponent(userId)}/two-step`, { method: "DELETE" }),
  resetPersonSsoLink: (userId: string) =>
    request<{ people: SignInPerson[] }>(`/auth/sign-in-settings/people/${encodeURIComponent(userId)}/sso-link`, { method: "DELETE" }),
  // People, teams and roles (FTR Command Center's people.js / teams.js; apps/api/app/api/routers/iam.py).
  iamPeople: () => request<IamView>("/iam/people"),
  iamAddPerson: (body: Record<string, unknown>) =>
    request<{ user: { id: string; email: string }; temporary: string | null; existingAccount: boolean; welcomed: boolean }>("/iam/people", { method: "POST", body: JSON.stringify(body) }),
  iamChangePerson: (id: string, body: Record<string, unknown>) =>
    request<{ ok: boolean; changed: string[] }>(`/iam/people/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(body) }),
  iamPersonAction: (id: string, action: "reset" | "unlock" | "signout" | "two-step-reset" | "welcome" | "approve") =>
    request<{ ok?: boolean; temporary?: string }>(`/iam/people/${encodeURIComponent(id)}/${action}`, { method: "POST", body: "{}" }),
  iamRemovePerson: (id: string) => request<{ ok: boolean }>(`/iam/people/${encodeURIComponent(id)}`, { method: "DELETE" }),
  iamSaveRole: (id: string, body: Record<string, unknown>) =>
    request<{ role: IamRole }>(`/iam/roles/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify(body) }),
  iamRemoveRole: (id: string) => request<{ ok: boolean }>(`/iam/roles/${encodeURIComponent(id)}`, { method: "DELETE" }),
  iamSaveTeam: (id: string | null, body: Record<string, unknown>) =>
    request<{ team: { id: string; name: string } }>(id ? `/iam/teams/${encodeURIComponent(id)}` : "/iam/teams", { method: id ? "PUT" : "POST", body: JSON.stringify(body) }),
  iamRemoveTeam: (id: string) => request<{ ok: boolean }>(`/iam/teams/${encodeURIComponent(id)}`, { method: "DELETE" }),
  iamJoinSettings: () => request<IamJoinSettings>("/iam/join-settings"),
  iamSaveJoinSettings: (body: Record<string, unknown>) =>
    request<IamJoinSettings>("/iam/join-settings", { method: "PUT", body: JSON.stringify(body) }),
  // Without a workspace: the installation's only one (the sign-in page has no workspace box).
  joinAvailable: (workspace = "") =>
    request<{ available: boolean; domains: string[]; workspace?: string }>(`/auth/join${workspace ? `?workspace=${encodeURIComponent(workspace)}` : ""}`, undefined, false),
  askToJoin: (workspace: string, email: string) =>
    request<{ message: string }>("/auth/join", { method: "POST", body: JSON.stringify({ workspace, email }) }, false),
  checkJoinLink: (token: string) => request<JoinLink>("/auth/join/check", { method: "POST", body: JSON.stringify({ token }) }, false),
  confirmJoin: (body: Record<string, unknown>) =>
    request<LoginResponse | { ok: boolean; twoStep: true; message: string }>("/auth/join/confirm", { method: "POST", body: JSON.stringify(body) }, false),
  oidcProviders: (workspace = "") =>
    request<OIDCProviderList>(`/auth/oidc/providers${workspace ? `?workspace=${encodeURIComponent(workspace)}` : ""}`, undefined, false),
  oidcDiscover: (email: string) =>
    request<OIDCProviderList>("/auth/oidc/discover", { method: "POST", body: JSON.stringify({ email }) }, false),
  oidcStart: (providerKey: string, workspace = "") =>
    request<{ authorization_url: string }>(
      `/auth/oidc/${encodeURIComponent(providerKey)}/start${workspace ? `?workspace=${encodeURIComponent(workspace)}` : ""}`,
      undefined,
      false,
    ),
  // The workspaces the person belongs to, and opening another (new session cookies for it).
  myTenants: () => request<{ items: Array<{ id: string; name: string; role: string }> }>("/auth/tenants"),
  selectTenant: (tenantId: string) =>
    request<LoginResponse>("/auth/select-tenant", { method: "POST", body: JSON.stringify({ tenant_id: tenantId }) }),
  oidcComplete: (ticket: string) =>
    request<LoginResponse>("/auth/oidc/complete", { method: "POST", body: JSON.stringify({ ticket }) }, false),
  me: () => request<CurrentUser>("/auth/me"),
  // Sign out: the API revokes this sign-in's refresh token and clears the session cookies.
  signOut: () => request<{ ok: boolean }>("/auth/refresh/sign-out", { method: "POST", body: "{}" }, false),
  // First sign-in (/settings/guide/install): a new password, the terms of use, and the first administrator's setup code.
  changePassword: (current: string, next: string) =>
    request<LoginResponse>("/auth/me/password", { method: "POST", body: JSON.stringify({ current, next }) }),
  // Before or after signing in: the session cookie, when there is one, says whose acceptance to show.
  getTerms: () => request<TermsView>("/terms", undefined, false),
  acceptTerms: (payload: TermsAcceptPayload) => request<{ terms: TermsState }>("/terms/accept", { method: "POST", body: JSON.stringify(payload) }),
  // The accepted licence agreement (Settings → About): the acceptances, their emailed copy, send again, download.
  getTermsAcceptances: () => request<TermsAcceptances>("/terms/acceptances"),
  resendTermsCopy: (id: string, to?: string) =>
    request<TermsAcceptance>(`/terms/acceptances/${encodeURIComponent(id)}/resend`, { method: "POST", body: JSON.stringify(to ? { to } : {}) }),
  downloadTermsCopy: (id: string, format: "html" | "txt") => requestBlob(`/terms/acceptances/${encodeURIComponent(id)}/copy?format=${format}`),
  setupStatus: () => request<{ setup: boolean }>("/setup", undefined, false),
  setup: (payload: { code: string; email: string; name: string; password: string }) =>
    request<LoginResponse | TwoStepChallenge>("/setup", { method: "POST", body: JSON.stringify(payload) }, false),
  // The product licence (/settings/guide/licence): the trial, the installation ID, the .hawkai licence file.
  getLicence: () => request<LicenceStatus>("/licence", undefined, false),
  getLicenceStatus: () => request<LicenceView>("/licence/status"),
  downloadLicenceRequest: () => requestBlob("/licence/request"),
  importLicence: (file: File) => uploadLicence(file),
  // Settings → HTTPS (/settings/guide/https).
  getHttps: () => request<HttpsStatus>("/https"),
  setHttpsMode: (mode: HttpsMode, confirm = false) =>
    request<HttpsStatus>("/https/mode", { method: "POST", body: JSON.stringify({ mode, confirm }) }),
  setHttpsHardening: (body: { minVersion: string; hsts: { enabled: boolean; includeSubDomains: boolean; maxAge: number } }) =>
    request<HttpsStatus>("/https/hardening", { method: "POST", body: JSON.stringify(body) }),
  inspectHttpsCertificate: (files: UploadFile[], passphrase: string) =>
    request<HttpsCertificateReport>("/https/inspect", { method: "POST", body: JSON.stringify({ files, passphrase }) }),
  installHttpsCertificate: (files: UploadFile[], passphrase: string, confirm = false) =>
    request<{ report: HttpsCertificateReport; status: HttpsStatus }>("/https/certificate", { method: "POST", body: JSON.stringify({ files, passphrase, confirm }) }),
  restorePreviousHttpsCertificate: () => request<HttpsStatus>("/https/certificate/previous", { method: "POST", body: "{}" }),
  createHttpsRequest: (names: string[], organization: string) =>
    request<{ csr: string; status: HttpsStatus }>("/https/request", { method: "POST", body: JSON.stringify({ names, organization }) }),
  downloadHttpsRequest: () => requestBlob("/https/request.csr"),
  makeSelfSignedCertificate: (names: string[]) => request<HttpsStatus>("/https/self-signed", { method: "POST", body: JSON.stringify({ names }) }),
  startLetsEncrypt: (body: { names: string[]; email: string; agree: boolean; staging: boolean }) =>
    request<AcmeStatus>("/https/acme", { method: "POST", body: JSON.stringify(body) }),
  renewLetsEncrypt: () => request<AcmeStatus>("/https/acme/renew", { method: "POST", body: "{}" }),
  stopLetsEncrypt: () => request<AcmeStatus>("/https/acme", { method: "DELETE" }),
  // Settings → Backups & health (app/api/routers/backups.py)
  getBackups: () => request<BackupsStatus>("/backups"),
  getBackupNotice: () => request<{ notice: BackupNotice }>("/backups/notice"),
  backUpNow: () => request<{ name: string; backups: BackupFile[] }>("/backups", { method: "POST", body: "{}" }),
  downloadBackup: (name: string) => requestBlob(`/backups/${encodeURIComponent(name)}`),
  showBackupKey: () => request<BackupKeyShown>("/backups/key/show", { method: "POST", body: "{}" }),
  confirmBackupKey: () => request<{ encryption: BackupEncryption }>("/backups/key/confirm", { method: "POST", body: "{}" }),
  turnOnBackupEncryption: () => request<{ encryption: BackupEncryption }>("/backups/encryption", { method: "POST", body: JSON.stringify({ on: true }) }),
  /** A backup file to check (`check`) or to stage for the next start; the passphrase only when one was typed. */
  restoreBackup: async (file: File, passphrase: string, check: boolean) => {
    const blob = await requestBlob(`/backups/restore${check ? "?check=1" : ""}`, {
      method: "POST",
      body: file,
      headers: { "Content-Type": "application/octet-stream", ...(passphrase ? { "X-Backup-Passphrase": passphrase } : {}) },
    });
    return JSON.parse(await blob.text()) as { backup: BackupInfo; staged?: boolean; restartRequired?: boolean };
  },
  cancelRestore: () => request<{ pendingRestore: boolean }>("/backups/restore", { method: "DELETE" }),
  getReadiness: () => request<Readiness>("/backups/readiness"),
  // Records → Audit log and Connector API activity (app/api/routers/records.py)
  getAuditLog: (query: string) => request<AuditPage>(`/audit/log${query ? `?${query}` : ""}`),
  verifyAuditLog: () => request<AuditVerify>("/audit/log/verify"),
  exportAuditLog: (format: "csv" | "jsonl" | "cef", query: string) => requestBlob(`/audit/log/export.${format}${query ? `?${query}` : ""}`),
  /** The export and its detached evidence signature (the X-Hawk-Evidence-Signature header, '' when none). */
  exportAuditLogSigned: async (format: "csv" | "jsonl" | "cef", query: string) => {
    let signature = "";
    const blob = await requestBlob(`/audit/log/export.${format}${query ? `?${query}` : ""}`, undefined, true, (res) => {
      signature = res.headers.get("X-Hawk-Evidence-Signature") ?? "";
    });
    return { blob, signature };
  },
  // Evidence signing (app/api/routers/evidence_signing.py)
  getEvidenceSigning: () => request<EvidenceSigning>("/evidence-signing"),
  rotateEvidenceSigning: () => request<{ rotated: boolean; active: string; previous: string | null; status: EvidenceSigning }>("/evidence-signing/rotate", { method: "POST" }),
  getConnectorActivity: (query: string) => request<ConnectorActivity>(`/connector-activity${query ? `?${query}` : ""}`),
  exportConnectorActivity: () => requestBlob("/connector-activity/export.csv"),
  exportUserActivity: () => requestBlob("/activity/log/export.csv"),
  // Get help (app/api/routers/support.py)
  getSupport: () => request<SupportList>("/support"),
  getSupportRequest: (id: string) => request<{ team: boolean; request: SupportRequest }>(`/support/${encodeURIComponent(id)}`),
  raiseSupportRequest: (body: { kind: SupportKind; subject: string; text: string; priority: string; page?: string }) =>
    request<{ request: SupportRequest; emailed: Emailed }>("/support", { method: "POST", body: JSON.stringify(body) }),
  writeOnSupportRequest: (id: string, text: string) =>
    request<{ request: SupportRequest; emailed: Emailed }>(`/support/${encodeURIComponent(id)}/messages`, { method: "POST", body: JSON.stringify({ text }) }),
  setSupportStatus: (id: string, status: string) =>
    request<{ request: SupportRequest; emailed: Emailed }>(`/support/${encodeURIComponent(id)}/status`, { method: "POST", body: JSON.stringify({ status }) }),
  supportMailto: (kind: SupportKind) => request<{ href: string }>(`/support/mailto/${kind}`),
  getSupportSettings: () => request<SupportChannel>("/support/settings"),
  saveSupportSettings: (body: { mode?: string; email?: string }) => request<SupportChannel>("/support/settings", { method: "PUT", body: JSON.stringify(body) }),
  // Network & proxy and trusted certificates (app/api/routers/network.py)
  getNetwork: () => request<NetworkInfo>("/network"),
  checkNetwork: (body: Record<string, string>) => request<NetworkCheck>("/network/check", { method: "POST", body: JSON.stringify(body) }),
  saveNetwork: (body: Record<string, string>) => request<NetworkInfo & { results: NetworkCheck["results"] }>("/network", { method: "PUT", body: JSON.stringify(body) }),
  removeNetwork: () => request<NetworkInfo>("/network", { method: "DELETE" }),
  getTrusted: () => request<{ certificates: TrustedCertificate[] }>("/trust"),
  diagnoseCertificate: (host: string, port: number) => request<TrustDiagnosis>("/trust/diagnose", { method: "POST", body: JSON.stringify({ host, port }) }),
  trustPresented: (host: string, port: number, fingerprint256: string) =>
    request<TrustDiagnosis & { certificates: TrustedCertificate[] }>("/trust/presented", { method: "POST", body: JSON.stringify({ host, port, fingerprint256 }) }),
  uploadCertificate: (data: string, host?: string, port?: number) =>
    request<{ added: TrustedCertificate[]; trusted: boolean | null; certificates: TrustedCertificate[] }>("/trust/upload", { method: "POST", body: JSON.stringify({ data, ...(host ? { host, port } : {}) }) }),
  removeTrusted: (fingerprint: string) => request<{ certificates: TrustedCertificate[] }>(`/trust/${encodeURIComponent(fingerprint)}`, { method: "DELETE" }),
  setReadiness: (id: string, accept: boolean) =>
    request<{ ok: boolean }>(`/backups/readiness/${encodeURIComponent(id)}`, { method: "PUT", body: JSON.stringify({ accept }) }),
  // Settings → General, Branding, Email (SMTP) and About, and the Settings menu (app/api/routers/settings_console.py).
  getSettingsMe: () => request<SettingsMe>("/settings/me"),
  getGeneralSettings: () => request<GeneralView>("/settings/general"),
  getBranding: () => request<BrandingView>("/branding", undefined, false),
  saveBranding: (patch: BrandingPatch) => request<BrandingView>("/settings/branding", { method: "PUT", body: JSON.stringify(patch) }),
  getSmtp: () => request<SmtpView>("/settings/smtp"),
  saveSmtp: (body: { smtp?: Partial<SmtpSettings> & { password?: string }; passwordReset?: string; test?: boolean }) =>
    request<SmtpView>("/settings/smtp", { method: "PUT", body: JSON.stringify(body) }),
  testSmtp: () => request<SmtpView & { message: string }>("/settings/smtp/test", { method: "POST", body: "{}" }),
  sendTestSmtp: (to: string) => request<{ message: string }>("/settings/smtp/send-test", { method: "POST", body: JSON.stringify({ to }) }),
  forgetSmtp: () => request<SmtpView>("/settings/smtp", { method: "DELETE" }),
  getAbout: () => request<AboutView>("/settings/about"),
  // Settings → AI system approvals (app/api/routers/ai_system_approvals.py).
  getApprovalPolicy: () => request<ApprovalPolicyView>("/settings/ai-system-approvals"),
  saveApprovalPolicy: (policy: ApprovalPolicy) =>
    request<ApprovalPolicyView>("/settings/ai-system-approvals", { method: "PUT", body: JSON.stringify(policy) }),
  listAiSystemApprovals: (status: "pending" | "approved" | "denied" | "expired" | "all" = "pending") =>
    request<{ items: ApprovalRequestView[]; total: number }>(`/ai-system-approvals?status=${encodeURIComponent(status)}`),
  decideAiSystemApproval: (requestId: string, body: ApprovalDecision) =>
    request<{ request: ApprovalRequestView; grant: ApprovalGrantView | null; ai_system_status: string | null }>(
      `/ai-system-approvals/${encodeURIComponent(requestId)}/decision`,
      { method: "POST", body: JSON.stringify(body) },
    ),
  listAiSystemApprovalGrants: (state: "ACTIVE" | "all" = "ACTIVE") =>
    request<{ items: ApprovalGrantView[]; total: number }>(`/ai-system-approvals/grants?state=${encodeURIComponent(state)}`),
  revokeAiSystemApproval: (grantId: string, reason: string) =>
    request<{ grant: ApprovalGrantView; ai_system_status: string | null }>(`/ai-system-approvals/grants/${encodeURIComponent(grantId)}/revoke`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  requestAiSystemApproval: (aiSystemId: string, body: { scope?: ApprovalScope; duration_hours?: number; reason?: string; target_status?: "approved" | "active" }) =>
    request<{ request: ApprovalRequestView; ai_system_status: string | null }>(`/ai-systems/${encodeURIComponent(aiSystemId)}/approval-requests`, {
      method: "POST",
      body: JSON.stringify(body),
    }),
  // Settings → Compliance (apps/api/app/api/routers/compliance.py; /settings/guide/compliance).
  getCompliance: () => request<ComplianceView>("/compliance"),
  saveCompliance: (patch: Partial<ComplianceSettings>) =>
    request<ComplianceView>("/compliance/settings", { method: "PUT", body: JSON.stringify(patch) }),
  /** The incident report for a time window, and its detached evidence signature ('' when none). */
  incidentReport: async (query: string) => {
    let signature = "";
    const blob = await requestBlob(`/compliance/incident-report${query ? `?${query}` : ""}`, undefined, true, (res) => {
      signature = res.headers.get("X-Hawk-Evidence-Signature") ?? "";
    });
    return { blob, signature };
  },
  // Framework packs on Settings → Compliance (apps/api/app/services/compliance_packs).
  getCompliancePacks: () => request<PacksOverview>("/compliance/packs"),
  getCompliancePack: (id: string) => request<PackView>(`/compliance/packs/${encodeURIComponent(id)}`),
  recordRequirement: (packId: string, requirementId: string, body: { status: "in_place" | "not_applicable"; note: string; reference?: string }) =>
    request<PackView>(`/compliance/packs/${encodeURIComponent(packId)}/requirements/${encodeURIComponent(requirementId)}/record`, {
      method: "PUT",
      body: JSON.stringify(body),
    }),
  removeRequirementRecord: (packId: string, requirementId: string) =>
    request<PackView>(`/compliance/packs/${encodeURIComponent(packId)}/requirements/${encodeURIComponent(requirementId)}/record`, { method: "DELETE" }),
  /** A pack's signed evidence bundle for a window: a zip whose manifest.json carries the evidence signature. */
  packEvidence: (id: string, query: string) => requestBlob(`/compliance/packs/${encodeURIComponent(id)}/evidence${query ? `?${query}` : ""}`),
  // Settings → Hands-off and the self-check (app/api/routers/hands_off.py); the emailed links need no sign-in.
  getHandsOff: () => request<HandsOffView>("/hands-off"),
  saveHandsOff: (body: { handsOff: Partial<Omit<HandsOffSettings, "statusTo">> & { statusTo?: string | string[] } }) =>
    request<HandsOffView>("/hands-off", { method: "PUT", body: JSON.stringify(body) }),
  sendHandsOffStatus: () => request<{ sent: number }>("/hands-off/status", { method: "POST", body: "{}" }),
  checkNow: () => request<{ health: SelfCheckHealth }>("/hands-off/check", { method: "POST", body: "{}" }),
  getSelfCheck: () => request<{ health: SelfCheckHealth }>("/hands-off/health"),
  describeHandsOffLink: (token: string) => request<LinkAnswer>("/hands-off/link", { method: "POST", body: JSON.stringify({ token }) }, false),
  confirmHandsOffLink: (token: string) => request<LinkAnswer>("/hands-off/link/confirm", { method: "POST", body: JSON.stringify({ token }) }, false),
  // Settings → Updates (app/api/routers/updates.py)
  getUpdates: () => request<UpdatesStatus>("/updates"),
  checkForUpdates: () => request<UpdatesStatus>("/updates/check", { method: "POST", body: "{}" }),
  installVersion: (version: string) => request<UpdatesStatus & { to: string }>("/updates/install", { method: "POST", body: JSON.stringify({ version }) }),
  saveUpdateSettings: (patch: Partial<Pick<UpdateSettings, "auto" | "windowHour" | "channel">>) =>
    request<UpdatesStatus>("/updates/settings", { method: "PUT", body: JSON.stringify(patch) }),
  restartHawk: () => request<{ restarting: boolean }>("/updates/restart", { method: "POST", body: "{}" }),
  downloadUpdateReport: () => requestBlob("/updates/report"),
  // Self-recovery and the diagnostics bundle on Settings → Backups & health (app/api/routers/diagnostics.py)
  getDiagnostics: () => request<DiagnosticsView>("/diagnostics"),
  runSelfRecovery: () => request<DiagnosticsView>("/diagnostics/recovery/run", { method: "POST", body: "{}" }),
  retrySelfRecovery: (reference: string) => request<DiagnosticsView>(`/diagnostics/recovery/${encodeURIComponent(reference)}/retry`, { method: "POST", body: "{}" }),
  downloadDiagnosticsBundle: async (prepared = false) => {
    let disposition: string | null = null;
    const blob = await requestBlob(prepared ? "/diagnostics/bundle/prepared" : "/diagnostics/bundle", undefined, true, (res) => {
      disposition = res.headers.get("Content-Disposition");
    });
    return { blob, disposition: disposition as string | null };
  },
  checkIntegrity: () => request<Integrity>("/integrity/check", { method: "POST", body: "{}" }),
  getIntegrityNotice: () => request<{ notice: { state: IntegrityState; summary: string } | null }>("/integrity/notice"),
  getPlatformMode: () => request<PlatformModeResponse>("/system/platform-mode"),
  updatePlatformMode: (platformMode: PlatformMode) =>
    request<PlatformModeResponse>("/system/platform-mode", {
      method: "POST",
      body: JSON.stringify({ platform_mode: platformMode }),
    }),
  listAISystems: () => request<ListEnvelope<AISystem>>("/ai-systems"),
  createAISystem: (payload: Record<string, unknown>) => request("/ai-systems", { method: "POST", body: JSON.stringify(payload) }),
  updateAISystem: (aiSystemId: string, payload: Record<string, unknown>) =>
    request(`/ai-systems/${aiSystemId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  listPolicyPacks: () => request<ListEnvelope<PolicyPack>>("/policies/packs"),
  listPolicyPackPlatformCatalog: (params?: { vertical?: string; department_persona?: string; surface?: string; package_tier?: string }) => {
    const query = new URLSearchParams();
    if (params?.vertical) query.set("vertical", params.vertical);
    if (params?.department_persona) query.set("department_persona", params.department_persona);
    if (params?.surface) query.set("surface", params.surface);
    if (params?.package_tier) query.set("package_tier", params.package_tier);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<{ items: PolicyPackPlatformDefinition[]; count: number }>(`/policy-pack-platform/catalog${suffix}`);
  },
  listPolicyPackPlatformFrameworkAtlas: () =>
    request<PolicyPackFrameworkAtlas>("/policy-pack-platform/framework-atlas"),
  getPolicyPackPlatformDefinition: (definitionId: string) =>
    request<PolicyPackPlatformDefinition>(`/policy-pack-platform/definitions/${encodeURIComponent(definitionId)}`),
  previewPolicyPackPlatformDefinition: (definitionId: string, surfaces?: string[]) => {
    const query = new URLSearchParams();
    for (const surface of surfaces || []) query.append("surfaces", surface);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<{ definition: PolicyPackPlatformDefinition; capability_coverage: PolicyPackCapabilityCoverage }>(
      `/policy-pack-platform/definitions/${encodeURIComponent(definitionId)}/preview${suffix}`,
    );
  },
  applyPolicyPackPlatformDefinition: (definitionId: string, payload: Record<string, unknown>) =>
    request<{ instance: PolicyPackPlatformInstance; capability_coverage: PolicyPackCapabilityCoverage }>(
      `/policy-pack-platform/definitions/${encodeURIComponent(definitionId)}/apply`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  listPolicyPackPlatformInstances: () =>
    request<{ items: PolicyPackPlatformInstance[]; count: number }>("/policy-pack-platform/instances"),
  simulatePolicyPackPlatformInstance: (instanceId: string, historical_events?: Array<Record<string, unknown>>) =>
    request<PolicyPackSimulation>(`/policy-pack-platform/instances/${encodeURIComponent(instanceId)}/simulate`, {
      method: "POST",
      body: JSON.stringify(historical_events ? { historical_events } : {}),
    }),
  transitionPolicyPackPlatformInstance: (instanceId: string, targetState: string, approverRef?: string) =>
    request<PolicyPackPlatformInstance>(`/policy-pack-platform/instances/${encodeURIComponent(instanceId)}/transition`, {
      method: "POST",
      body: JSON.stringify({ target_state: targetState, ...(approverRef ? { approver_ref: approverRef } : {}) }),
    }),
  comparePolicyPackPlatformUpdate: (instanceId: string, definitionId: string) =>
    request<Record<string, unknown>>(`/policy-pack-platform/instances/${encodeURIComponent(instanceId)}/updates/${encodeURIComponent(definitionId)}/compare`),
  acceptPolicyPackPlatformUpdate: (instanceId: string, definitionId: string, reason: string) =>
    request<PolicyPackPlatformInstance>(`/policy-pack-platform/instances/${encodeURIComponent(instanceId)}/updates/${encodeURIComponent(definitionId)}/accept`, {
      method: "POST",
      body: JSON.stringify({ reason }),
    }),
  createPolicyPackPlatformGroup: (payload: Record<string, unknown>) =>
    request<{ id: string; group_key: string; name: string; group_type: string; membership_rule: Record<string, unknown>; nested_group_ids: string[]; active: boolean }>(
      "/policy-pack-platform/groups",
      { method: "POST", body: JSON.stringify(payload) },
    ),
  previewPolicyPackPlatformGroupMembers: (groupId: string) =>
    request<{ group_id: string; group_key: string; membership_rule: Record<string, unknown>; members: string[] }>(
      `/policy-pack-platform/groups/${encodeURIComponent(groupId)}/members`,
    ),
  policyPackPlatformEffectivePolicy: (params: Record<string, string | undefined>) => {
    const query = new URLSearchParams();
    Object.entries(params).forEach(([key, value]) => { if (value) query.set(key, value); });
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<{ final: Record<string, unknown>; source_policy_versions: string[]; matched: boolean }>(`/policy-pack-platform/effective-policy${suffix}`);
  },
  createPolicyPack: (payload: Record<string, unknown>) => request("/policies/packs", { method: "POST", body: JSON.stringify(payload) }),
  updatePolicyPack: (packId: string, payload: Record<string, unknown>) =>
    request(`/policies/packs/${packId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  ensurePilotPolicyPack: (payload?: { activate?: boolean }) =>
    request<{
      pack: PolicyPack;
      policy_version: PolicyVersion;
      applied: "created" | "updated";
    }>("/policies/pilot-pack/ensure", {
      method: "POST",
      body: JSON.stringify({ activate: payload?.activate ?? true }),
    }),
  runningPolicyStatus: () => request<RunningPolicyStatus>("/policies/running"),
  listPolicyVersions: (packId: string) => request<ListEnvelope<PolicyVersion>>(`/policies/packs/${packId}/versions`),
  createPolicyVersion: (packId: string, payload: Record<string, unknown>) =>
    request<PolicyVersion>(`/policies/packs/${packId}/versions`, { method: "POST", body: JSON.stringify(payload) }),
  getPolicyVersionScopedRules: (policyVersionId: string) =>
    request<PolicyScopedRulesResponse>(`/policies/versions/${encodeURIComponent(policyVersionId)}/scoped-rules`),
  updatePolicyVersionScopedRules: (policyVersionId: string, scopedRules: PolicyScopedRule[]) =>
    request<PolicyScopedRulesResponse>(`/policies/versions/${encodeURIComponent(policyVersionId)}/scoped-rules`, {
      method: "PATCH",
      body: JSON.stringify({ scoped_rules: scopedRules }),
    }),
  listEnforcementEvents: () => request<ListEnvelope<EnforcementEvent>>("/enforcement/events"),
  extensionPolicySync: () => request<ExtensionPolicySync>("/extension/policy-sync"),
  listApprovals: (statusFilter: string) => {
    if (!statusFilter || statusFilter === "all") throw new Error("An explicit approval status filter is required");
    return request<ListEnvelope<ApprovalRequest>>(`/enforcement/approvals?status_filter=${encodeURIComponent(statusFilter)}`);
  },
  listApprovalsForFilter: async (statusFilter: string) => {
    const results = await Promise.all(approvalStatusFilters(statusFilter).map((status) => api.listApprovals(status)));
    return { items: mergeApprovalStatusResults(results) };
  },
  decideApproval: (
    id: string,
    payload: "approve" | "deny" | { decision: "approve" | "deny" } | {
        schema_version: "2.0";
        decision: "approve" | "deny";
        expected_version: number;
        idempotency_key: string;
        reason: string;
      },
  ) =>
    request(`/enforcement/approvals/${id}/decision`, {
      method: "POST",
      body: JSON.stringify(typeof payload === "string" ? { decision: payload } : payload),
    }),
  listAguiActions: (params?: { source_module?: string; action_prefix?: string; page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.source_module) query.set("source_module", params.source_module);
    if (params?.action_prefix) query.set("action_prefix", params.action_prefix);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<AguiAction>>(`/agui/actions${suffix}`);
  },
  getAguiAction: (actionId: string) => request<AguiAction>(`/agui/actions/${encodeURIComponent(actionId)}`),
  listAguiDecisions: (params?: {
    action_id?: string;
    source_module?: string;
    source_object_type?: string;
    source_object_id?: string;
    page?: number;
    page_size?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.action_id) query.set("action_id", params.action_id);
    if (params?.source_module) query.set("source_module", params.source_module);
    if (params?.source_object_type) query.set("source_object_type", params.source_object_type);
    if (params?.source_object_id) query.set("source_object_id", params.source_object_id);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<AguiDecision>>(`/agui/decisions${suffix}`);
  },
  decideAguiAction: (
    actionId: string,
    payload: {
      decision: string;
      justification?: string;
      evidence_node_ids?: string[];
      decision_payload?: Record<string, unknown>;
      source_module?: string;
      source_object_type?: string;
      source_object_id?: string;
      evidence_displayed?: boolean;
      diff_preview_displayed?: boolean;
    }
  ) => request<AguiDecision>(`/agui/actions/${encodeURIComponent(actionId)}/decide`, { method: "POST", body: JSON.stringify(payload) }),
  guardianMatrix: (aiSystemId: string, actorType = "human") =>
    request(`/gateway/llm/guardian-matrix?ai_system_id=${encodeURIComponent(aiSystemId)}&actor_type=${encodeURIComponent(actorType)}`),
  llmIntercept: (payload: Record<string, unknown>) => request("/gateway/llm/intercept", { method: "POST", body: JSON.stringify(payload) }),
  llmGatewayDocumentComplete: (fields: {
    mode: "draft" | "transform";
    output_format: "pdf" | "docx";
    ai_system_id: string;
    policy_version_id: string;
    provider: string;
    model?: string;
    instruction: string;
    file?: File;
  }) => {
    const form = new FormData();
    form.set("mode", fields.mode);
    form.set("output_format", fields.output_format);
    form.set("ai_system_id", fields.ai_system_id);
    form.set("policy_version_id", fields.policy_version_id);
    form.set("provider", fields.provider);
    if (fields.model?.trim()) form.set("model", fields.model.trim());
    form.set("instruction", fields.instruction);
    if (fields.file) form.set("file", fields.file, fields.file.name);
    return requestMultipart<LLMGatewayDocumentCompleteResponse>("/llm-gateway/documents/complete", form);
  },
  mcpAuthorize: (payload: Record<string, unknown>) => request("/gateway/mcp/authorize", { method: "POST", body: JSON.stringify(payload) }),
  scanMcpTool: (payload: Record<string, unknown>) => request(
    "/gateway/mcp/tools/scan",
    { method: "POST", body: JSON.stringify(payload) },
    true,
    true,
    { timeoutMs: 25000 },
  ),
  listAgents: () => request<ListEnvelope<AgentIdentity>>("/ai-iam/agents"),
  listAIIAMIdentities: (params?: { q?: string; page?: number; page_size?: number; lookback_hours?: number }) => {
    const query = new URLSearchParams();
    if (params?.q) query.set("q", params.q);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.lookback_hours) query.set("lookback_hours", String(params.lookback_hours));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<AIIAMIdentityProfile>>(`/ai-iam/identities${suffix}`);
  },
  getAIIAMIdentity: (identityId: string, params?: { lookback_hours?: number; include_graph_details?: boolean }) => {
    const query = new URLSearchParams();
    if (params?.lookback_hours) query.set("lookback_hours", String(params.lookback_hours));
    if (typeof params?.include_graph_details === "boolean") {
      query.set("include_graph_details", String(params.include_graph_details));
    }
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<AIIAMIdentityProfile>(`/ai-iam/identities/${encodeURIComponent(identityId)}${suffix}`);
  },
  getAgent: (agentId: string) => request<AgentDetail>(`/agents/${encodeURIComponent(agentId)}`),
  createAgent: (payload: Record<string, unknown>) => request("/ai-iam/agents", { method: "POST", body: JSON.stringify(payload) }),
  mintAgentToken: (agentId: string, payload: Record<string, unknown>) =>
    request(`/ai-iam/agents/${agentId}/tokens`, { method: "POST", body: JSON.stringify(payload) }),
  killSwitch: (agentId: string) => request(`/ai-iam/agents/${agentId}/kill-switch`, { method: "POST" }),
  disableAgent: (agentId: string) => request(`/ai-iam/agents/${agentId}/disable`, { method: "POST" }),
  revokeAgentToken: (tokenId: string) =>
    request(`/ai-iam/tokens/${encodeURIComponent(tokenId)}/revoke`, { method: "POST" }),
  runtimeAgentGraph: (agentId: string) =>
    request<RuntimeAgentGraph>(`/runtime-intelligence/agent-graph/${encodeURIComponent(agentId)}`),
  agentTouchpoints: (agentId: string) =>
    request<AgentTouchpoints>(`/ai-iam/agents/${encodeURIComponent(agentId)}/touchpoints`),
  agentBlastRadius: (agentId: string) =>
    request<AgentBlastRadius>(`/ai-iam/agents/${encodeURIComponent(agentId)}/blast-radius`),
  runtimeChainGraph: (chainId: string) =>
    request<RuntimeChainGraph>(`/runtime/chain/${encodeURIComponent(chainId)}`),
  runtimeContextGraph: (contextId: string) =>
    request<RuntimeChainGraph>(`/runtime/context/${encodeURIComponent(contextId)}`),
  runtimeChainByAgent: (agentId: string) =>
    request<RuntimeAgentChain>(`/runtime/chain?agent_id=${encodeURIComponent(agentId)}`),
  listActivityUsers: (params?: { q?: string; page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.q) query.set("q", params.q);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<ActivityAuditUser>>(`/users${suffix}`);
  },
  getActivityUser: (userId: string, actionLimit = 20) =>
    request<ActivityAuditUserDetail>(
      `/users/${encodeURIComponent(userId)}?action_limit=${encodeURIComponent(String(actionLimit))}`
    ),
  blockUser: (userId: string, payload?: { reason?: string }) =>
    request<ActivityAuditUserDetail>(`/users/${encodeURIComponent(userId)}/block`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  enforceUserPolicy: (userId: string, payload?: { reason?: string }) =>
    request<ActivityAuditUserDetail>(`/users/${encodeURIComponent(userId)}/enforce-policy`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  listActivityEndpoints: (params?: { q?: string; user_id?: string; page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.q) query.set("q", params.q);
    if (params?.user_id) query.set("user_id", params.user_id);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<ActivityAuditEndpoint>>(`/endpoints${suffix}`);
  },
  getUserTimeline: (userId: string, params?: {
    action_type?: string;
    enforcement_action?: string;
    severity?: string;
    page?: number;
    page_size?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.action_type) query.set("action_type", params.action_type);
    if (params?.enforcement_action) query.set("enforcement_action", params.enforcement_action);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ActivityAuditTimeline>(`/users/${encodeURIComponent(userId)}/timeline${suffix}`);
  },
  getEndpointTimeline: (endpointId: string, params?: {
    action_type?: string;
    enforcement_action?: string;
    severity?: string;
    page?: number;
    page_size?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.action_type) query.set("action_type", params.action_type);
    if (params?.enforcement_action) query.set("enforcement_action", params.enforcement_action);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ActivityAuditTimeline>(`/endpoints/${encodeURIComponent(endpointId)}/timeline${suffix}`);
  },
  searchActivityAudit: (params?: {
    user?: string;
    device?: string;
    ai_app?: string;
    prompt_keyword?: string;
    alert_type?: string;
    runtime_event_id?: string;
    page?: number;
    page_size?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.user) query.set("user", params.user);
    if (params?.device) query.set("device", params.device);
    if (params?.ai_app) query.set("ai_app", params.ai_app);
    if (params?.prompt_keyword) query.set("prompt_keyword", params.prompt_keyword);
    if (params?.alert_type) query.set("alert_type", params.alert_type);
    if (params?.runtime_event_id) query.set("runtime_event_id", params.runtime_event_id);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ActivityAuditSearchResponse>(`/activity-audit/search${suffix}`);
  },
  userVisibilityUsers: (params?: {
    q?: string;
    department?: string;
    status?: string;
    role?: string;
    group_id?: string;
    application?: string;
    account_class?: string;
    provider?: string;
    model?: string;
    last_activity_after?: string;
    sort_by?: "last_activity" | "display_name" | "department" | "action_count";
    sort_direction?: "asc" | "desc";
    page?: number;
    page_size?: number;
  }) => request<ListEnvelope<UserVisibilityUser>>(`/user-visibility/users${boundedQuery(params || {})}`),
  userVisibilityDirectorySummary: () =>
    request<UserVisibilityDirectorySummary>("/user-visibility/users/summary"),
  userVisibilityUser: (userId: string) =>
    request<UserVisibilityUser360>(`/user-visibility/users/${encodeURIComponent(userId)}`),
  userVisibilityUserExperience: <T = Record<string, unknown>>(
    userId: string,
    section: string,
    params?: { page?: number; page_size?: number },
  ) => request<UserVisibilityExperienceSection<T>>(
    `/user-visibility/users/${encodeURIComponent(userId)}/experience/${encodeURIComponent(section)}${boundedQuery(params || {})}`,
  ),
  userVisibilityDepartments: (params?: { page?: number; page_size?: number }) =>
    request<ListEnvelope<UserVisibilityDepartment>>(`/user-visibility/departments${boundedQuery(params || {})}`),
  userVisibilityOrganization: (lookbackHours = 24 * 30) =>
    request<UserVisibilityOrganization>(`/user-visibility/organization${boundedQuery({ lookback_hours: lookbackHours })}`),
  userVisibilityActions: (params?: {
    user_id?: string;
    group_id?: string;
    department?: string;
    application?: string;
    account_class?: string;
    provider?: string;
    model?: string;
    agent?: string;
    tool?: string;
    action_class?: string;
    resource?: string;
    target?: string;
    destination?: string;
    data_class?: string;
    side_effect?: string;
    decision?: string;
    integrity?: string;
    control_state?: string;
    surface?: string;
    start_time?: string;
    end_time?: string;
    page?: number;
    page_size?: number;
  }) => request<ListEnvelope<UserVisibilityAction>>(`/user-visibility/actions${boundedQuery(params || {})}`),
  userVisibilityGroups: (params?: { page?: number; page_size?: number }) =>
    request<ListEnvelope<UserVisibilityGroup>>(`/user-visibility/groups${boundedQuery(params || {})}`),
  userVisibilityGroup: (groupId: string) =>
    request<UserVisibilityGroupDetail>(
      `/user-visibility/groups/${encodeURIComponent(groupId)}`,
    ),
  userVisibilityEffectivePolicies: (userId: string) =>
    request<{ group_refs: string[]; pack_assignments: Array<Record<string, unknown>>; effective_policy: Record<string, unknown> }>(
      `/user-visibility/users/${encodeURIComponent(userId)}/effective-policies`,
    ),
  userVisibilityPolicyStack: (userId: string) =>
    request<UserVisibilityPolicyStack>(
      `/user-visibility/users/${encodeURIComponent(userId)}/policy-stack`,
    ),
  createUserVisibilityAccessGrant: (payload: {
    user_id: string;
    capabilities: string[];
    department_scope: string[];
    reason: string;
    expires_at?: string | null;
  }) => request<UserVisibilityAccessGrant>(
    "/user-visibility/access-grants",
    { method: "POST", body: JSON.stringify(payload) },
  ),
  requestUserVisibilityPromptReveal: (actionId: string, payload: {
    purpose: "security_investigation" | "audit" | "incident_response" | "privacy_review";
    reason: string;
  }) => request<UserVisibilityRevealGrant>(
    `/user-visibility/prompts/${encodeURIComponent(actionId)}/reveal-grants`,
    { method: "POST", body: JSON.stringify(payload) },
  ),
  consumeUserVisibilityPromptReveal: (grantId: string) =>
    request<UserVisibilityRevealedPrompt>(`/user-visibility/prompt-reveal/${encodeURIComponent(grantId)}`, { method: "POST" }),
  updateUserVisibilityStaticGroupMemberships: (groupId: string, payload: { add_user_ids: string[]; remove_user_ids: string[] }) =>
    request<{ added_user_ids: string[]; removed_user_ids: string[] }>(
      `/user-visibility/groups/${encodeURIComponent(groupId)}/memberships`,
      { method: "POST", body: JSON.stringify(payload) },
    ),
  aiDiscoveryOverview: (lookbackHours = 24 * 7) =>
    request<AIDiscoveryOverview>(`/ai-discovery/overview?lookback_hours=${encodeURIComponent(String(lookbackHours))}`),
  aiDiscoveryUsageEvents: (params?: {
    lookback_hours?: number;
    source_surface?: string;
    user_id?: string;
    page?: number;
    page_size?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.lookback_hours) query.set("lookback_hours", String(params.lookback_hours));
    if (params?.source_surface) query.set("source_surface", params.source_surface);
    if (params?.user_id) query.set("user_id", params.user_id);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<AIDiscoveryUsageEvent>>(`/ai-discovery/usage-events${suffix}`);
  },
  aiDiscoveryGraph: (params?: {
    lookback_hours?: number;
    user_id?: string;
    agent_id?: string;
    ai_app?: string;
    max_edges?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.lookback_hours) query.set("lookback_hours", String(params.lookback_hours));
    if (params?.user_id) query.set("user_id", params.user_id);
    if (params?.agent_id) query.set("agent_id", params.agent_id);
    if (params?.ai_app) query.set("ai_app", params.ai_app);
    if (params?.max_edges) query.set("max_edges", String(params.max_edges));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<AIDiscoveryGraph>(`/ai-discovery/graph${suffix}`);
  },
  aiDiscoveryIdentities: (params?: { q?: string; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.q) query.set("q", params.q);
    if (params?.limit) query.set("limit", String(params.limit));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<AIDiscoveryIdentityProfile>>(`/ai-discovery/identities${suffix}`);
  },
  aiDiscoveryIdentity: (userId: string, lookbackHours = 24 * 30) =>
    request<AIDiscoveryIdentityProfile>(
      `/ai-discovery/identities/${encodeURIComponent(userId)}?lookback_hours=${encodeURIComponent(String(lookbackHours))}`
    ),
  aiDiscoveryAnomalies: (params?: { lookback_hours?: number; severity?: string; user_id?: string; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.lookback_hours) query.set("lookback_hours", String(params.lookback_hours));
    if (params?.severity) query.set("severity", params.severity);
    if (params?.user_id) query.set("user_id", params.user_id);
    if (params?.limit) query.set("limit", String(params.limit));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<AIDiscoveryAnomalyEvent>>(`/ai-discovery/anomalies${suffix}`);
  },
  aiDiscoveryRecompute: (params?: { lookback_hours?: number; max_events?: number }) => {
    const query = new URLSearchParams();
    if (params?.lookback_hours) query.set("lookback_hours", String(params.lookback_hours));
    if (params?.max_events) query.set("max_events", String(params.max_events));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<{ tenant_id: string; recomputed_events: number; started_at: string; finished_at: string }>(
      `/ai-discovery/recompute${suffix}`,
      { method: "POST" }
    );
  },
  aiDiscoveryAgentOverview: (lookbackHours = 24 * 7) =>
    request<AIAgentDiscoveryOverview>(
      `/ai-discovery/agents/overview?lookback_hours=${encodeURIComponent(String(lookbackHours))}`
    ),
  aiDiscoveryAgentAttackSurface: (agentId: string, params?: { lookback_hours?: number; max_edges?: number }) => {
    const query = new URLSearchParams();
    if (params?.lookback_hours) query.set("lookback_hours", String(params.lookback_hours));
    if (params?.max_edges) query.set("max_edges", String(params.max_edges));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<AIAgentAttackSurface>(`/ai-discovery/agents/${encodeURIComponent(agentId)}/attack-surface${suffix}`);
  },
  aiDiscoveryAgentBlastRadius: (agentId: string, lookbackHours = 24 * 7) =>
    request<AIAgentBlastRadius>(
      `/ai-discovery/agents/${encodeURIComponent(agentId)}/blast-radius?lookback_hours=${encodeURIComponent(String(lookbackHours))}`
    ),
  aiDiscoveryAgentBehavior: (agentId: string, lookbackHours = 24 * 7) =>
    request<AIAgentBehaviorProfile>(
      `/ai-discovery/agents/${encodeURIComponent(agentId)}/behavior?lookback_hours=${encodeURIComponent(String(lookbackHours))}`
    ),
  aiDiscoveryAgentOWASPCoverage: (agentId: string, lookbackHours = 24 * 7) =>
    request<AIAgentOWASPCoverage>(
      `/ai-discovery/agents/${encodeURIComponent(agentId)}/owasp-coverage?lookback_hours=${encodeURIComponent(String(lookbackHours))}`
    ),
  aiDiscoveryAgentAnomalies: (agentId: string, params?: { lookback_hours?: number; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.lookback_hours) query.set("lookback_hours", String(params.lookback_hours));
    if (params?.limit) query.set("limit", String(params.limit));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<AIDiscoveryAnomalyEvent>>(`/ai-discovery/agents/${encodeURIComponent(agentId)}/anomalies${suffix}`);
  },
  aiDiscoveryEnforceAgent: (
    agentId: string,
    payload: {
      action: "block_agent" | "restrict_tools" | "require_approval" | "isolate_execution";
      reason: string;
      tool_allowlist?: string[];
      required_approval?: boolean;
      ai_system_id?: string;
      control_ids?: string[];
    },
  ) =>
    request<AIAgentEnforcementResult>(`/ai-discovery/agents/${encodeURIComponent(agentId)}/enforce`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  aiDiscoveryRunAgentSimulation: (
    agentId: string,
    payload: {
      pack_id?: string;
      attack_type?: string;
      ai_system_id?: string;
      mode?: "deterministic" | "stochastic";
      max_definitions?: number;
      target_control_ids?: string[];
    },
  ) =>
    request<AIAgentSimulationResult>(`/ai-discovery/agents/${encodeURIComponent(agentId)}/simulate`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  runtimeEvents: (params?: {
    page?: number;
    page_size?: number;
    source_surface?: string;
    event_type?: string;
    agent_id?: string;
    decision?: string;
    chain_id?: string;
    correlation_id?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.source_surface) query.set("source_surface", params.source_surface);
    if (params?.event_type) query.set("event_type", params.event_type);
    if (params?.agent_id) query.set("agent_id", params.agent_id);
    if (params?.decision) query.set("decision", params.decision);
    if (params?.chain_id) query.set("chain_id", params.chain_id);
    if (params?.correlation_id) query.set("correlation_id", params.correlation_id);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<RuntimeTimelineEvent>>(`/runtime/events${suffix}`);
  },
  runtimeActivities: (params?: {
    page?: number;
    page_size?: number;
    source_surface?: string;
    event_type?: string;
    application?: string;
    user_id?: string;
    machine_id?: string;
    browser_type?: string;
    agent_id?: string;
    decision?: string;
    chain_id?: string;
    correlation_id?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.source_surface) query.set("source_surface", params.source_surface);
    if (params?.event_type) query.set("event_type", params.event_type);
    if (params?.application) query.set("application", params.application);
    if (params?.user_id) query.set("user_id", params.user_id);
    if (params?.machine_id) query.set("machine_id", params.machine_id);
    if (params?.browser_type) query.set("browser_type", params.browser_type);
    if (params?.agent_id) query.set("agent_id", params.agent_id);
    if (params?.decision) query.set("decision", params.decision);
    if (params?.chain_id) query.set("chain_id", params.chain_id);
    if (params?.correlation_id) query.set("correlation_id", params.correlation_id);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<RuntimeTimelineEvent>>(`/runtime/activities${suffix}`);
  },
  runtimeActivity: (eventId: string) =>
    request<RuntimeTimelineEvent>(`/runtime/activities/${encodeURIComponent(eventId)}`),
  runtimeUserActivity: (userId: string, params?: { page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<RuntimeTimelineEvent>>(`/runtime/users/${encodeURIComponent(userId)}/activity${suffix}`);
  },
  runtimeAgentActivity: (agentId: string, params?: { page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<RuntimeTimelineEvent>>(`/runtime/agents/${encodeURIComponent(agentId)}/activity${suffix}`);
  },
  runtimeTrace: (eventId: string) =>
    request<RuntimeTrace>(`/runtime/trace/${encodeURIComponent(eventId)}`),
  runtimePatterns: (params?: {
    page?: number;
    page_size?: number;
    type_filter?: string;
    severity?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.type_filter) query.set("type_filter", params.type_filter);
    if (params?.severity) query.set("severity", params.severity);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<RuntimePattern>>(`/runtime/patterns${suffix}`);
  },
  runtimeRecommendations: (params?: {
    page?: number;
    page_size?: number;
    status_filter?: string;
    recommendation_type?: string;
    ai_system_id?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.status_filter) query.set("status_filter", params.status_filter);
    if (params?.recommendation_type) query.set("recommendation_type", params.recommendation_type);
    if (params?.ai_system_id) query.set("ai_system_id", params.ai_system_id);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<RuntimeRecommendation>>(`/runtime/recommendations${suffix}`);
  },
  runtimeIntelligenceEvents: (params?: {
    page?: number;
    page_size?: number;
    source_surface?: string;
    event_type?: string;
    ai_system_id?: string;
    agent_id?: string;
    correlation_id?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.source_surface) query.set("source_surface", params.source_surface);
    if (params?.event_type) query.set("event_type", params.event_type);
    if (params?.ai_system_id) query.set("ai_system_id", params.ai_system_id);
    if (params?.agent_id) query.set("agent_id", params.agent_id);
    if (params?.correlation_id) query.set("correlation_id", params.correlation_id);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<RuntimeIntelligenceEvent>>(`/runtime-intelligence/events${suffix}`);
  },
  runtimeIntelligenceFindings: (params?: {
    page?: number;
    page_size?: number;
    ai_system_id?: string;
    severity?: string;
    finding_type?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.ai_system_id) query.set("ai_system_id", params.ai_system_id);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.finding_type) query.set("finding_type", params.finding_type);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<RuntimeIntelligenceFindingsEnvelope>(`/runtime-intelligence/findings${suffix}`);
  },
  runtimeIntelligenceGraph: (aiSystemId: string) =>
    request<RuntimeAISystemGraph>(`/runtime-intelligence/graph/${encodeURIComponent(aiSystemId)}`),
  runtimeActionGraph: (actionId: string) =>
    request<RuntimeActionGraph>(`/runtime-intelligence/action-graph/${encodeURIComponent(actionId)}`),
  runtimeActionTrace: (actionId: string) =>
    request<RuntimeActionTrace>(`/runtime-intelligence/action-trace/${encodeURIComponent(actionId)}`),
  actionIntegrityDetail: (runtimeEventId: string) =>
    request<ActionIntegrityDetail>(`/action-integrity/actions/${encodeURIComponent(runtimeEventId)}`),
  activityLineageByRuntimeEvent: (runtimeEventId: string, params?: { depth?: number; limit?: number }) => {
    const query = new URLSearchParams();
    if (params?.depth !== undefined) query.set("depth", String(params.depth));
    if (params?.limit !== undefined) query.set("limit", String(params.limit));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ActivityLineageProjection>(
      `/investigations/runtime-events/${encodeURIComponent(runtimeEventId)}${suffix}`,
    );
  },
  bankingTransaction: (aiTransactionId: string) =>
    request<BankingTransactionProjection>(
      `/runtime-control/banking-transactions/${encodeURIComponent(aiTransactionId)}`,
    ),
  bankingCisoSummary: () =>
    request<BankingCisoSummary>("/runtime-control/banking-transactions/summary/ciso"),
  runtimeAgenticChainGraph: (chainId: string) =>
    request<RuntimeAgenticChainGraph>(`/runtime-intelligence/chains/${encodeURIComponent(chainId)}/graph`),
  runtimeAgenticChainEvidence: (chainId: string) =>
    request<RuntimeAgenticChainEvidence>(`/runtime-intelligence/chains/${encodeURIComponent(chainId)}/evidence`),
  runtimeIntelligenceTriggers: (params?: {
    page?: number;
    page_size?: number;
    status_filter?: string;
    ai_system_id?: string;
    reason_code?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.status_filter) query.set("status_filter", params.status_filter);
    if (params?.ai_system_id) query.set("ai_system_id", params.ai_system_id);
    if (params?.reason_code) query.set("reason_code", params.reason_code);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<RuntimeIntelligenceTrigger>>(`/runtime-intelligence/triggers${suffix}`);
  },
  runtimeIntelligenceRecommendations: (params?: {
    page?: number;
    page_size?: number;
    status_filter?: string;
    ai_system_id?: string;
    recommendation_type?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    if (params?.status_filter) query.set("status_filter", params.status_filter);
    if (params?.ai_system_id) query.set("ai_system_id", params.ai_system_id);
    if (params?.recommendation_type) query.set("recommendation_type", params.recommendation_type);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<RuntimeIntelligenceRecommendation>>(`/runtime-intelligence/recommendations${suffix}`);
  },
  auditEvidence: (evidenceId: string) =>
    request<AuditEvidenceExplanation>(`/audit/evidence/${encodeURIComponent(evidenceId)}`),
  listConnectors: () => request<ListEnvelope<Connector>>("/monitoring/connectors"),
  connectorEvaluation: (connectorId: string) =>
    request<ConnectorEvaluation>(
      `/monitoring/connectors/${encodeURIComponent(connectorId)}/evaluation`,
    ),
  createConnector: (payload: Record<string, unknown>) => request("/monitoring/connectors", { method: "POST", body: JSON.stringify(payload) }),
  ingestShadowEvent: (payload: Record<string, unknown>) => request("/monitoring/shadow-events", { method: "POST", body: JSON.stringify(payload) }),
  ingestSignal: (payload: Record<string, unknown>) => request("/monitoring/signals", { method: "POST", body: JSON.stringify(payload) }),
  listDriftAlerts: () => request<ListEnvelope<DriftAlert>>("/monitoring/drift-alerts"),
  listFindings: (params?: {
    status_filter?: string;
    severity_filter?: string;
    finding_type_filter?: string;
    department_filter?: string;
    tool_filter?: string;
    page?: number;
    page_size?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.set("status_filter", params.status_filter);
    if (params?.severity_filter) query.set("severity_filter", params.severity_filter);
    if (params?.finding_type_filter) query.set("finding_type_filter", params.finding_type_filter);
    if (params?.department_filter) query.set("department_filter", params.department_filter);
    if (params?.tool_filter) query.set("tool_filter", params.tool_filter);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<Finding>>(`/findings${suffix}`);
  },
  getFinding: (findingId: string) => request<Finding>(`/findings/${encodeURIComponent(findingId)}`),
  getFindingTraceability: (findingId: string) =>
    request<FindingTraceability>(`/findings/${encodeURIComponent(findingId)}/traceability`),
  updateFindingStatus: (findingId: string, statusValue: "open" | "reviewing" | "resolved" | "accepted_risk") =>
    request<Finding>(`/findings/${encodeURIComponent(findingId)}/status`, {
      method: "POST",
      body: JSON.stringify({ status: statusValue }),
    }),
  assignFindingOwner: (findingId: string, payload: { owner_user_id?: string; owner_department?: string }) =>
    request<Finding>(`/findings/${encodeURIComponent(findingId)}/assign-owner`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  escalateFinding: (findingId: string, payload?: { reason?: string }) =>
    request<Finding>(`/findings/${encodeURIComponent(findingId)}/escalate`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  runFindingValidationPack: (
    findingId: string,
    payload: { simulation_ids?: string[]; mode?: "deterministic" | "stochastic"; limit?: number; inputs_used?: Record<string, unknown> },
  ) =>
    request<FindingValidationPackResponse>(`/findings/${encodeURIComponent(findingId)}/run-validation-pack`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  createFindingTicket: (findingId: string, payload?: { system?: string; severity_override?: string; note?: string }) =>
    request<FindingTicketResponse>(`/findings/${encodeURIComponent(findingId)}/create-ticket`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  generateFindingRemediationGuidance: (
    findingId: string,
    payload?: {
      task_type?: string;
      data_sensitivity?: string;
      customer_region?: string;
      residency_required?: boolean;
      cost_ceiling_usd?: number;
      allowed_remediation_types?: string[];
      context_payload?: Record<string, unknown>;
      route_policy_overrides?: Record<string, unknown>;
    },
  ) =>
    request<AIOrchestrationResult>(`/ai-orchestration/findings/${encodeURIComponent(findingId)}/remediation-guidance`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  executeNotetakerPlatformAction: (payload: NotetakerPlatformActionRequest) =>
    request<NotetakerPlatformActionResponse>("/endpoint-agent/notetaker/platform-action", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  generateSimulationRemediationGuidance: (
    runId: string,
    payload?: {
      task_type?: string;
      data_sensitivity?: string;
      customer_region?: string;
      residency_required?: boolean;
      cost_ceiling_usd?: number;
      allowed_remediation_types?: string[];
      context_payload?: Record<string, unknown>;
      route_policy_overrides?: Record<string, unknown>;
    },
  ) =>
    request<AIOrchestrationResult>(`/ai-orchestration/simulations/${encodeURIComponent(runId)}/remediation-guidance`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  generateDriftRemediationGuidance: (
    alertId: string,
    payload?: {
      task_type?: string;
      data_sensitivity?: string;
      customer_region?: string;
      residency_required?: boolean;
      cost_ceiling_usd?: number;
      allowed_remediation_types?: string[];
      context_payload?: Record<string, unknown>;
      route_policy_overrides?: Record<string, unknown>;
    },
  ) =>
    request<AIOrchestrationResult>(`/ai-orchestration/drift-alerts/${encodeURIComponent(alertId)}/remediation-guidance`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  generateRuntimePatternRemediationGuidance: (
    patternId: string,
    payload?: {
      task_type?: string;
      data_sensitivity?: string;
      customer_region?: string;
      residency_required?: boolean;
      cost_ceiling_usd?: number;
      allowed_remediation_types?: string[];
      context_payload?: Record<string, unknown>;
      route_policy_overrides?: Record<string, unknown>;
    },
  ) =>
    request<AIOrchestrationResult>(
      `/ai-orchestration/runtime-patterns/${encodeURIComponent(patternId)}/remediation-guidance`,
      {
        method: "POST",
        body: JSON.stringify(payload || {}),
      }
    ),
  getAIReasoningTrace: (traceId: string) =>
    request<AIReasoningTrace>(`/ai-orchestration/traces/${encodeURIComponent(traceId)}`),
  generateAIReasoningTicketPayload: (traceId: string, system: "jira" | "servicenow" = "jira") =>
    request<AIReasoningTicketPayload>(`/ai-orchestration/traces/${encodeURIComponent(traceId)}/ticket-payload`, {
      method: "POST",
      body: JSON.stringify({ system }),
    }),
  generateAISystemRemediationGuidance: (
    aiSystemId: string,
    payload?: {
      task_type?: string;
      data_sensitivity?: string;
      customer_region?: string;
      residency_required?: boolean;
      cost_ceiling_usd?: number;
      allowed_remediation_types?: string[];
      context_payload?: Record<string, unknown>;
      route_policy_overrides?: Record<string, unknown>;
    },
  ) =>
    request<AIOrchestrationResult>(`/ai-orchestration/ai-systems/${encodeURIComponent(aiSystemId)}/remediation-guidance`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  generateAgentRemediationGuidance: (
    agentId: string,
    payload?: {
      task_type?: string;
      data_sensitivity?: string;
      customer_region?: string;
      residency_required?: boolean;
      cost_ceiling_usd?: number;
      allowed_remediation_types?: string[];
      context_payload?: Record<string, unknown>;
      route_policy_overrides?: Record<string, unknown>;
    },
  ) =>
    request<AIOrchestrationResult>(`/ai-orchestration/agents/${encodeURIComponent(agentId)}/remediation-guidance`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  generateShadowEntityRemediationGuidance: (
    entityId: string,
    payload?: {
      task_type?: string;
      data_sensitivity?: string;
      customer_region?: string;
      residency_required?: boolean;
      cost_ceiling_usd?: number;
      allowed_remediation_types?: string[];
      context_payload?: Record<string, unknown>;
      route_policy_overrides?: Record<string, unknown>;
    },
  ) =>
    request<AIOrchestrationResult>(`/ai-orchestration/shadow-entities/${encodeURIComponent(entityId)}/remediation-guidance`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  acceptFindingRecommendation: (findingId: string, note?: string) =>
    request<Finding>(`/findings/${encodeURIComponent(findingId)}/recommendation/accept`, {
      method: "POST",
      body: JSON.stringify({ note }),
    }),
  listDiscoveryApplications: (params?: { status_filter?: string; page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.set("status_filter", params.status_filter);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<DiscoveryApplication>>(`/discovery/applications${suffix}`);
  },
  getDiscoveryApplication: (applicationId: string) =>
    request<DiscoveryApplication>(`/discovery/applications/${encodeURIComponent(applicationId)}`),
  promoteDiscoveryApplication: (
    applicationId: string,
    payload: { action: "approve" | "keep_monitoring"; provisional_risk_tier?: string },
  ) =>
    request<DiscoveryApplication>(`/discovery/applications/${encodeURIComponent(applicationId)}/promote`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  blockDiscoveryApplication: (applicationId: string, payload?: { reason?: string }) =>
    request<DiscoveryApplication>(`/discovery/applications/${encodeURIComponent(applicationId)}/block`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  assignDiscoveryApplicationOwner: (
    applicationId: string,
    payload: { owner_user_id?: string; owner_department?: string },
  ) =>
    request<DiscoveryApplication>(`/discovery/applications/${encodeURIComponent(applicationId)}/assign-owner`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  importShadowAITelemetry: (payload: { format: "defender_csv" | "swg_csv"; source_instance: string; content: string; window_start: string; window_end: string; preview: boolean }) =>
    request<TelemetryImportResult>("/shadow-ai/telemetry-import", { method: "POST", body: JSON.stringify(payload) }),
  listShadowAIEntities: (params?: { status_filter?: string; source_surface?: string; page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.set("status_filter", params.status_filter);
    if (params?.source_surface) query.set("source_surface", params.source_surface);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<ShadowAIEntity>>(`/shadow-ai/entities${suffix}`);
  },
  getShadowAIEntity: (entityId: string) =>
    request<ShadowAIEntityDetail>(`/shadow-ai/entities/${encodeURIComponent(entityId)}`),
  promoteShadowAIEntity: (entityId: string, payload?: { force?: boolean }) =>
    request<ShadowAIEntityDetail>(`/shadow-ai/entities/${encodeURIComponent(entityId)}/promote`, {
      method: "POST",
      body: JSON.stringify(payload || { force: true }),
    }),
  linkShadowAIEntityToAISystem: (entityId: string, payload: { ai_system_id: string }) =>
    request<ShadowAIEntityDetail>(`/shadow-ai/entities/${encodeURIComponent(entityId)}/link-to-ai-system`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  rejectShadowAIEntity: (entityId: string, payload?: { reason?: string }) =>
    request<ShadowAIEntityDetail>(`/shadow-ai/entities/${encodeURIComponent(entityId)}/reject`, {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  mergeShadowAIEntities: (entityId: string, payload: { target_entity_id: string }) =>
    request<ShadowAIEntityDetail>(`/shadow-ai/entities/${encodeURIComponent(entityId)}/merge`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  listShadowAIUnresolvedSignals: (params?: { page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<ShadowAISignal>>(`/shadow-ai/unresolved-signals${suffix}`);
  },
  ingestShadowAIEndpoint: (payload: Record<string, unknown>) =>
    request("/shadow-ai/ingest/endpoint", { method: "POST", body: JSON.stringify(payload) }),
  ingestShadowAIDNS: (payload: Record<string, unknown>) =>
    request("/shadow-ai/ingest/dns", { method: "POST", body: JSON.stringify(payload) }),
  ingestShadowAIProxy: (payload: Record<string, unknown>) =>
    request("/shadow-ai/ingest/proxy", { method: "POST", body: JSON.stringify(payload) }),
  shadowAIProviderCatalog: () => request<Array<Record<string, unknown>>>("/shadow-ai/provider-catalog"),
  shadowAICoverage: () => request<Record<string, unknown>>("/shadow-ai/coverage"),
  listSimulationDefinitions: () => request<ListEnvelope<SimulationDefinition>>("/simulations/definitions"),
  listSimulationPolicies: () => request<ListEnvelope<SimulationPolicy>>("/simulation-policies"),
  getActiveSimulationPolicy: () => request<SimulationPolicy>("/simulation-policies/active"),
  createSimulationPolicy: (payload: Record<string, unknown>) =>
    request<SimulationPolicy>("/simulation-policies", { method: "POST", body: JSON.stringify(payload) }),
  patchSimulationPolicy: (policyId: string, payload: Record<string, unknown>) =>
    request<SimulationPolicy>(`/simulation-policies/${encodeURIComponent(policyId)}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),
  activateSimulationPolicy: (policyId: string) =>
    request<SimulationPolicy>(`/simulation-policies/${encodeURIComponent(policyId)}/activate`, { method: "POST" }),
  listSimulationExecutors: () => request<ListEnvelope<SimulationExecutor>>("/simulation-policies/executors"),
  simulationCatalogCoverage: (sync = true) =>
    request<SimulationCatalogCoverage>(`/simulation-policies/catalog/coverage?sync=${encodeURIComponent(String(sync))}`),
  syncSimulationCatalog: () => request<SimulationCatalogCoverage>("/simulation-policies/catalog/sync", { method: "POST" }),
  listControls: () => request<ListEnvelope<Control>>("/simulations/controls"),
  createControl: (payload: Record<string, unknown>) => request("/simulations/controls", { method: "POST", body: JSON.stringify(payload) }),
  createSimulationDefinition: (payload: Record<string, unknown>) =>
    request("/simulations/definitions", { method: "POST", body: JSON.stringify(payload) }),
  updateSimulationDefinition: (simulationId: string, payload: Record<string, unknown>) =>
    request(`/simulations/definitions/${simulationId}`, { method: "PATCH", body: JSON.stringify(payload) }),
  listSimulationTemplates: () => request<ListEnvelope<Record<string, unknown>>>("/simulations/templates"),
  createSimulationTemplate: (payload: Record<string, unknown>) =>
    request("/simulations/templates", { method: "POST", body: JSON.stringify(payload) }),
  generateTemplateSimulations: (templateId: string, payload: Record<string, unknown>) =>
    request(`/simulations/templates/${templateId}/generate`, { method: "POST", body: JSON.stringify(payload) }),
  bootstrapRfpSimulationCatalog: (payload: { per_category_target: number }) =>
    request<SimulationCoverageSummary>("/simulations/catalog/bootstrap-rfp", { method: "POST", body: JSON.stringify(payload) }),
  bootstrapInitialRealSeedPack: (payload?: { update_existing?: boolean }) =>
    request<SimulationSeedPackBootstrapSummary>("/simulations/catalog/bootstrap-initial-real-seed-pack", {
      method: "POST",
      body: JSON.stringify(payload || {}),
    }),
  listSimulationPacks: () => request<ListEnvelope<SimulationPack>>("/simulations/packs"),
  runSimulationPack: (
    packId: string,
    payload: {
      ai_system_id: string;
      mode?: "deterministic" | "stochastic";
      stochastic_runs?: number;
      inputs_used?: Record<string, unknown>;
      max_definitions?: number;
      target_control_ids?: string[];
    },
  ) => request<SimulationPackRunResult>(`/simulations/packs/${encodeURIComponent(packId)}/run`, { method: "POST", body: JSON.stringify(payload) }),
  simulationCoverageSummary: () => request<SimulationCoverageSummary>("/simulations/coverage/summary"),
  simulationCoverageHeatmap: () => request<SimulationHeatmap>("/simulations/coverage/heatmap"),
  simulationCoverageTrends: (lookbackDays = 14) =>
    request<SimulationTrendSeries>(`/simulations/coverage/trends?lookback_days=${encodeURIComponent(String(lookbackDays))}`),
  runSimulation: (simulationId: string, payload: Record<string, unknown>) =>
    request<SimulationRun>(`/simulations/definitions/${simulationId}/run`, { method: "POST", body: JSON.stringify(payload) }),
  listSimulationRuns: () => request<ListEnvelope<SimulationRun>>("/simulations/runs"),
  getSimulationRunTrace: (runId: string) =>
    request<SimulationRunTrace>(`/simulations/runs/${encodeURIComponent(runId)}/trace`),
  listAgenticChainIntegrityScenarios: () =>
    request<AgenticChainScenarioListResponse>("/simulations/agentic-chain-integrity/scenarios"),
  runAgenticChainIntegrityValidation: (payload: {
    scenario_id?: string;
    defense_mode?: AgenticChainDefenseMode;
    run_all?: boolean;
  }) =>
    request<AgenticChainRunResponse>("/simulations/agentic-chain-integrity/run", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  agenticChainIntegrityMetrics: () =>
    request<AgenticChainIntegrityMetrics>("/simulations/agentic-chain-integrity/metrics"),
  controlTraceability: (aiSystemId: string) =>
    request<ListEnvelope<ControlTraceabilityRow>>(`/simulations/controls/traceability?ai_system_id=${encodeURIComponent(aiSystemId)}`),
  controlValidationCoverage: (controlId: string, trendPoints = 20) =>
    request(`/controls/${encodeURIComponent(controlId)}/coverage?trend_points=${encodeURIComponent(String(trendPoints))}`),
  frameworkCoverage: (frameworkName: string, minSimulations = 1) =>
    request(`/frameworks/${encodeURIComponent(frameworkName)}/coverage?min_simulations=${encodeURIComponent(String(minSimulations))}`),
  controlExplorer: (params?: {
    foundation_only?: boolean;
    framework?: string;
    category?: string;
    enforcement_point?: string;
    risk_tag?: string;
  }) => {
    const query = new URLSearchParams();
    if (params?.foundation_only !== undefined) query.set("foundation_only", String(Boolean(params.foundation_only)));
    if (params?.framework) query.set("framework", params.framework);
    if (params?.category) query.set("category", params.category);
    if (params?.enforcement_point) query.set("enforcement_point", params.enforcement_point);
    if (params?.risk_tag) query.set("risk_tag", params.risk_tag);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ControlExplorerState>(`/controls/explorer${suffix}`);
  },
  runtimeControlView: (lookbackHours = 24, foundationOnly = true) =>
    request<RuntimeControlViewState>(
      `/controls/runtime-view?lookback_hours=${encodeURIComponent(String(lookbackHours))}&foundation_only=${encodeURIComponent(String(Boolean(foundationOnly)))}`
    ),
  simulationControlView: (foundationOnly = true) =>
    request<SimulationControlViewState>(`/controls/simulation-view?foundation_only=${encodeURIComponent(String(Boolean(foundationOnly)))}`),
  deploymentCoverage: () => request<DeploymentCoverageSummary>("/coverage"),
  enterpriseDeveloperAIControl: () =>
    request<EnterpriseDeveloperAIControl>("/control-coverage/source-control/github-repository-boundary"),
  githubRepositoryOrganizations: (limit = 100, cursor?: string) =>
    request<GitHubRepositoryInventoryPage>(
      `/control-coverage/source-control/github-repositories/organizations?limit=${encodeURIComponent(String(limit))}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
    ),
  githubRepositories: (limit = 100, cursor?: string) =>
    request<GitHubRepositoryInventoryPage>(
      `/control-coverage/source-control/github-repositories/repositories?limit=${encodeURIComponent(String(limit))}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
    ),
  githubRepositoryDetail: (repositoryId: string) =>
    request<GitHubRepositoryDetail>(
      `/control-coverage/source-control/github-repositories/repositories/${encodeURIComponent(repositoryId)}`,
    ),
  githubRepositoryDevelopers: (limit = 100, cursor?: string) =>
    request<GitHubRepositoryInventoryPage>(
      `/control-coverage/source-control/github-repositories/developers?limit=${encodeURIComponent(String(limit))}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
    ),
  githubRepositoryAIConnections: (limit = 100, cursor?: string) =>
    request<GitHubRepositoryInventoryPage>(
      `/control-coverage/source-control/github-repositories/ai-connections?limit=${encodeURIComponent(String(limit))}${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
    ),
  updateGitHubRepositoryGovernance: (repositoryId: string, payload: { decision: "APPROVED" | "UNAPPROVED"; expected_governance_version: number; assignment_id?: string | null; deny_posture?: "BLOCK_CHANGES" | "BLOCK_ALL" | null }) =>
    request<GitHubRepositoryProjection>(
      `/control-coverage/source-control/github-repositories/repositories/${encodeURIComponent(repositoryId)}/governance`,
      { method: "PUT", body: JSON.stringify(payload) },
    ),
  updateGitHubRepositoryOperationControls: (repositoryId: string, payload: { controls: Record<"READ" | "EDIT" | "COMMIT" | "PULL" | "PUSH", "ALLOW" | "BLOCK">; expected_governance_version: number }) =>
    request<GitHubRepositoryProjection>(
      `/control-coverage/source-control/github-repositories/repositories/${encodeURIComponent(repositoryId)}/operation-controls`,
      { method: "PUT", body: JSON.stringify(payload) },
    ),
  githubRepositoryRuntimeBindings: (repositoryId?: string) =>
    request<{ items: GitHubRepositoryRuntimeBinding[]; next_cursor: string | null; limit: number }>(
      `/control-coverage/source-control/github-repositories/runtime-bindings${repositoryId ? `?repository_id=${encodeURIComponent(repositoryId)}` : ""}`,
    ),
  bindGitHubRepositoryRuntime: (repositoryId: string, payload: { observation_id: string; expected_governance_version: number }) =>
    request<GitHubRepositoryRuntimeBinding>(
      `/control-coverage/source-control/github-repositories/repositories/${encodeURIComponent(repositoryId)}/runtime-binding`,
      { method: "PUT", body: JSON.stringify(payload) },
    ),
  githubSourceConnections: () =>
    request<{ items: HMAIRSourceConnection[]; total: number }>("/discovery/source-connections"),
  sourceConnectionSetupCatalog: () =>
    request<SourceConnectionSetupCatalog>("/discovery/source-connections/setup-catalog"),
  enterpriseDenominatorAuthority: () =>
    request<EnterpriseDenominatorStatus>("/discovery/source-connections/authority-status"),
  createGitHubSourceConnection: (payload: HMAIRSourceConnectionInput) =>
    request<HMAIRSourceConnection>("/discovery/source-connections", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  validateGitHubSourceConnection: (connectionId: string) =>
    request<HMAIRSourceConnection>(`/discovery/source-connections/${encodeURIComponent(connectionId)}/validate`, {
      method: "POST",
      body: JSON.stringify({}),
    }),
  browserExtensionHealth: () => request<BrowserExtensionHealth>("/extension/health"),
  browserExtensionRemovalGovernance: () =>
    request<BrowserExtensionRemovalGovernance>("/extension/governance/removal"),
  aiToolsUsage: () => request<AIToolsUsageWorkspace>("/ai-tools-usage?limit=250"),
  getEndpointFloorStatus: () =>
    request<EndpointEnforcementFloorSummary>("/endpoint-agent/floor/status"),
  getEndpointHealth: () =>
    request<EndpointHealthSummary>("/endpoint-agent/health"),
  createEndpointReenrollmentAuthorization: (endpointId: string) =>
    request<EndpointReenrollmentAuthorization>(
      `/endpoint-agent/identities/${encodeURIComponent(endpointId)}/reenroll-authorizations`,
      { method: "POST", body: JSON.stringify({}) },
    ),
  chatGPTDesktopAssets: () =>
    request<ChatGPTDesktopAssetResponse>("/native-controls/chatgpt-desktop/assets"),
  chatGPTDesktopControlPlan: (endpointId: string, action: ChatGPTDesktopAction) =>
    request<ChatGPTDesktopControlPlan>("/native-controls/chatgpt-desktop/control-plan", {
      method: "POST",
      body: JSON.stringify({ endpoint_id: endpointId, action }),
    }),
  // Which optional parts of the API this server has on (Control Coverage is off unless CONTROL_COVERAGE_API_ENABLED).
  systemFeatures: () => request<{ control_coverage: boolean }>("/system/features"),
  controlCoverage: (windowDays = 30) =>
    request<ControlCoverageSummary>(`/control-coverage?window_days=${encodeURIComponent(String(windowDays))}`),
  controlCoveragePaths: (query: string) =>
    request<ControlCoveragePathList>(`/control-coverage/paths?${query}`),
  controlCoveragePath: (pathId: string) =>
    request<ControlCoveragePathDetail>(`/control-coverage/paths/${encodeURIComponent(pathId)}`),
  executiveControlCoverage: () =>
    request<ExecutiveControlCoverageSummary>("/control-coverage/executive"),
  refreshExecutiveControlCoverage: () =>
    request<ExecutiveControlCoverageSummary>("/control-coverage/executive/refresh", {
      method: "POST",
      body: JSON.stringify({
        scope_type: "tenant",
        scope_key: "all",
        display_name: "Enterprise AI estate",
      }),
    }),
  executiveControlCoverageAssessments: (snapshotId: string, query = "") =>
    request<ExecutiveCoverageAssessmentList>(
      `/control-coverage/executive/snapshots/${encodeURIComponent(snapshotId)}/assessments${query ? `?${query}` : ""}`,
    ),
  executiveControlCoverageAssessment: (assessmentId: string) =>
    request<ExecutiveCoverageAssessmentExplanation>(
      `/control-coverage/executive/assessments/${encodeURIComponent(assessmentId)}`,
    ),
  nativeControlProviders: () =>
    request<NativeCapabilityMatrix>("/control-capabilities/providers"),
  nativeControlPoints: () =>
    request<NativeControlPointList>("/control-points"),
  nativeControlPointHealth: (controlPointId: string) =>
    request<NativeControlPointHealth>(`/control-points/${encodeURIComponent(controlPointId)}/health`),
  configureNativeControlPoint: (controlPointId: string) =>
    request<NativeControlPoint>(`/native-controls/integrations/${encodeURIComponent(controlPointId)}/configure`, { method: "POST" }),
  validateNativeControlPoint: (controlPointId: string) =>
    request<NativeControlValidationRun>(`/native-controls/integrations/${encodeURIComponent(controlPointId)}/validate/run`, { method: "POST" }),
  monitorNativeControlPoint: (controlPointId: string) =>
    request<NativeControlPoint>(`/native-controls/integrations/${encodeURIComponent(controlPointId)}/monitor`, { method: "POST" }),
  enforceNativeControlPoint: (controlPointId: string) =>
    request<NativeControlPoint>(`/native-controls/integrations/${encodeURIComponent(controlPointId)}/enforce`, { method: "POST" }),
  disableNativeControlPoint: (controlPointId: string) =>
    request<NativeControlPoint>(`/native-controls/integrations/${encodeURIComponent(controlPointId)}/disable`, { method: "POST" }),
  nativeControlSelection: (actionId: string) =>
    request<NativeControlSelection>(`/control-selections/${encodeURIComponent(actionId)}`),
  listMaturity: () => request<ListEnvelope<MaturityRow>>("/trust-center/maturity"),
  maturityScoreExplanation: (aiSystemId: string, controlId: string) =>
    request(`/trust-center/maturity/${encodeURIComponent(aiSystemId)}/controls/${encodeURIComponent(controlId)}/explanation`),
  listEvidenceNodes: () => request<ListEnvelope<EvidenceNode>>("/trust-center/evidence/nodes"),
  listJobStatus: (limitPerJob = 5) =>
    request<ListEnvelope<JobStatusItem>>(`/ops/jobs/status?limit_per_job=${encodeURIComponent(String(limitPerJob))}`),
  dashboard: () => request("/auditor/dashboard"),
  auditorControlPosture: (params?: { group_by?: "framework" | "domain" | "ai_system"; ai_system_id?: string }) => {
    const query = new URLSearchParams();
    if (params?.group_by) query.set("group_by", params.group_by);
    if (params?.ai_system_id) query.set("ai_system_id", params.ai_system_id);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<AuditorControlPostureView>(`/auditor/control-posture${suffix}`);
  },
  dashboardNotifications: (params?: { limit?: number; lookback_hours?: number }) => {
    const query = new URLSearchParams();
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.lookback_hours) query.set("lookback_hours", String(params.lookback_hours));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<DashboardNotificationsState>(`/dashboard/notifications${suffix}`, undefined, true, true, {
      timeoutMs: 12000,
    });
  },
  pilotHealth: () =>
    request<PilotHealthState>("/dashboard/pilot-health", undefined, true, true, {
      timeoutMs: 8000,
    }),
  commandCenterDashboard: (params?: {
    time_window_hours?: number;
    ai_system_id?: string;
    severity?: "low" | "med" | "medium" | "high" | "critical";
    intent_category?: string;
    input_sensitivity?: "none" | "low" | "medium" | "high" | "critical";
    output_sensitivity?: "none" | "low" | "medium" | "high" | "critical";
    action_alignment?: "aligned" | "suspicious" | "out_of_scope" | "unknown";
    force_refresh?: boolean;
  }) => {
    const query = new URLSearchParams();
    if (params?.time_window_hours) query.set("time_window_hours", String(params.time_window_hours));
    if (params?.ai_system_id) query.set("ai_system_id", params.ai_system_id);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.intent_category) query.set("intent_category", params.intent_category);
    if (params?.input_sensitivity) query.set("input_sensitivity", params.input_sensitivity);
    if (params?.output_sensitivity) query.set("output_sensitivity", params.output_sensitivity);
    if (params?.action_alignment) query.set("action_alignment", params.action_alignment);
    if (params?.force_refresh) query.set("force_refresh", "true");
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<CommandCenterDashboardState>(`/dashboard/command-center${suffix}`, undefined, true, true, {
      timeoutMs: 30000,
    });
  },
  recordDecisionTuningAction: (
    explanationId: string,
    payload: {
      action: string;
      runtime_event_id?: string;
      finding_id?: string;
      justification?: string;
    }
  ) =>
    request<{
      status: string;
      audit_log_id: string;
      explanation_id: string;
      action: string;
      requires_confirmation: boolean;
    }>(`/dashboard/decision-explanations/${encodeURIComponent(explanationId)}/tuning-actions`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  syncExternalRisk: () =>
    request<Record<string, unknown>>(
      "/external-risk/sync",
      { method: "POST" },
      true,
      true,
      { timeoutMs: 45000 }
    ),
  triggerScan: (payload: {
    scan_type: "discovery" | "user" | "risk" | "policy";
    scope: "global" | "user_id" | "endpoint_id" | "ai_app";
    parameters?: Record<string, unknown>;
  }) => request<ScanTriggerResponse>("/scans/trigger", { method: "POST", body: JSON.stringify(payload) }),
  latestScan: () => request<ExposureScanState>("/scans/latest"),
  scanById: (scanId: string) => request<ExposureScanState>(`/scans/${encodeURIComponent(scanId)}`),
  listHmairScans: (params?: { limit?: number; cursor?: string }) => {
    const query = new URLSearchParams();
    if (params?.limit) query.set("limit", String(params.limit));
    if (params?.cursor) query.set("cursor", params.cursor);
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<HmairDiscoveryScan>>(`/discovery/scans${suffix}`);
  },
  getHmairScan: (scanId: string) =>
    request<HmairDiscoveryScan>(`/discovery/scans/${encodeURIComponent(scanId)}`),
  preflightHmairDeepScan: (payload: DeepScanPreflightRequest) =>
    request<DeepScanPreflight>("/discovery/scans/deep-scan/preflight", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  launchHmairDeepScan: (
    payload: DeepScanLaunchRequest,
    idempotencyKey: string,
  ) =>
    request<DeepScanLaunch>("/discovery/scans/deep-scan", {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey },
      body: JSON.stringify(payload),
    }),
  getHmairDeepScanCoverage: (scanId: string) =>
    request<DeepScanCoverage>(
      `/discovery/scans/${encodeURIComponent(scanId)}/coverage`,
    ),
  createHmairScan: (
    payload: Record<string, unknown>,
    idempotencyKey: string,
  ) =>
    request<HmairDiscoveryScan>("/discovery/scans", {
      method: "POST",
      headers: { "Idempotency-Key": idempotencyKey },
      body: JSON.stringify(payload),
    }),
  cancelHmairScan: (scanId: string) =>
    request<HmairDiscoveryScan>(
      `/discovery/scans/${encodeURIComponent(scanId)}/cancel`,
      { method: "POST" },
    ),
  rescanHmairScan: (scanId: string, idempotencyKey: string) =>
    request<HmairDiscoveryScan>(
      `/discovery/scans/${encodeURIComponent(scanId)}/rescan`,
      {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
      },
    ),
  listHmairCollectors: () =>
    request<ListEnvelope<HmairCollectorSummary>>("/discovery/collectors"),
  listHmairTargets: () =>
    request<ListEnvelope<HmairTargetSummary>>("/discovery/targets"),
  getHmairCollectorHealth: (collectorId: string) =>
    request<HmairCollectorSummary>(
      `/discovery/collectors/${encodeURIComponent(collectorId)}/health`,
    ),
  listDiscoveryAssets: (params?: {
    asset_type?: string;
    shadow_status?: string;
    usage_state?: string;
    verification_state?: string;
    search?: string;
    page?: number;
    page_size?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.asset_type) query.set("asset_type", params.asset_type);
    if (params?.shadow_status) query.set("shadow_status", params.shadow_status);
    if (params?.usage_state) query.set("usage_state", params.usage_state);
    if (params?.verification_state) query.set("verification_state", params.verification_state);
    if (params?.search) query.set("search", params.search);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<DiscoveryAssetSummary>>(`/discovery/assets${suffix}`);
  },
  getDiscoveryAsset: (assetId: string) =>
    request<DiscoveryAssetDetail>(`/discovery/assets/${encodeURIComponent(assetId)}`),
  getDiscoveryAssetEvidence: (assetId: string, limit = 50) =>
    request<DiscoveryAssetEvidenceList>(
      `/discovery/assets/${encodeURIComponent(assetId)}/evidence?limit=${encodeURIComponent(String(limit))}`,
    ),
  getDiscoveryAssetHistory: (assetId: string, page = 1, pageSize = 50) =>
    request<ListEnvelope<DiscoveryAssetHistory>>(
      `/discovery/assets/${encodeURIComponent(assetId)}/history?page=${encodeURIComponent(String(page))}&page_size=${encodeURIComponent(String(pageSize))}`,
    ),
  getDiscoveryAssetExposure: (assetId: string) =>
    request<ExposureProjection>(
      `/discovery/assets/${encodeURIComponent(assetId)}/exposure`,
    ),
  getDiscoveryAssetExposureTimeline: (assetId: string, page = 1, asOf?: string) => {
    const query = new URLSearchParams({ page: String(page) });
    if (asOf) query.set("as_of", asOf);
    return (
    request<ExposureTimelineResponse>(
      `/discovery/assets/${encodeURIComponent(assetId)}/exposure/timeline?${query.toString()}`,
    ));
  },
  getDiscoveryAssetExposureGraph: (assetId: string, categoryId: string, asOf?: string) => {
    const query = new URLSearchParams({ category_id: categoryId });
    if (asOf) query.set("as_of", asOf);
    return request<ExposureGraphResponse>(
      `/discovery/assets/${encodeURIComponent(assetId)}/exposure/graph?${query.toString()}`,
    );
  },
  getDiscoveryContext: (assetId: string) =>
    request<Record<string, unknown>>(`/discovery/assets/${encodeURIComponent(assetId)}/context`),
  getDiscoveryEstate: () =>
    request<DiscoveryEstateSummary>("/discovery/intelligence/estate"),
  listDiscoveryEcosystems: (params?: { page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<DiscoveryEcosystem>>(`/discovery/intelligence/ecosystems${suffix}`);
  },
  getDiscoveryEcosystem: (ecosystemId: string) =>
    request<DiscoveryEcosystem>(
      `/discovery/intelligence/ecosystems/${encodeURIComponent(ecosystemId)}`,
    ),
  listResolvedEcosystems: () =>
    request<ERGEcosystemSummary[]>("/discovery/evidence-resolution/ecosystems"),
  getResolvedEcosystem: (ecosystemId: string) =>
    request<ERGEcosystemDetail>(
      `/discovery/evidence-resolution/ecosystems/${encodeURIComponent(ecosystemId)}`,
    ),
  getResolvedEcosystemTimeline: (ecosystemId: string) =>
    request<ERGTimeline>(
      `/discovery/evidence-resolution/ecosystems/${encodeURIComponent(ecosystemId)}/timeline`,
    ),
  getEcosystemVerification: (ecosystemId: string) =>
    request<EcosystemVerificationProjection>(
      `/discovery/evidence-resolution/ecosystems/${encodeURIComponent(ecosystemId)}/verification`,
    ),
  getEcosystemVerificationHistory: (ecosystemId: string) =>
    request<EcosystemVerificationHistory>(
      `/discovery/evidence-resolution/ecosystems/${encodeURIComponent(ecosystemId)}/verification/history`,
    ),
  startEcosystemVerification: (
    ecosystemId: string,
    payload: {
      hypothesis_evaluation_id: string;
      environment: string;
      trigger: "manual_verification";
      idempotency_key: string;
    },
  ) => request<VerificationPlanResponse>(
    `/discovery/evidence-resolution/ecosystems/${encodeURIComponent(ecosystemId)}/verification/start`,
    { method: "POST", body: JSON.stringify(payload) },
  ),
  retryVerificationEpisode: (episodeId: string, idempotencyKey: string) =>
    request<VerificationPlanResponse>(
      `/discovery/evidence-resolution/verification/episodes/${encodeURIComponent(episodeId)}/retry`,
      { method: "POST", body: JSON.stringify({ idempotency_key: idempotencyKey }) },
    ),
  listUnknownAI: (params?: { page?: number; page_size?: number }) => {
    const query = new URLSearchParams();
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<UnknownAIItem>>(`/discovery/intelligence/unknown${suffix}`);
  },
  listDiscoveryIntelligenceFindings: (params?: {
    status_filter?: string;
    severity?: string;
    page?: number;
    page_size?: number;
  }) => {
    const query = new URLSearchParams();
    if (params?.status_filter) query.set("status_filter", params.status_filter);
    if (params?.severity) query.set("severity", params.severity);
    if (params?.page) query.set("page", String(params.page));
    if (params?.page_size) query.set("page_size", String(params.page_size));
    const suffix = query.toString() ? `?${query.toString()}` : "";
    return request<ListEnvelope<DiscoveryIntelligenceFinding>>(`/discovery/intelligence/findings${suffix}`);
  },
  listDiscoveryCollectorHealth: () =>
    request<DiscoveryCollectorHealth[]>("/discovery/intelligence/collector-health"),
  getDiscoveryCoverage: () =>
    request<DiscoveryCoverageProjection>("/discovery/intelligence/coverage"),
  estimateHmairScan: (payload: { target_ids: string[]; collector_ids: string[] }) =>
    request<DiscoveryScanEstimate>("/discovery/scans/estimate", {
      method: "POST",
      body: JSON.stringify(payload),
    }),
  getHmairScanProgress: (scanId: string) =>
    request<DiscoveryScanProgress>(`/discovery/scans/${encodeURIComponent(scanId)}/progress`),
  getHmairScanResults: (scanId: string) =>
    request<DiscoveryScanResults>(`/discovery/scans/${encodeURIComponent(scanId)}/results`),
  getHmairScanDiagnostics: (scanId: string) =>
    request<DiscoveryScanDiagnostics>(`/discovery/scans/${encodeURIComponent(scanId)}/diagnostics`),
  listEndpointMetadataInventoryRuns: (limit = 20) =>
    request<{ items: EndpointMetadataInventoryRun[] }>(
      `/endpoint-agent/discovery/metadata-inventory-runs?limit=${encodeURIComponent(String(limit))}`,
    ),
  createEndpointMetadataInventoryRun: (
    payload: { endpoint_ids: string[] | null; expires_in_minutes: number },
    idempotencyKey: string,
  ) =>
    request<EndpointMetadataInventoryRun>(
      "/endpoint-agent/discovery/metadata-inventory-runs",
      {
        method: "POST",
        headers: { "Idempotency-Key": idempotencyKey },
        body: JSON.stringify(payload),
      },
    ),
  getEndpointMetadataInventoryRun: (runId: string) =>
    request<EndpointMetadataInventoryRun>(
      `/endpoint-agent/discovery/metadata-inventory-runs/${encodeURIComponent(runId)}`,
    ),
  listConflicts: (statusFilter = "open") =>
    request<ListEnvelope<ControlConflict>>(`/auditor/conflicts?status_filter=${encodeURIComponent(statusFilter)}`),
  resolveConflict: (conflictId: string, payload: { decision: "accept_positive" | "accept_negative" | "inconclusive"; notes?: string }) =>
    request(`/auditor/conflicts/${conflictId}/resolve`, { method: "POST", body: JSON.stringify(payload) }),
  exportAudit: (payload: Record<string, unknown>) =>
    request<AuditorExportResponse>("/auditor/export", { method: "POST", body: JSON.stringify(payload) }),
  downloadAuditorArtifact: (path: string) => requestBlob(path),
  maturityCurveOverview: () => request<MaturityCurveOverview>("/maturity-curve/overview"),
  listMaturityCurveScopes: () => request<{ items: MaturityCurveScope[]; total: number }>("/maturity-curve/scopes"),
  getMaturityCurveScope: (scopeId: string) =>
    request<MaturityCurveScopeDetail>(`/maturity-curve/scopes/${encodeURIComponent(scopeId)}`),
  createMaturityCurveScope: (payload: {
    scope_key: string;
    scope_type: string;
    display_name: string;
    filters?: Record<string, unknown>;
  }) => request<MaturityCurveScope>("/maturity-curve/scopes", { method: "POST", body: JSON.stringify(payload) }),
  refreshMaturityCurveScope: (scopeId: string, windowDays = 30) =>
    request<{
      scope: MaturityCurveScope;
      assessment: MaturityCurveScopeDetail["assessment"];
      baseline: MaturityCurveScopeDetail["baseline"];
      recommendations: MaturityCurveRecommendation[];
    }>(`/maturity-curve/scopes/${encodeURIComponent(scopeId)}/refresh`, {
      method: "POST",
      body: JSON.stringify({ window_days: windowDays }),
    }),
  simulateMaturityRecommendation: (recommendationId: string) =>
    request<MaturityCurveSimulation>(`/maturity-curve/recommendations/${encodeURIComponent(recommendationId)}/simulate`, {
      method: "POST",
    }),
  reviewMaturityRecommendation: (recommendationId: string, action: string, reason: string) =>
    request<MaturityCurveRecommendation>(`/maturity-curve/recommendations/${encodeURIComponent(recommendationId)}/review`, {
      method: "POST",
      body: JSON.stringify({ action, reason }),
    }),
  listMaturityPatterns: (scopeId: string, dimension?: string) =>
    request<{ items: MaturityCurvePattern[]; total: number }>(
      `/maturity-curve/scopes/${encodeURIComponent(scopeId)}/patterns${dimension ? `?dimension=${encodeURIComponent(dimension)}` : ""}`,
    ),
  startMaturityRollout: (recommendationId: string) =>
    request<MaturityCurveRollout>(`/maturity-curve/recommendations/${encodeURIComponent(recommendationId)}/rollouts`, {
      method: "POST",
    }),
  transitionMaturityRollout: (rolloutId: string, targetState: string, reason: string, rolloutStage?: string) =>
    request<MaturityCurveRollout>(`/maturity-curve/rollouts/${encodeURIComponent(rolloutId)}/transition`, {
      method: "POST",
      body: JSON.stringify({ target_state: targetState, reason, ...(rolloutStage ? { rollout_stage: rolloutStage } : {}) }),
    }),
  refreshMaturityEffectiveness: (rolloutId: string) =>
    request<MaturityCurveEffectiveness>(`/maturity-curve/rollouts/${encodeURIComponent(rolloutId)}/effectiveness`, {
      method: "POST",
    }),
  refreshMaturityExecutive: (scopeId: string) =>
    request<NonNullable<MaturityCurveOverview["executive"]>>(
      `/maturity-curve/scopes/${encodeURIComponent(scopeId)}/executive`,
      { method: "POST" },
    ),
  listConnectorProviders: () => request<ListEnvelope<ConnectorProviderCatalogItem>>("/monitoring/connectors/providers"),
  listMicrosoftPermissionModes: () => request<ListEnvelope<MicrosoftPermissionMode>>("/monitoring/connectors/microsoft/permission-modes"),
  resolveMicrosoftScopes: (payload: {
    provider_key: string;
    permission_mode?: string;
    include_optional?: boolean;
  }) => request<MicrosoftScopeResolution>("/monitoring/connectors/microsoft/resolve-scopes", {
    method: "POST",
    body: JSON.stringify(payload),
  }),
  buildMicrosoftConsentUrl: (payload: {
    tenant_id: string;
    client_id: string;
    redirect_uri: string;
    state?: string;
  }) => request<MicrosoftConsentUrlResponse>("/monitoring/connectors/microsoft/admin-consent-url", {
    method: "POST",
    body: JSON.stringify(payload),
  }),
  getMicrosoftAppRegistrationTemplate: () =>
    request<MicrosoftAppRegistrationTemplate>("/monitoring/connectors/microsoft/app-registration-template"),
  bootstrapMicrosoftConnector: (payload: {
    connector_id?: string;
    name: string;
    provider_key: string;
    tenant_id: string;
    client_id: string;
    redirect_uri: string;
    permission_mode?: string;
    include_optional_scopes?: boolean;
    create_connector?: boolean;
    enabled?: boolean;
    polling_interval_minutes?: number;
    credential_mode?: "client_secret" | "client_assertion";
    client_secret?: string;
    client_assertion?: string;
    client_assertion_type?: string;
    state?: string;
  }) => request<ConnectorBootstrapResponse>("/monitoring/connectors/bootstrap/microsoft", {
    method: "POST",
    body: JSON.stringify(payload),
  }),
  pullConnectorNow: (connectorId: string) => request(`/monitoring/connectors/${connectorId}/pull`, { method: "POST" }),
};
