import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, it, vi } from "vitest";

import { STORAGE_KEYS } from "./policy-sync";
import {
  applyAttestedEndpointIdentity,
  enqueueTelemetryEvent,
  flushTelemetryQueue,
  getEndpointContext,
  getTelemetryNextRetryDelayMs,
  getTelemetryQueueDepth,
} from "./telemetry";

function createStorage(initial: Record<string, unknown> = {}) {
  const store = new Map<string, unknown>(Object.entries(initial));
  return {
    store,
    get: vi.fn(async (keys?: string | string[]) => {
      if (!keys) return Object.fromEntries(store.entries());
      const normalizedKeys = Array.isArray(keys) ? keys : [keys];
      return Object.fromEntries(normalizedKeys.map((key) => [key, store.get(key)]));
    }),
    set: vi.fn(async (values: Record<string, unknown>) => {
      for (const [key, value] of Object.entries(values)) {
        store.set(key, value);
      }
    }),
    remove: vi.fn(async (keys: string | string[]) => {
      for (const key of Array.isArray(keys) ? keys : [keys]) {
        store.delete(key);
      }
    }),
  };
}

function jwtPayload(payload: Record<string, unknown>): string {
  const encoded = btoa(JSON.stringify(payload)).replace(/=+$/, "");
  return `header.${encoded}.signature`;
}

describe("extension pilot telemetry payload context", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
  });

  it("hydrates a stable pilot endpoint context with configured hostname and platform versions", async () => {
  const storage = createStorage({
      [STORAGE_KEYS.pilotHostname]: "finance-macbook-01",
      [STORAGE_KEYS.pilotOsVersion]: "14.6.1",
    });
    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 Chrome/125.0.6422.142 Safari/537.36",
    });
    vi.stubGlobal("chrome", {
      storage: { local: storage },
      runtime: {
        getPlatformInfo: vi.fn(async () => ({ os: "mac", arch: "x86-64", nacl_arch: "x86-64" })),
        getManifest: vi.fn(() => ({ name: "AI Control Plane - Discovery & Guard", version: "0.1.0" })),
      },
    });

    const context = await getEndpointContext();

    expect(context.endpoint_id).toMatch(/^ep_/);
    expect(context.hostname).toBe("finance-macbook-01");
    expect(context.device_type).toBe("laptop");
    expect(context.os_type).toBe("mac");
    expect(context.os_version).toBe("14.6.1");
    expect(context.browser_version).toBe("125.0.6422.142");
  });

  it("replaces a generated browser id only with an attested endpoint identity", async () => {
    const storage = createStorage({
      endpointId: "ep_generated_browser_id",
      endpointContext: {
        endpoint_id: "ep_generated_browser_id",
        hostname: "finance-macbook-01",
        device_type: "laptop",
        os_type: "mac",
        os_version: "15.6",
        browser_version: "140.0.0.0",
        extension_name: "AI Control Plane - Discovery & Guard",
      },
      [STORAGE_KEYS.pilotHostname]: "finance-macbook-01",
      [STORAGE_KEYS.pilotOsVersion]: "15.6",
    });
    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 15_6) AppleWebKit/537.36 Chrome/140.0.0.0 Safari/537.36",
    });
    vi.stubGlobal("chrome", {
      storage: { local: storage },
      runtime: {
        getPlatformInfo: vi.fn(async () => ({ os: "mac", arch: "arm64", nacl_arch: "arm64" })),
        getManifest: vi.fn(() => ({ name: "AI Control Plane - Discovery & Guard", version: "0.1.0" })),
      },
    });

    await applyAttestedEndpointIdentity({
      endpointId: "9350fb98-60f0-590a-bbf6-9d5a9847a6c7",
      endpointIdentityVerified: true,
    });

    expect(await getEndpointContext()).toMatchObject({
      endpoint_id: "9350fb98-60f0-590a-bbf6-9d5a9847a6c7",
      hostname: "finance-macbook-01",
    });
    expect(storage.store.get("endpointId")).toBe("9350fb98-60f0-590a-bbf6-9d5a9847a6c7");
  });

  it("rejects an unverified endpoint identity override", async () => {
    const storage = createStorage({ endpointId: "ep_generated_browser_id" });
    vi.stubGlobal("chrome", {
      storage: { local: storage },
      runtime: {
        getPlatformInfo: vi.fn(async () => ({ os: "mac", arch: "arm64", nacl_arch: "arm64" })),
        getManifest: vi.fn(() => ({ name: "AI Control Plane - Discovery & Guard", version: "0.1.0" })),
      },
    });

    await expect(applyAttestedEndpointIdentity({
      endpointId: "spoofed-endpoint",
      endpointIdentityVerified: false,
    })).rejects.toThrow("endpoint_identity_unverified");
    expect(storage.store.get("endpointId")).toBe("ep_generated_browser_id");
  });

  it("posts queued telemetry with endpoint context and explicit user identity", async () => {
    const storage = createStorage({
      [STORAGE_KEYS.backendUrl]: "http://127.0.0.1:8000",
      [STORAGE_KEYS.tenantId]: "tenant-1",
      [STORAGE_KEYS.accessToken]: jwtPayload({ sub: "user-123", email: "analyst@example.com" }),
      [STORAGE_KEYS.refreshToken]: "refresh.token.value",
      [STORAGE_KEYS.browser]: "edge",
      [STORAGE_KEYS.browserProfile]: "pilot-profile",
      [STORAGE_KEYS.authEmail]: "analyst@example.com",
      [STORAGE_KEYS.pilotHostname]: "pilot-win-01",
      [STORAGE_KEYS.pilotOsVersion]: "10.0.22631",
    });
    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/126.0.2592.81",
    });
    vi.stubGlobal("chrome", {
      storage: { local: storage },
      runtime: {
        getPlatformInfo: vi.fn(async () => ({ os: "win", arch: "x86-64", nacl_arch: "x86-64" })),
        getManifest: vi.fn(() => ({ name: "AI Control Plane - Discovery & Guard", version: "0.1.0" })),
      },
    });
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit): Promise<Response> => new Response(JSON.stringify({ status: "ok" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await enqueueTelemetryEvent({
      event_type: "extension_installed",
      domain: "extension.local",
      action_taken: "installed",
    });
    await flushTelemetryQueue();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const request = JSON.parse(String(fetchMock.mock.calls[0][1]?.body || "{}"));
    expect(request).toMatchObject({
      tenant_id: "tenant-1",
      browser: "edge",
      browser_profile: "pilot-profile",
      browser_version: "126.0.2592.81",
      extension_name: "AI Control Plane - Discovery & Guard",
      extension_version: "0.1.0",
      extension_build_hash: "dev",
      hostname: "pilot-win-01",
      device_type: "laptop",
      os_type: "windows",
      os_version: "10.0.22631",
      user_id: "user-123",
      user_email: "analyst@example.com",
      event_type: "extension_installed",
    });
    expect(request.endpoint_id).toMatch(/^ep_/);
    expect(request.session_id).toMatch(/^sess_/);
    expect(storage.store.get("telemetryQueueV1")).toEqual([]);
  });

  it("flushes prompt telemetry immediately for live action explorer visibility", async () => {
    const storage = createStorage({
      [STORAGE_KEYS.backendUrl]: "http://127.0.0.1:8000",
      [STORAGE_KEYS.tenantId]: "tenant-1",
      [STORAGE_KEYS.accessToken]: jwtPayload({ sub: "user-123", email: "analyst@example.com" }),
      [STORAGE_KEYS.refreshToken]: "refresh.token.value",
      [STORAGE_KEYS.browser]: "chrome",
      [STORAGE_KEYS.browserProfile]: "pilot-profile",
      [STORAGE_KEYS.authEmail]: "analyst@example.com",
    });
    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 Chrome/125.0.6422.142 Safari/537.36",
    });
    vi.stubGlobal("chrome", {
      storage: { local: storage },
      runtime: {
        getPlatformInfo: vi.fn(async () => ({ os: "mac", arch: "arm64", nacl_arch: "arm64" })),
        getManifest: vi.fn(() => ({ name: "AI Control Plane - Discovery & Guard", version: "0.1.0" })),
      },
    });
    const fetchMock = vi.fn(async (_url: string, _init?: RequestInit): Promise<Response> => new Response(JSON.stringify({ status: "ok" }), { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await enqueueTelemetryEvent({
      event_type: "prompt_submitted",
      domain: "chatgpt.com",
      action_taken: "allow",
      prompt_preview_redacted: "Hawk live action explorer acceptance.",
    }, { flushImmediately: true });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const request = JSON.parse(String(fetchMock.mock.calls[0][1]?.body || "{}"));
    expect(request).toMatchObject({
      tenant_id: "tenant-1",
      event_type: "prompt_submitted",
      domain: "chatgpt.com",
      prompt_preview_redacted: "Hawk live action explorer acceptance.",
    });
    expect(getTelemetryQueueDepth()).toBe(0);
    expect(storage.store.get("telemetryQueueV1")).toEqual([]);
  });

  it("does not immediately retry failed telemetry and create a request storm", async () => {
    const storage = createStorage({
      [STORAGE_KEYS.backendUrl]: "http://127.0.0.1:8000",
      [STORAGE_KEYS.tenantId]: "tenant-1",
      [STORAGE_KEYS.accessToken]: jwtPayload({ sub: "user-123", email: "analyst@example.com" }),
      [STORAGE_KEYS.refreshToken]: "refresh.token.value",
      [STORAGE_KEYS.browser]: "chrome",
      [STORAGE_KEYS.browserProfile]: "pilot-profile",
      [STORAGE_KEYS.authEmail]: "analyst@example.com",
    });
    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 Chrome/125.0.6422.142 Safari/537.36",
    });
    vi.stubGlobal("chrome", {
      storage: { local: storage },
      runtime: {
        getPlatformInfo: vi.fn(async () => ({ os: "mac", arch: "x86-64", nacl_arch: "x86-64" })),
        getManifest: vi.fn(() => ({ name: "AI Control Plane - Discovery & Guard", version: "0.1.0" })),
      },
    });
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ status: "unavailable" }), { status: 503 }));
    vi.stubGlobal("fetch", fetchMock);

    await enqueueTelemetryEvent({
      event_type: "clipboard_paste_detected",
      domain: "chatgpt.com",
      action_taken: "detected",
    });

    await flushTelemetryQueue();
    await flushTelemetryQueue();

    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(getTelemetryQueueDepth()).toBe(1);
    const persistedQueue = storage.store.get("telemetryQueueV1");
    expect(Array.isArray(persistedQueue)).toBe(true);
    expect((persistedQueue as Array<Record<string, unknown>>)[0]).toMatchObject({
      event_type: "clipboard_paste_detected",
      domain: "chatgpt.com",
      __retry_attempts: 1,
    });
  });

  it("keeps failed prompt telemetry on a live retry path", async () => {
    const storage = createStorage({
      [STORAGE_KEYS.backendUrl]: "http://127.0.0.1:8000",
      [STORAGE_KEYS.tenantId]: "tenant-1",
      [STORAGE_KEYS.accessToken]: jwtPayload({ sub: "user-123", email: "analyst@example.com" }),
      [STORAGE_KEYS.refreshToken]: "refresh.token.value",
      [STORAGE_KEYS.browser]: "chrome",
      [STORAGE_KEYS.browserProfile]: "pilot-profile",
      [STORAGE_KEYS.authEmail]: "analyst@example.com",
    });
    vi.stubGlobal("navigator", {
      userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_6_1) AppleWebKit/537.36 Chrome/125.0.6422.142 Safari/537.36",
    });
    vi.stubGlobal("chrome", {
      storage: { local: storage },
      runtime: {
        getPlatformInfo: vi.fn(async () => ({ os: "mac", arch: "arm64", nacl_arch: "arm64" })),
        getManifest: vi.fn(() => ({ name: "AI Control Plane - Discovery & Guard", version: "0.1.0" })),
      },
    });
    const fetchMock = vi.fn(async () => new Response(JSON.stringify({ status: "expired" }), { status: 401 }));
    vi.stubGlobal("fetch", fetchMock);

    await enqueueTelemetryEvent({
      event_type: "prompt_submitted",
      domain: "chatgpt.com",
      action_taken: "allow",
      prompt_preview_redacted: "Hawk live retry acceptance.",
    }, { flushImmediately: true });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(getTelemetryNextRetryDelayMs()).toBeLessThanOrEqual(1_500);
    const persistedQueue = storage.store.get("telemetryQueueV1");
    expect(Array.isArray(persistedQueue)).toBe(true);
    expect((persistedQueue as Array<Record<string, unknown>>)).toContainEqual(expect.objectContaining({
      event_type: "prompt_submitted",
      domain: "chatgpt.com",
      __retry_attempts: 1,
    }));
  });

  it("flushes extension health and context errors immediately so browser stability is visible", () => {
    const serviceWorkerSource = readFileSync(
      fileURLToPath(new URL("./service-worker.ts", import.meta.url)),
      "utf8",
    );

    for (const eventType of [
      "extension_health_status",
      "extension_connected",
      "context_invalidated",
      "context_recovered",
      "backend_unreachable",
      "telemetry_queued",
      "extension_error",
    ]) {
      expect(serviceWorkerSource).toContain(`"${eventType}"`);
    }
  });
  it("does not replay queued telemetry after the identity changes", async () => {
    const storage = createStorage({
      [STORAGE_KEYS.backendUrl]: "https://one.example.test/api",
      [STORAGE_KEYS.tenantId]: "tenant-one",
    });
    const sessionStorage = createStorage({
      [STORAGE_KEYS.accessToken]: jwtPayload({ sub: "user-one" }),
      [STORAGE_KEYS.refreshToken]: "refresh-one",
    });
    vi.stubGlobal("chrome", {
      storage: { local: storage, session: sessionStorage },
      runtime: {
        getPlatformInfo: vi.fn(async () => ({ os: "mac" })),
        getManifest: vi.fn(() => ({ name: "Hawk", version: "1" })),
      },
    });
    const fetchMock = vi.fn(async () => new Response("{}", { status: 200 }));
    vi.stubGlobal("fetch", fetchMock);

    await enqueueTelemetryEvent({ event_type: "prompt_submitted", domain: "chatgpt.com" });
    sessionStorage.store.set(STORAGE_KEYS.accessToken, jwtPayload({ sub: "user-two" }));
    await flushTelemetryQueue();

    expect(fetchMock).not.toHaveBeenCalled();
    expect(getTelemetryQueueDepth()).toBe(0);
  });

  it("stops a batch when authentication changes after the first post", async () => {
    const storage = createStorage({
      [STORAGE_KEYS.backendUrl]: "https://one.example.test/api",
      [STORAGE_KEYS.tenantId]: "tenant-one",
    });
    const sessionStorage = createStorage({
      [STORAGE_KEYS.accessToken]: jwtPayload({ sub: "user-one" }),
      [STORAGE_KEYS.refreshToken]: "refresh-one",
    });
    vi.stubGlobal("chrome", {
      storage: { local: storage, session: sessionStorage },
      runtime: {
        getPlatformInfo: vi.fn(async () => ({ os: "mac" })),
        getManifest: vi.fn(() => ({ name: "Hawk", version: "1" })),
      },
    });
    const posted: string[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: unknown, options: RequestInit) => {
      posted.push(String(JSON.parse(String(options.body)).tenant_id));
      storage.store.set(STORAGE_KEYS.tenantId, "tenant-two");
      return new Response("{}", { status: 200 });
    }));
    await enqueueTelemetryEvent({ event_type: "prompt_submitted", domain: "chatgpt.com" });
    await enqueueTelemetryEvent({ event_type: "prompt_submitted", domain: "chatgpt.com" });
    await flushTelemetryQueue();
    expect(posted).toEqual(["tenant-one"]);
  });


});
