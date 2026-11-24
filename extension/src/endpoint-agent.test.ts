import { describe, expect, it, vi } from "vitest";

import {
  blockedDataTransferResult,
  blockedInteractionResult,
  blockedInteractionV2Result,
  DEFAULT_NATIVE_MESSAGE_TIMEOUT_MS,
  ENDPOINT_NATIVE_HOST,
  ENDPOINT_PROTOCOL_VERSION,
  evaluateEndpointFirst,
  getEndpointIdentityWithEndpointAgent,
  evaluateWithEndpointAgent,
  endpointDecisionMetadata,
  endpointPlatformMode,
  normalizeEndpointDecisionAction,
} from "./endpoint-agent";

describe("endpoint agent native messaging", () => {
  it("waits beyond the agent backend timeout before declaring native messaging unavailable", () => {
    expect(DEFAULT_NATIVE_MESSAGE_TIMEOUT_MS).toBe(10_000);
  });

  it("sends a versioned browser-only request to the Hawk native host", async () => {
    const sendNativeMessage = vi.fn((_host, _message, callback) => {
      callback({
        ok: true,
        protocol_version: ENDPOINT_PROTOCOL_VERSION,
        request_id: "request-1",
        endpoint_available: true,
        endpoint_authorized: true,
        action: "block",
        control_mode: "inline_prevented",
      });
    });

    const result = await evaluateWithEndpointAgent(
      { surface: "mcp", prompt: "sensitive prompt", url: "https://chatgpt.com/" },
      {
        runtime: { sendNativeMessage },
        requestId: () => "request-1",
      }
    );

    expect(sendNativeMessage).toHaveBeenCalledWith(
      ENDPOINT_NATIVE_HOST,
      {
        protocol_version: ENDPOINT_PROTOCOL_VERSION,
        request_id: "request-1",
        op: "evaluate",
        payload: {
          surface: "browser",
          prompt: "sensitive prompt",
          url: "https://chatgpt.com/",
        },
      },
      expect.any(Function)
    );
    expect(result.endpointAvailable).toBe(true);
    expect(result.endpointAuthorized).toBe(true);
    expect(result.decision?.action).toBe("block");
  });

  it("gets an endpoint identity only when the native bridge verified the enrolled device", async () => {
    const sendNativeMessage = vi.fn((_host, _message, callback) => {
      callback({
        ok: true,
        protocol_version: ENDPOINT_PROTOCOL_VERSION,
        request_id: "identity-1",
        endpoint_available: true,
        endpoint_identity_verified: true,
        endpoint_id: "9350fb98-60f0-590a-bbf6-9d5a9847a6c7",
        user_id: "user-1",
      });
    });

    const result = await getEndpointIdentityWithEndpointAgent({
      runtime: { sendNativeMessage },
      requestId: () => "identity-1",
    });

    expect(sendNativeMessage).toHaveBeenCalledWith(
      ENDPOINT_NATIVE_HOST,
      {
        protocol_version: ENDPOINT_PROTOCOL_VERSION,
        request_id: "identity-1",
        op: "identity",
      },
      expect.any(Function)
    );
    expect(result).toMatchObject({
      ok: true,
      endpointAvailable: true,
      endpointIdentityVerified: true,
      endpointId: "9350fb98-60f0-590a-bbf6-9d5a9847a6c7",
      userId: "user-1",
    });
  });

  it("does not accept an endpoint identity without native bridge verification", async () => {
    const sendNativeMessage = vi.fn((_host, _message, callback) => {
      callback({
        ok: true,
        protocol_version: ENDPOINT_PROTOCOL_VERSION,
        request_id: "identity-2",
        endpoint_available: true,
        endpoint_identity_verified: false,
        endpoint_id: "spoofed-endpoint",
      });
    });

    const result = await getEndpointIdentityWithEndpointAgent({
      runtime: { sendNativeMessage },
      requestId: () => "identity-2",
    });

    expect(result.ok).toBe(false);
    expect(result.endpointIdentityVerified).toBe(false);
    expect(result.endpointId).toBeUndefined();
  });

  it("returns an explicit unavailable result when Chrome cannot connect", async () => {
    const runtime = {
      lastError: undefined as { message?: string } | undefined,
      sendNativeMessage: vi.fn((_host, _message, callback) => {
        runtime.lastError = { message: "Specified native messaging host not found." };
        callback(undefined);
      }),
    };

    const result = await evaluateWithEndpointAgent(
      { prompt: "hello" },
      { runtime, requestId: () => "request-2" }
    );

    expect(result).toEqual({
      ok: false,
      endpointAvailable: false,
      endpointAuthorized: false,
      source: "endpoint_agent_unavailable",
      protocolVersion: ENDPOINT_PROTOCOL_VERSION,
      requestId: "request-2",
      error: "Specified native messaging host not found.",
    });
  });

  it("does not claim endpoint authorization for an unavailable agent response", async () => {
    const sendNativeMessage = vi.fn((_host, _message, callback) => {
      callback({
        ok: false,
        protocol_version: ENDPOINT_PROTOCOL_VERSION,
        request_id: "request-3",
        endpoint_available: false,
        endpoint_authorized: false,
        error: "agent_unavailable",
      });
    });

    const result = await evaluateWithEndpointAgent(
      { prompt: "hello" },
      { runtime: { sendNativeMessage }, requestId: () => "request-3" }
    );

    expect(result.endpointAvailable).toBe(false);
    expect(result.endpointAuthorized).toBe(false);
    expect(result.decision).toBeUndefined();
  });

  it("uses an endpoint decision before the backend fallback", async () => {
    const fallback = vi.fn(async () => ({ decision: "allow" }));
    const endpointEvaluate = vi.fn(async () => ({
      ok: true,
      endpointAvailable: true,
      endpointAuthorized: true,
      source: "endpoint_agent_native" as const,
      protocolVersion: ENDPOINT_PROTOCOL_VERSION,
      requestId: "request-4",
      decision: { ok: true as const, action: "block", reason: "secret_detected" },
    }));

    const result = await evaluateEndpointFirst(
      { prompt: "secret" },
      fallback,
      (decision) => ({ decision: decision.action }),
      { endpointEvaluate }
    );

    expect(result.decisionSource).toBe("endpoint_agent_native");
    expect(result.result).toEqual({ decision: "block" });
    expect(fallback).not.toHaveBeenCalled();
  });

  it("labels backend use as fallback when the native endpoint is unavailable", async () => {
    const fallback = vi.fn(async () => ({ decision: "warn" }));
    const endpointEvaluate = vi.fn(async () => ({
      ok: false,
      endpointAvailable: false,
      endpointAuthorized: false,
      source: "endpoint_agent_unavailable" as const,
      protocolVersion: ENDPOINT_PROTOCOL_VERSION,
      requestId: "request-5",
      error: "native host missing",
    }));

    const result = await evaluateEndpointFirst(
      { prompt: "hello" },
      fallback,
      () => ({ decision: "block" }),
      { endpointEvaluate }
    );

    expect(result.decisionSource).toBe("backend_fallback");
    expect(result.endpoint.endpointAuthorized).toBe(false);
    expect(result.result).toEqual({ decision: "warn" });
    expect(fallback).toHaveBeenCalledOnce();
  });

  it("fails closed without backend fallback when the endpoint is reachable but not authorized", async () => {
    const fallback = vi.fn(async () => ({ decision: "allow" }));
    const endpointEvaluate = vi.fn(async () => ({
      ok: false,
      endpointAvailable: true,
      endpointAuthorized: false,
      source: "endpoint_agent_native" as const,
      protocolVersion: ENDPOINT_PROTOCOL_VERSION,
      requestId: "request-6",
      error: "endpoint_authorization_failed",
    }));

    const result = await evaluateEndpointFirst(
      { prompt: "hello" },
      fallback,
      (decision) => ({ decision: decision.action }),
      {
        endpointEvaluate,
        mapNonAuthorized: blockedInteractionResult,
      }
    );

    expect(result.decisionSource).toBe("endpoint_agent_native_non_authorized");
    expect(result.endpoint.endpointAvailable).toBe(true);
    expect(result.endpoint.endpointAuthorized).toBe(false);
    expect(result.result.decision).toBe("block");
    expect(fallback).not.toHaveBeenCalled();
  });

  it("preserves a signed monitor decision without claiming endpoint authorization", async () => {
    const sendNativeMessage = vi.fn((_host, _message, callback) => {
      callback({
        ok: true,
        protocol_version: ENDPOINT_PROTOCOL_VERSION,
        request_id: "request-monitor-1",
        endpoint_available: true,
        endpoint_authorized: false,
        action: "allow",
        control_mode: "monitor_would_block",
      });
    });

    const result = await evaluateWithEndpointAgent(
      { prompt: "synthetic monitor prompt" },
      { runtime: { sendNativeMessage }, requestId: () => "request-monitor-1" }
    );

    expect(result).toMatchObject({
      ok: false,
      endpointAvailable: true,
      endpointAuthorized: false,
      decision: {
        action: "allow",
        control_mode: "monitor_would_block",
      },
    });
  });

  it("continues a verified monitor action without backend fallback or authorization coverage", async () => {
    const fallback = vi.fn(async () => ({ decision: "block" }));
    const endpointEvaluate = vi.fn(async () => ({
      ok: false,
      endpointAvailable: true,
      endpointAuthorized: false,
      source: "endpoint_agent_native" as const,
      protocolVersion: ENDPOINT_PROTOCOL_VERSION,
      requestId: "request-monitor-2",
      decision: {
        ok: true as const,
        action: "allow",
        control_mode: "monitor_would_block",
      },
    }));

    const evaluated = await evaluateEndpointFirst(
      { prompt: "synthetic monitor prompt" },
      fallback,
      (decision) => ({
        decision: normalizeEndpointDecisionAction(decision),
        platform_mode: endpointPlatformMode(decision),
      }),
      { endpointEvaluate, mapNonAuthorized: blockedInteractionResult }
    );

    expect(evaluated).toMatchObject({
      decisionSource: "endpoint_agent_native_non_authorized",
      endpoint: { endpointAuthorized: false },
      result: { decision: "allow", platform_mode: "discovery" },
    });
    expect(fallback).not.toHaveBeenCalled();
  });

  it("returns fail-secure browser result shapes for both interaction handlers", () => {
    const endpoint = {
      ok: false,
      endpointAvailable: true,
      endpointAuthorized: false,
      source: "endpoint_agent_native" as const,
      protocolVersion: ENDPOINT_PROTOCOL_VERSION,
      requestId: "request-7",
      error: "policy_unavailable",
    };

    expect(blockedInteractionResult(endpoint)).toMatchObject({
      decision: "block",
      tier: "clear_positive",
      platform_mode: "enforce",
      reason_codes: ["endpoint_authorization_unverified"],
    });
    expect(blockedInteractionV2Result(endpoint)).toMatchObject({
      decision: "block",
      evidence_required: true,
      reason_codes: ["endpoint_authorization_unverified"],
    });
  });

  it("returns a fail-secure data-transfer block instead of an allow-shaped error", () => {
    const result = blockedDataTransferResult({
      ok: false,
      endpointAvailable: true,
      endpointAuthorized: false,
      source: "endpoint_agent_native",
      protocolVersion: ENDPOINT_PROTOCOL_VERSION,
      requestId: "request-8",
      error: "policy_unavailable",
    });

    expect(result).toMatchObject({
      decision: "block",
      reason_code: "endpoint_authorization_unverified",
      recommended_action: "cancel_transfer",
      justification_required: false,
      platform_mode: "enforce",
    });
  });

  it("preserves reachable non-authorization provenance in handler metadata", () => {
    expect(endpointDecisionMetadata({
      decisionSource: "endpoint_agent_native_non_authorized",
      endpoint: {
        ok: false,
        endpointAvailable: true,
        endpointAuthorized: false,
        source: "endpoint_agent_native",
        protocolVersion: ENDPOINT_PROTOCOL_VERSION,
        requestId: "request-9",
        error: "policy_unavailable",
      },
    })).toEqual({
      endpointAvailable: true,
      endpointAuthorized: false,
      decisionSource: "endpoint_agent_native_non_authorized",
    });
  });

  it.each(["redact", "hold", "review", "require_approval", "require_step_up", "", "garbage"])(
    "fails closed for non-allow endpoint action %s",
    (action) => {
      expect(normalizeEndpointDecisionAction({ ok: true, action })).toBe("block");
    }
  );

  it("blocks scope unless the endpoint explicitly proves browser enforcement", () => {
    expect(normalizeEndpointDecisionAction({ ok: true, action: "scope" })).toBe("block");
    expect(normalizeEndpointDecisionAction({
      ok: true,
      action: "scope",
      detail: {
        constraints_enforced: true,
        constraints_enforcement_surface: "browser_extension",
      },
    })).toBe("allow");
  });

  it.each(["monitor_observation", "monitor_would_block", "shadow_would_block"])(
    "maps non-enforcing control mode %s to discovery",
    (controlMode) => {
      expect(endpointPlatformMode({ ok: true, control_mode: controlMode })).toBe("discovery");
    }
  );

  it("times out a silent native host and ignores a late callback", async () => {
    vi.useFakeTimers();
    try {
      let callback: ((response?: unknown) => void) | undefined;
      const runtime = {
        sendNativeMessage: vi.fn((_host, _message, value) => {
          callback = value;
        }),
      };
      const resultPromise = evaluateWithEndpointAgent(
        { prompt: "hello" },
        { runtime, requestId: () => "request-10", timeoutMs: 50 }
      );

      await vi.advanceTimersByTimeAsync(50);
      await expect(resultPromise).resolves.toMatchObject({
        ok: false,
        endpointAvailable: false,
        endpointAuthorized: false,
        source: "endpoint_agent_unavailable",
        error: "native_host_timeout",
      });

      callback?.({
        ok: true,
        protocol_version: ENDPOINT_PROTOCOL_VERSION,
        request_id: "request-10",
        endpoint_available: true,
        endpoint_authorized: true,
        action: "allow",
      });
      await vi.runAllTimersAsync();
    } finally {
      vi.useRealTimers();
    }
  });

  it("labels native-host timeout as backend fallback without endpoint coverage", async () => {
    vi.useFakeTimers();
    try {
      const fallback = vi.fn(async () => ({ decision: "warn" }));
      const endpointEvaluate = () => evaluateWithEndpointAgent(
        { prompt: "hello" },
        {
          runtime: { sendNativeMessage: vi.fn(() => undefined) },
          requestId: () => "request-11",
          timeoutMs: 25,
        }
      );
      const evaluatedPromise = evaluateEndpointFirst(
        { prompt: "hello" },
        fallback,
        (decision) => ({ decision: decision.action }),
        { endpointEvaluate }
      );

      await vi.advanceTimersByTimeAsync(25);
      await expect(evaluatedPromise).resolves.toMatchObject({
        decisionSource: "backend_fallback",
        endpoint: {
          endpointAvailable: false,
          endpointAuthorized: false,
          error: "native_host_timeout",
        },
        result: { decision: "warn" },
      });
      expect(fallback).toHaveBeenCalledOnce();
    } finally {
      vi.useRealTimers();
    }
  });
});
