"use client";

import { useEffect, useRef } from "react";

import { getSession } from "@/lib/auth";
import { API_BASE_URL } from "@/lib/api-url";
import type { SimulationStreamEvent } from "@/lib/types";

type UseSimulationStreamOptions = {
  enabled?: boolean;
  onEvent: (event: SimulationStreamEvent) => void;
  onReconnect?: () => void;
  onConnectionStateChange?: (connected: boolean) => void;
  reconnectBaseMs?: number;
  reconnectMaxMs?: number;
};

const API_URL = API_BASE_URL;

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => {
    setTimeout(resolve, ms);
  });
}

function parseSseBuffer(
  input: string,
  onEvent: (event: SimulationStreamEvent) => void
): string {
  const chunks = input.split("\n\n");
  const complete = chunks.slice(0, -1);
  const remainder = chunks[chunks.length - 1] || "";

  for (const chunk of complete) {
    const block = chunk.trim();
    if (!block || block.startsWith(":")) continue;
    const lines = block.split("\n");
    let eventType = "";
    const dataLines: string[] = [];

    for (const line of lines) {
      if (line.startsWith("event:")) {
        eventType = line.slice("event:".length).trim();
      } else if (line.startsWith("data:")) {
        dataLines.push(line.slice("data:".length).trim());
      }
    }

    if (!dataLines.length) continue;

    try {
      const payload = JSON.parse(dataLines.join("\n")) as SimulationStreamEvent;
      const normalized = {
        ...payload,
        event_type: String(payload.event_type || eventType || "").trim() || eventType,
      } as SimulationStreamEvent;
      onEvent(normalized);
    } catch {
      continue;
    }
  }

  return remainder;
}

export function useSimulationStream(options: UseSimulationStreamOptions): void {
  const abortRef = useRef<AbortController | null>(null);
  const onEventRef = useRef(options.onEvent);
  const onReconnectRef = useRef(options.onReconnect);
  const onConnectionStateChangeRef = useRef(options.onConnectionStateChange);

  useEffect(() => {
    onEventRef.current = options.onEvent;
    onReconnectRef.current = options.onReconnect;
    onConnectionStateChangeRef.current = options.onConnectionStateChange;
  }, [options.onEvent, options.onReconnect, options.onConnectionStateChange]);

  useEffect(() => {
    const enabled = options.enabled !== false;
    if (!enabled) return;

    let stopped = false;
    let hasConnectedOnce = false;

    const start = async () => {
      let attempt = 0;
      while (!stopped) {
        const session = getSession();
        if (!session?.tenantId) {
          onConnectionStateChangeRef.current?.(false);
          await sleep(1000);
          continue;
        }

        const controller = new AbortController();
        abortRef.current = controller;

        try {
          const response = await fetch(`${API_URL}/simulations/runs/stream`, {
            method: "GET",
            headers: {
              Accept: "text/event-stream",
              "X-Tenant-ID": session.tenantId,
            },
            // The session cookie (apps/api/app/core/session_cookies.py): a GET, so no CSRF token.
            credentials: "include",
            cache: "no-store",
            signal: controller.signal,
          });

          if (!response.ok || !response.body) {
            throw new Error(`Simulation SSE connection failed: ${response.status}`);
          }

          attempt = 0;
          onConnectionStateChangeRef.current?.(true);
          if (hasConnectedOnce) {
            onReconnectRef.current?.();
          }
          hasConnectedOnce = true;

          const reader = response.body.getReader();
          const decoder = new TextDecoder();
          let buffer = "";

          while (!stopped) {
            const { done, value } = await reader.read();
            if (done) break;
            buffer += decoder.decode(value, { stream: true });
            buffer = parseSseBuffer(buffer, (event) => onEventRef.current(event));
          }
        } catch {
          onConnectionStateChangeRef.current?.(false);
        } finally {
          abortRef.current = null;
        }

        if (stopped) break;
        attempt += 1;
        const base = Math.max(250, options.reconnectBaseMs ?? 1000);
        const max = Math.max(base, options.reconnectMaxMs ?? 15000);
        const delay = Math.min(max, base * (2 ** Math.min(attempt, 6)));
        await sleep(delay);
      }
    };

    start().catch(() => undefined);

    return () => {
      stopped = true;
      abortRef.current?.abort();
      onConnectionStateChangeRef.current?.(false);
    };
  }, [
    options.enabled,
    options.reconnectBaseMs,
    options.reconnectMaxMs,
  ]);
}
