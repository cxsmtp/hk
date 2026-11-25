import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export class ExecutiveApiClient {
  constructor({ apiUrl, tenantId, accessToken, timeoutMs = 15000 } = {}) {
    this.apiUrl = normalizeBaseUrl(apiUrl || process.env.HAWK_EXEC_API_URL || process.env.HAWK_API_URL);
    this.tenantId = String(tenantId || process.env.HAWK_EXEC_TENANT_ID || process.env.HAWK_TENANT_ID || "").trim();
    this.accessToken = String(accessToken || process.env.HAWK_EXEC_ACCESS_TOKEN || process.env.HAWK_ACCESS_TOKEN || "").trim();
    this.timeoutMs = Number(timeoutMs || process.env.HAWK_EXEC_MCP_TIMEOUT_MS || process.env.HAWK_MCP_TIMEOUT_MS || 15000);
    if (!this.apiUrl) {
      throw new Error("Executive MCP requires HAWK_EXEC_API_URL or HAWK_API_URL");
    }
    if (!this.tenantId) {
      throw new Error("Executive MCP requires HAWK_EXEC_TENANT_ID or HAWK_TENANT_ID");
    }
    if (!this.accessToken) {
      throw new Error("Executive MCP requires HAWK_EXEC_ACCESS_TOKEN or HAWK_ACCESS_TOKEN");
    }
  }

  getSummary({ windowDays = 30 } = {}) {
    return this.#request("GET", `/executive-mcp/summary?window_days=${boundedInt(windowDays, 1, 366)}`);
  }

  queryMetrics({ metric, groupBy = null, windowDays = 30, limit = 10, includeNamedUsers = false } = {}) {
    return this.#request("POST", "/executive-mcp/query", {
      metric,
      group_by: groupBy,
      window_days: boundedInt(windowDays, 1, 366),
      limit: boundedInt(limit, 1, 100),
      include_named_users: Boolean(includeNamedUsers),
    });
  }

  async createPresentation({ title = "Executive AI Governance Brief", windowDays = 30 } = {}) {
    const result = await this.#request("POST", "/executive-mcp/presentations", {
      title,
      window_days: boundedInt(windowDays, 1, 366),
    });
    if (result?.content_base64 && result?.filename) {
      const outputDir = path.join(os.tmpdir(), "hawk-executive-mcp");
      fs.mkdirSync(outputDir, { recursive: true });
      const localPath = path.join(outputDir, sanitizeFilename(result.filename));
      fs.writeFileSync(localPath, Buffer.from(result.content_base64, "base64"));
      return {
        ...result,
        local_path: localPath,
        content_base64: undefined,
        note: "Presentation written locally for the connected assistant.",
      };
    }
    return result;
  }

  async #request(method, path, body = undefined) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const response = await fetch(`${this.apiUrl}${path}`, {
        method,
        headers: {
          Authorization: `Bearer ${this.accessToken}`,
          "Content-Type": "application/json",
          "X-Tenant-ID": this.tenantId,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      });
      const text = await response.text();
      let parsed;
      try {
        parsed = text ? JSON.parse(text) : {};
      } catch {
        parsed = { detail: text.slice(0, 1000) };
      }
      if (!response.ok) {
        const detail = parsed?.detail || parsed?.message || response.statusText;
        throw new Error(`Executive MCP API ${response.status}: ${stringifyDetail(detail)}`);
      }
      return parsed;
    } finally {
      clearTimeout(timer);
    }
  }
}

function sanitizeFilename(value) {
  return String(value || "executive-brief.pptx").replace(/[^a-zA-Z0-9._-]/g, "_").slice(0, 160);
}

function normalizeBaseUrl(value) {
  const text = String(value || "").trim();
  return text ? text.replace(/\/+$/, "") : "";
}

function boundedInt(value, min, max) {
  const parsed = Number.parseInt(String(value ?? min), 10);
  if (!Number.isFinite(parsed)) {
    return min;
  }
  return Math.max(min, Math.min(parsed, max));
}

function stringifyDetail(detail) {
  if (typeof detail === "string") {
    return detail;
  }
  try {
    return JSON.stringify(detail);
  } catch {
    return "request failed";
  }
}
