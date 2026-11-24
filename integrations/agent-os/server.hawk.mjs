import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import fetch from "node-fetch";
import { google } from "googleapis";

import { HawkAgentBindingBlockedError, createAgentOsBinding } from "./hawk-binding.mjs";

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const OLLAMA_URL = process.env.OLLAMA_URL || "http://localhost:11434";
const TAVILY_KEY = process.env.TAVILY_API_KEY || "";
const COMPOSIO_KEY = process.env.COMPOSIO_API_KEY || "";
const ENTITY_ID = process.env.COMPOSIO_ENTITY_ID || "sith-raffe";
const GOOGLE_GMAIL_ACCESS_TOKEN = process.env.GOOGLE_GMAIL_ACCESS_TOKEN || "";
const PORT = Number(process.env.PORT || 4000);

let hawkBinding = null;
let hawkRegistrationError = null;

const AGENT_SYSTEM_PROMPT = `You are an autonomous AI agent for Ayush.

CRITICAL RULES — never break these:
1. ALWAYS respond in English only. Never use any other language.
2. NEVER ask clarifying questions — execute the requested task immediately.
3. NEVER claim a tool action succeeded unless the tool returned success.
4. For research + draft requests, call web_search and then GMAIL_CREATE_DRAFT.
5. When asked to save a draft or draft an email, call GMAIL_CREATE_DRAFT.
6. If no recipient is specified, leave recipient_email blank and create the draft.
7. Hawk authorization is mandatory before every model or tool execution.

You are a governed executor. Search → Draft → Confirm.`;

const TOOL_DEFS = [
  {
    type: "function",
    function: {
      name: "web_search",
      description: "Search the web for current information, company research, news.",
      parameters: {
        type: "object",
        properties: {
          query: { type: "string", description: "Search query" },
          max_results: { type: "number", description: "Number of results (default 5)" },
        },
        required: ["query"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "GMAIL_CREATE_DRAFT",
      description: "Create a draft email saved in Gmail drafts folder.",
      parameters: {
        type: "object",
        properties: {
          recipient_email: { type: "string", description: "Recipient email address" },
          subject: { type: "string", description: "Email subject line" },
          body: { type: "string", description: "Full email body content" },
        },
        required: ["subject", "body"],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "GMAIL_FETCH_EMAILS",
      description: "Fetch and read emails from Gmail inbox.",
      parameters: {
        type: "object",
        properties: {
          max_results: { type: "number", description: "Number of emails to fetch" },
          label: { type: "string", description: "Gmail label such as INBOX, SENT, or DRAFT" },
          query: { type: "string", description: "Search query to filter emails" },
        },
        required: [],
      },
    },
  },
  {
    type: "function",
    function: {
      name: "GMAIL_SEND_EMAIL",
      description: "Send an email immediately via Gmail.",
      parameters: {
        type: "object",
        properties: {
          recipient_email: { type: "string", description: "Recipient email address" },
          subject: { type: "string", description: "Email subject line" },
          body: { type: "string", description: "Full email body" },
        },
        required: ["recipient_email", "subject", "body"],
      },
    },
  },
];

function requireHawkBinding() {
  if (!hawkBinding) {
    throw new HawkAgentBindingBlockedError(
      hawkRegistrationError || "hawk_endpoint_binding_unavailable",
    );
  }
  return hawkBinding;
}

async function initializeHawk() {
  try {
    hawkBinding = await createAgentOsBinding({
      capabilityTokenProvider: () => process.env.HAWK_AGENT_CAPABILITY_TOKEN || "",
    });
    const response = await fetch(`${OLLAMA_URL}/api/tags`);
    const data = response.ok ? await response.json() : { models: [] };
    await hawkBinding.register({ models: (data.models || []).map((model) => model.name) });
    hawkRegistrationError = null;
  } catch (error) {
    hawkBinding = null;
    hawkRegistrationError = error instanceof HawkAgentBindingBlockedError
      ? error.reasonCode
      : "hawk_endpoint_registration_failed";
    console.error(`[Hawk] ${hawkRegistrationError}`);
  }
}

async function composioExecute(toolName, args) {
  if (!COMPOSIO_KEY) throw new Error("COMPOSIO_API_KEY is not configured");
  const response = await fetch(
    `https://backend.composio.dev/api/v2/actions/${toolName}/execute`,
    {
      method: "POST",
      headers: {
        "x-api-key": COMPOSIO_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ input: args, appName: "gmail", entityId: ENTITY_ID }),
    },
  );
  const text = await response.text();
  if (!response.ok) throw new Error(`Composio returned HTTP ${response.status}`);
  try {
    const data = JSON.parse(text);
    return JSON.stringify(data.data || data.response || data);
  } catch {
    return text.slice(0, 500);
  }
}

function safeHeader(value) {
  return String(value || "").replace(/[\r\n]+/g, " ").trim();
}

function rawEmail({ recipient_email = "", subject = "", body = "" }) {
  const lines = [
    `To: ${safeHeader(recipient_email)}`,
    `Subject: ${safeHeader(subject)}`,
    "Content-Type: text/plain; charset=utf-8",
    "MIME-Version: 1.0",
    "",
    String(body || ""),
  ];
  return Buffer.from(lines.join("\r\n"), "utf8").toString("base64url");
}

function directGmailClient() {
  if (!GOOGLE_GMAIL_ACCESS_TOKEN) {
    throw new Error("GOOGLE_GMAIL_ACCESS_TOKEN is not configured");
  }
  const auth = new google.auth.OAuth2();
  auth.setCredentials({ access_token: GOOGLE_GMAIL_ACCESS_TOKEN });
  return google.gmail({ version: "v1", auth });
}

async function googleDirectExecute(toolName, args) {
  const gmail = directGmailClient();
  if (toolName === "GMAIL_FETCH_EMAILS") {
    const maxResults = Math.max(1, Math.min(20, Number(args.max_results || 5)));
    const list = await gmail.users.messages.list({
      userId: "me",
      maxResults,
      labelIds: args.label ? [safeHeader(args.label)] : undefined,
      q: args.query ? String(args.query) : undefined,
    });
    const messages = await Promise.all(
      (list.data.messages || []).map(async ({ id }) => {
        if (!id) return null;
        const message = await gmail.users.messages.get({ userId: "me", id, format: "metadata" });
        return {
          id,
          threadId: message.data.threadId,
          snippet: message.data.snippet,
          headers: (message.data.payload?.headers || []).filter((header) =>
            ["From", "To", "Subject", "Date"].includes(String(header.name || "")),
          ),
        };
      }),
    );
    return JSON.stringify(messages.filter(Boolean));
  }
  if (toolName === "GMAIL_CREATE_DRAFT") {
    const response = await gmail.users.drafts.create({
      userId: "me",
      requestBody: { message: { raw: rawEmail(args) } },
    });
    return JSON.stringify({ draftId: response.data.id, messageId: response.data.message?.id });
  }
  if (toolName === "GMAIL_SEND_EMAIL") {
    const response = await gmail.users.messages.send({
      userId: "me",
      requestBody: { raw: rawEmail(args) },
    });
    return JSON.stringify({ messageId: response.data.id, threadId: response.data.threadId });
  }
  throw new Error("Unsupported Gmail tool");
}

async function executeGmail(toolName, args) {
  const transport = requireHawkBinding().activeGmailTransport;
  if (transport === "composio") return composioExecute(toolName, args);
  if (transport === "google_direct") return googleDirectExecute(toolName, args);
  throw new Error("No verified Gmail transport is active");
}

async function runWebSearch({ query, max_results = 5 }) {
  if (!TAVILY_KEY) throw new Error("Web search is not configured");
  const response = await fetch("https://api.tavily.com/search", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      api_key: TAVILY_KEY,
      query,
      max_results: Math.max(1, Math.min(10, Number(max_results || 5))),
      search_depth: "basic",
      include_answer: true,
    }),
  });
  if (!response.ok) throw new Error(`Tavily returned HTTP ${response.status}`);
  const data = await response.json();
  if (data.answer) {
    const sources = (data.results || []).slice(0, 5)
      .map((result, index) => `[${index + 1}] ${result.title}\n${result.content?.slice(0, 300)}`)
      .join("\n\n");
    return `Answer: ${data.answer}\n\nSources:\n${sources}`;
  }
  return (data.results || [])
    .map((result) => `${result.title}: ${result.content?.slice(0, 400)}`)
    .join("\n\n");
}

async function guardedOllamaChat({ model, messages, tools }) {
  const prompt = String(messages.at(-1)?.content || "");
  const { result } = await requireHawkBinding().withLlmAuthorization(
    { prompt, model },
    async () => {
      const response = await fetch(`${OLLAMA_URL}/api/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model, messages, stream: false, ...(tools ? { tools } : {}) }),
      });
      if (!response.ok) throw new Error(`Ollama returned HTTP ${response.status}`);
      return response.json();
    },
  );
  return result;
}

async function runTool(toolName, args) {
  const { result } = await requireHawkBinding().withToolAuthorization(
    { toolName, args },
    async () => toolName === "web_search" ? runWebSearch(args) : executeGmail(toolName, args),
  );
  return result;
}

async function runAgentLoop(messages, model, maxIterations = 8) {
  const toolsUsed = [];
  const toolDefs = TAVILY_KEY ? TOOL_DEFS : TOOL_DEFS.filter((tool) => tool.function.name !== "web_search");
  for (let iteration = 0; iteration < maxIterations; iteration += 1) {
    const data = await guardedOllamaChat({ model, messages, tools: toolDefs });
    const message = data.message;
    if (!message?.tool_calls?.length) return { content: message?.content || "", toolsUsed };
    messages.push({ role: "assistant", content: message.content || "", tool_calls: message.tool_calls });
    for (const call of message.tool_calls) {
      const name = call.function?.name;
      let args = {};
      try {
        args = typeof call.function?.arguments === "string"
          ? JSON.parse(call.function.arguments)
          : call.function?.arguments || {};
      } catch {
        args = {};
      }
      toolsUsed.push(name);
      let result;
      try {
        result = await runTool(name, args);
      } catch (error) {
        if (error instanceof HawkAgentBindingBlockedError) {
          result = `Blocked by Hawk: ${error.reasonCode}`;
        } else {
          result = `Tool error: ${error.message}`;
        }
      }
      messages.push({ role: "tool", content: String(result) });
    }
  }
  const data = await guardedOllamaChat({ model, messages });
  return { content: data.message?.content || "Task completed.", toolsUsed };
}

app.post("/api/chat", async (request, response) => {
  const { messages: history = [], userMessage, model = "qwen3.5:9b" } = request.body;
  if (!userMessage) return response.status(400).json({ error: "userMessage required" });
  const messages = [
    { role: "system", content: AGENT_SYSTEM_PROMPT },
    ...history.filter((message) => !message.isLoading).map((message) => ({
      role: message.role,
      content: message.content,
    })),
    { role: "user", content: userMessage },
  ];
  try {
    return response.json(await runAgentLoop(messages, model));
  } catch (error) {
    const blocked = error instanceof HawkAgentBindingBlockedError;
    return response.status(blocked ? 403 : 500).json({
      error: blocked ? "Blocked by Hawk" : "Agent execution failed",
      reason_code: blocked ? error.reasonCode : "agent_execution_failed",
    });
  }
});

app.get("/api/health", async (_request, response) => {
  let models = [];
  let ollama = false;
  try {
    const result = await fetch(`${OLLAMA_URL}/api/tags`);
    const data = result.ok ? await result.json() : { models: [] };
    models = (data.models || []).map((model) => model.name);
    ollama = result.ok;
  } catch {
    ollama = false;
  }
  const hawk = hawkBinding?.status() || {
    activeGmailTransport: "unknown",
    mode: process.env.HAWK_AGENT_MODE || "enforce",
    registration: null,
    lastDecision: null,
  };
  response.json({
    status: hawkBinding ? "ok" : "degraded",
    ollama,
    models,
    tavilyConfigured: Boolean(TAVILY_KEY),
    gmailTransport: hawk.activeGmailTransport,
    gmailConfigured: hawk.activeGmailTransport === "composio"
      ? Boolean(COMPOSIO_KEY)
      : hawk.activeGmailTransport === "google_direct"
        ? Boolean(GOOGLE_GMAIL_ACCESS_TOKEN)
        : false,
    hawk: {
      bound: Boolean(hawkBinding),
      mode: hawk.mode,
      registration: hawk.registration,
      lastDecision: hawk.lastDecision,
      error: hawkRegistrationError,
    },
  });
});

app.listen(PORT, async () => {
  console.log(`Agent OS running on http://localhost:${PORT}`);
  await initializeHawk();
});
