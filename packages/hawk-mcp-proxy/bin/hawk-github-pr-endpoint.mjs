#!/usr/bin/env node
import { execFileSync, spawn } from "node:child_process";
import { readFileSync, openSync, closeSync, fstatSync, lstatSync, constants } from "node:fs";
import { createHash } from "node:crypto";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import process from "node:process";
import { fileURLToPath, pathToFileURL } from "node:url";

import {
  normalizeGitHubRepositoryScope,
  repositoryScopedMcpServerId,
} from "../src/policy.mjs";

const ACCEPTANCE_PROFILES = new Set(["cli", "desktop", "claude"]);
const SAFE_ENVIRONMENT_NAMES = new Set([
  "ALL_PROXY",
  "HOME",
  "HTTPS_PROXY",
  "HTTP_PROXY",
  "LANG",
  "LC_ALL",
  "LC_CTYPE",
  "NO_PROXY",
  "PATH",
  "SSL_CERT_DIR",
  "SSL_CERT_FILE",
  "TERM",
  "TMPDIR",
]);
const TOOL_SCOPE = "list_pull_requests,pull_request_read,create_branch,create_or_update_file,create_pull_request";
export const GITHUB_CLI_PATH = process.env.HAWK_GITHUB_CLI_PATH || "/usr/local/bin/gh";
export const GITHUB_CLI_SHA256 = "eedbfd5b8071027fe6326826eded48d274f1ec9d93f9239d9ba778ea1f479ac9";
const GITHUB_AUTH_SCOPE = "github.com/jd2402247-sudo/hawk-governed-ai-demo-private";
const GITHUB_AUTH_ERROR = "GitHub CLI credential unavailable";
const GITHUB_ACCOUNT_ERROR = "Existing GitHub CLI account must be explicitly selected";
const CLAUDE_CAPABILITY_TOKEN_ERROR = "Claude capability token unavailable";
const CLAUDE_KEYCHAIN_REFERENCE_ERROR = "Claude Keychain reference unavailable";
const CLAUDE_SESSION_ID_ERROR = "Claude session identifier unavailable";
const MAX_CLAUDE_CAPABILITY_TOKEN_LENGTH = 4096;
const MAX_CLAUDE_KEYCHAIN_REFERENCE_LENGTH = 128;
const MAX_CLAUDE_SESSION_ID_LENGTH = 128;
const SAFE_CLAUDE_KEYCHAIN_REFERENCE = /^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,127}$/;
const SAFE_CLAUDE_SESSION_ID = /^mcp_sess_[A-Za-z0-9_-]+$/;
const CLIENT_APP_BY_PROFILE = {
  cli: "Codex CLI",
  desktop: "Codex",
  claude: "Claude Desktop",
};

export function buildLaunchConfig({
  profile,
  endpointConfigPath,
  endpointSocketPath,
  githubBinaryPath,
  repositoryScope = null,
  keychainService = null,
  keychainAccount = null,
  sessionId = null,
  githubAuthSource = null,
  githubUser = null,
  nodePath = process.execPath,
  parentEnv = process.env,
  proxyPath = fileURLToPath(new URL("./hawk-mcp-proxy.mjs", import.meta.url)),
  userHome = homedir(),
  capabilityTokenReader = readClaudeCapabilityTokenFromKeychain,
  githubTokenReader = readExistingGitHubCliToken,
} = {}) {
  if (!ACCEPTANCE_PROFILES.has(profile)) {
    throw new Error("Profile must be one of: cli, desktop, claude");
  }

  const configPath = endpointConfigPath || join(
    userHome,
    "Library",
    "Application Support",
    "Hawk",
    "EndpointAgent",
    "state",
    "endpoint-agent.json",
  );
  const endpointConfig = readEndpointConfig(configPath);
  const thumbprint = String(endpointConfig.ipc_trusted_device_thumbprint || "").trim();
  if (!/^[0-9a-f]{64}$/.test(thumbprint)) {
    throw new Error("Endpoint config must contain a valid lowercase SHA256 IPC trusted device thumbprint");
  }

  const configuredSocketPath = endpointSocketPath
    || endpointConfig.ipc_socket_path
    || join(userHome, ".config", "hawk", "agent.sock");
  const socketPath = configuredSocketPath.startsWith("~/")
    ? join(userHome, configuredSocketPath.slice(2))
    : configuredSocketPath;
  const binaryPath = githubBinaryPath || join(
    userHome,
    "Library",
    "Application Support",
    "Hawk",
    "MCP",
    "bin",
    "github-mcp-server-v1.8.0",
  );
  const normalizedRepositoryScope = normalizeGitHubRepositoryScope(repositoryScope);
  if (repositoryScope !== null && repositoryScope !== undefined && !normalizedRepositoryScope) {
    throw new Error("GitHub repository scope must be github.com/<owner>/<repository>");
  }
  if (githubAuthSource !== null && githubAuthSource !== "gh-session") {
    throw new Error("Unsupported GitHub credential source");
  }
  if (githubAuthSource === null && githubUser !== null) {
    throw new Error(GITHUB_ACCOUNT_ERROR);
  }
  if (githubAuthSource === "gh-session") {
    if (!["cli", "desktop"].includes(profile) || normalizedRepositoryScope !== GITHUB_AUTH_SCOPE) {
      throw new Error("GitHub CLI credential mode requires the exact customer repository and Codex profile");
    }
    if (typeof githubUser !== "string" || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(githubUser) || githubUser.includes("--")) {
      throw new Error(GITHUB_ACCOUNT_ERROR);
    }
  }
  if (profile === "claude" && !normalizedRepositoryScope) {
    throw new Error("Claude profile requires a GitHub repository scope");
  }
  const resolvedSessionId = profile === "claude"
    ? validateClaudeSessionId(sessionId)
    : `github-pr-${profile}-20260809`;
  const mcpServerId = normalizedRepositoryScope
    ? repositoryScopedMcpServerId(normalizedRepositoryScope)
    : "github-pull-requests";
  const env = sanitizeEnvironment(parentEnv);
  if (githubAuthSource === "gh-session") {
    try {
      const raw = githubTokenReader({ user: githubUser, environment: env });
      const token = typeof raw === "string" ? raw.replace(/\r?\n$/, "") : "";
      if (!/^[\x21-\x7e]{1,4096}$/.test(token)) throw new Error("invalid token");
      env.GITHUB_PERSONAL_ACCESS_TOKEN = token;
    } catch {
      // Never propagate command stdout/stderr or error properties containing secrets.
      throw new Error(GITHUB_AUTH_ERROR);
    }
  }
  if (profile === "claude") {
    env.HAWK_CAPABILITY_TOKEN = readClaudeCapabilityToken(capabilityTokenReader, {
      service: validateClaudeKeychainReference(keychainService),
      account: validateClaudeKeychainReference(keychainAccount),
    });
  }

  return {
    command: nodePath,
    args: [
      proxyPath,
      "--endpoint-socket", socketPath,
      "--endpoint-device-thumbprint", thumbprint,
      "--server-id", mcpServerId,
      ...(normalizedRepositoryScope
        ? ["--repository-scope", normalizedRepositoryScope]
        : []),
      "--session-id", resolvedSessionId,
      "--client-app", CLIENT_APP_BY_PROFILE[profile],
      "--allowed-tools", TOOL_SCOPE,
      // The proxy passes the GitHub MCP server only a minimal environment: its token is named explicitly.
      ...(env.GITHUB_PERSONAL_ACCESS_TOKEN
        ? ["--pass-env", "GITHUB_PERSONAL_ACCESS_TOKEN"]
        : []),
      "--",
      binaryPath,
      "stdio",
      "--tools", TOOL_SCOPE,
    ],
    env,
  };
}

export function sanitizeEnvironment(parentEnv = {}) {
  return Object.fromEntries(
    Object.entries(parentEnv).filter(([name, value]) => (
      SAFE_ENVIRONMENT_NAMES.has(name) && typeof value === "string" && value.length > 0
    )),
  );
}

function executableIdentity(info) {
  return [info.dev, info.ino, info.uid, info.gid, info.mode, info.nlink, info.size, info.mtimeMs, info.ctimeMs].join(":");
}

export function readExistingGitHubCliToken({ user, environment }, {
  run = execFileSync,
  path = GITHUB_CLI_PATH,
  expectedHash = GITHUB_CLI_SHA256,
} = {}) {
  let fd;
  try {
    if (typeof user !== "string" || !/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/.test(user) || user.includes("--")) throw new Error("invalid user");
    const before = lstatSync(path);
    if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) throw new Error("invalid executable");
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
    const opened = fstatSync(fd);
    if (executableIdentity(opened) !== executableIdentity(before)) throw new Error("identity changed");
    if (createHash("sha256").update(readFileSync(fd)).digest("hex") !== expectedHash) throw new Error("pin mismatch");
    if (executableIdentity(fstatSync(fd)) !== executableIdentity(before) || executableIdentity(lstatSync(path)) !== executableIdentity(before)) throw new Error("identity changed");
    const output = run(path, ["auth", "token", "--hostname", "github.com", "--user", user], {
      encoding: "utf8", shell: false, timeout: 5000, maxBuffer: 8192,
      stdio: ["ignore", "pipe", "ignore"], env: sanitizeEnvironment(environment),
    });
    if (executableIdentity(fstatSync(fd)) !== executableIdentity(before) || executableIdentity(lstatSync(path)) !== executableIdentity(before)) throw new Error("executable changed");
    return output;
  } catch {
    throw new Error(GITHUB_AUTH_ERROR);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

function readEndpointConfig(configPath) {
  try {
    return JSON.parse(readFileSync(configPath, "utf8"));
  } catch {
    throw new Error(`Unable to read installed Hawk endpoint config: ${configPath}`);
  }
}

function readClaudeCapabilityToken(reader, { service, account }) {
  try {
    if (typeof reader !== "function") {
      throw new Error("invalid capability reader");
    }
    const rawToken = reader({ service, account });
    if (typeof rawToken !== "string") {
      throw new Error("invalid capability token");
    }
    const token = rawToken.endsWith("\r\n")
      ? rawToken.slice(0, -2)
      : rawToken.endsWith("\n")
        ? rawToken.slice(0, -1)
        : rawToken;
    if (
      token.length === 0
      || token.length > MAX_CLAUDE_CAPABILITY_TOKEN_LENGTH
      || /[\r\n]/.test(token)
    ) {
      throw new Error("invalid capability token");
    }
    return token;
  } catch {
    throw new Error(CLAUDE_CAPABILITY_TOKEN_ERROR);
  }
}

function validateClaudeKeychainReference(value) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > MAX_CLAUDE_KEYCHAIN_REFERENCE_LENGTH
    || !SAFE_CLAUDE_KEYCHAIN_REFERENCE.test(value)
  ) {
    throw new Error(CLAUDE_KEYCHAIN_REFERENCE_ERROR);
  }
  return value;
}

function validateClaudeSessionId(value) {
  if (
    typeof value !== "string"
    || value.length === 0
    || value.length > MAX_CLAUDE_SESSION_ID_LENGTH
    || !SAFE_CLAUDE_SESSION_ID.test(value)
  ) {
    throw new Error(CLAUDE_SESSION_ID_ERROR);
  }
  return value;
}

function readClaudeCapabilityTokenFromKeychain({ service, account }) {
  return execFileSync(
    "/usr/bin/security",
    ["find-generic-password", "-s", service, "-a", account, "-w"],
    { encoding: "utf8", shell: false, stdio: ["ignore", "pipe", "ignore"] },
  );
}

function isDirectExecution() {
  if (!process.argv[1]) return false;
  return pathToFileURL(process.argv[1]).href === import.meta.url;
}

export function parseLaunchArguments(argv) {
  const [profile, ...optionArgs] = argv;
  const options = {
    profile,
    repositoryScope: null,
    keychainService: null,
    keychainAccount: null,
    sessionId: null,
  };
  for (let index = 0; index < optionArgs.length; index += 2) {
    const option = optionArgs[index];
    const value = optionArgs[index + 1];
    const destination = {
      "--repository-scope": "repositoryScope",
      "--keychain-service": "keychainService",
      "--keychain-account": "keychainAccount",
      "--session-id": "sessionId",
      "--github-auth-source": "githubAuthSource",
      "--github-user": "githubUser",
    }[option];
    if (!destination || !value || (destination in options && options[destination] !== null)) {
      throw new Error("Usage: hawk-github-pr-endpoint <cli|desktop|claude> [--repository-scope github.com/<owner>/<repository>] [--keychain-service SERVICE --keychain-account ACCOUNT] [--session-id mcp_sess_IDENTIFIER] [--github-auth-source gh-session --github-user EXISTING_LOGIN]");
    }
    options[destination] = value;
  }
  return options;
}

if (isDirectExecution()) {
  try {
    const launch = buildLaunchConfig(parseLaunchArguments(process.argv.slice(2)));
    const child = spawn(launch.command, launch.args, {
      cwd: dirname(launch.args[0]),
      env: launch.env,
      stdio: "inherit",
    });

    child.once("error", (error) => {
      console.error(`Unable to start Hawk GitHub MCP profile: ${error.message}`);
      process.exitCode = 1;
    });
    child.once("exit", (code, signal) => {
      if (signal) {
        process.kill(process.pid, signal);
        return;
      }
      process.exitCode = code ?? 1;
    });
    for (const signal of ["SIGINT", "SIGTERM"]) {
      process.once(signal, () => child.kill(signal));
    }
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 2;
  }
}
