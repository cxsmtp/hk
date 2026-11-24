import test from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import * as launcher from "../bin/hawk-github-pr-endpoint.mjs";

const { buildLaunchConfig } = launcher;

const VALID_PIN = "a".repeat(64);
const CLAUDE_KEYCHAIN_SERVICE = "com.hawk.mcp-proxy.capability";
const CLAUDE_KEYCHAIN_ACCOUNT = "claude-desktop";
const CLAUDE_SESSION_ID = "mcp_sess_Claude-Desktop_01";

test("accepts only the three named acceptance profiles", async () => {
  const configPath = await writeEndpointConfig({
    ipc_trusted_device_thumbprint: VALID_PIN,
  });

  for (const profile of ["cli", "desktop", "claude"]) {
    const launch = buildLaunchConfig({
      profile,
      ...(profile === "claude"
        ? {
          repositoryScope: "github.com/hawk-demo/governed-repo",
          keychainService: CLAUDE_KEYCHAIN_SERVICE,
          keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT,
          sessionId: CLAUDE_SESSION_ID,
          capabilityTokenReader: () => "capability-from-keychain",
        }
        : {}),
      ...paths(configPath),
    });
    assert.match(
      launch.args.join(" "),
      profile === "claude"
        ? new RegExp(CLAUDE_SESSION_ID)
        : new RegExp(`github-pr-${profile}-20260809`),
    );
    assert.ok(launch.args.includes("--client-app"));
  }

  assert.throws(
    () => buildLaunchConfig({ profile: "unbounded", ...paths(configPath) }),
    /profile must be one of: cli, desktop, claude/i,
  );

  assert.throws(
    () => buildLaunchConfig({
      profile: "claude",
      repositoryScope: "github.com/hawk-demo/governed-repo",
      capabilityTokenReader: () => "capability-from-keychain",
      keychainService: CLAUDE_KEYCHAIN_SERVICE,
      keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT,
      ...paths(configPath),
    }),
    /Claude session identifier unavailable/i,
  );

  assert.throws(
    () => buildLaunchConfig({
      profile: "claude",
      repositoryScope: "github.com/hawk-demo/governed-repo",
      sessionId: CLAUDE_SESSION_ID,
      capabilityTokenReader: () => "capability-from-keychain",
      ...paths(configPath),
    }),
    /Claude Keychain reference unavailable/i,
  );

  assert.throws(
    () => buildLaunchConfig({ profile: "claude", ...paths(configPath) }),
    /Claude profile requires a GitHub repository scope/i,
  );
});

test("fails before launch when the installed public-key pin is absent or malformed", async () => {
  for (const endpointConfig of [
    {},
    { ipc_trusted_device_thumbprint: "not-a-sha256-pin" },
    { ipc_trusted_device_thumbprint: "A".repeat(64) },
  ]) {
    const configPath = await writeEndpointConfig(endpointConfig);
    assert.throws(
      () => buildLaunchConfig({ profile: "cli", ...paths(configPath) }),
      /valid lowercase sha256 ipc trusted device thumbprint/i,
    );
  }
});

test("expands the installed user-relative endpoint socket path", async () => {
  const configPath = await writeEndpointConfig({
    ipc_trusted_device_thumbprint: VALID_PIN,
    ipc_socket_path: "~/.config/hawk/agent.sock",
  });

  const launch = buildLaunchConfig({
    profile: "cli",
    endpointConfigPath: configPath,
    githubBinaryPath: "/test/github-mcp-server",
    nodePath: "/test/node",
    proxyPath: "/test/hawk-mcp-proxy.mjs",
    parentEnv: {},
    userHome: "/Users/tester",
  });

  assert.deepEqual(
    launch.args.slice(1, 4),
    ["--endpoint-socket", "/Users/tester/.config/hawk/agent.sock", "--endpoint-device-thumbprint"],
  );
});

test("launches only the bounded pull-request tools without inherited credentials", async () => {
  const configPath = await writeEndpointConfig({
    ipc_trusted_device_thumbprint: VALID_PIN,
  });
  const parentEnv = {
    PATH: "/usr/bin:/bin",
    LANG: "en_US.UTF-8",
    GITHUB_PAT_TOKEN: "secret-pat",
    GITHUB_TOKEN: "secret-token",
    GH_TOKEN: "secret-gh-token",
    HAWK_ACCESS_TOKEN: "secret-hawk-token",
    HAWK_AGENT_TOKEN: "secret-agent-token",
    HAWK_CAPABILITY_TOKEN: "secret-capability",
    HAWK_AGENT_OPERATOR_TOKEN: "secret-operator",
  };

  const launch = buildLaunchConfig({
    profile: "desktop",
    ...paths(configPath),
    parentEnv,
  });

  assert.equal(launch.command, "/test/node");
  assert.deepEqual(launch.args, [
    "/test/hawk-mcp-proxy.mjs",
    "--endpoint-socket", "/test/agent.sock",
    "--endpoint-device-thumbprint", VALID_PIN,
    "--server-id", "github-pull-requests",
    "--session-id", "github-pr-desktop-20260809",
    "--client-app", "Codex",
    "--allowed-tools", "list_pull_requests,pull_request_read,create_branch,create_or_update_file,create_pull_request",
    "--",
    "/test/github-mcp-server",
    "stdio",
    "--tools", "list_pull_requests,pull_request_read,create_branch,create_or_update_file,create_pull_request",
  ]);
  assert.deepEqual(launch.env, {
    PATH: "/usr/bin:/bin",
    LANG: "en_US.UTF-8",
  });
  assert.doesNotMatch(JSON.stringify(launch), /secret-/);
});

test("Claude reads a capability token once and keeps it out of launch arguments", async () => {
  const configPath = await writeEndpointConfig({
    ipc_trusted_device_thumbprint: VALID_PIN,
  });
  let reads = 0;
  const capabilityToken = "capability-from-keychain";
  const launch = buildLaunchConfig({
    profile: "claude",
    repositoryScope: "github.com/hawk-demo/governed-repo",
    keychainService: CLAUDE_KEYCHAIN_SERVICE,
    keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT,
    sessionId: CLAUDE_SESSION_ID,
    capabilityTokenReader: ({ service, account }) => {
      reads += 1;
      assert.equal(service, CLAUDE_KEYCHAIN_SERVICE);
      assert.equal(account, CLAUDE_KEYCHAIN_ACCOUNT);
      return capabilityToken;
    },
    ...paths(configPath),
    parentEnv: { HAWK_CAPABILITY_TOKEN: "inherited-capability" },
  });

  assert.equal(reads, 1);
  assert.equal(launch.env.HAWK_CAPABILITY_TOKEN, capabilityToken);
  assert.equal(launch.args.filter((value) => value === CLAUDE_SESSION_ID).length, 1);
  assert.equal(launch.args[launch.args.indexOf("--session-id") + 1], CLAUDE_SESSION_ID);
  assert.equal(launch.args.includes(capabilityToken), false);
  assert.doesNotMatch(JSON.stringify(launch.args), /inherited-capability/);
});

test("Claude accepts exactly one terminal Keychain newline", async () => {
  const configPath = await writeEndpointConfig({
    ipc_trusted_device_thumbprint: VALID_PIN,
  });

  for (const token of ["capability-lf\n", "capability-crlf\r\n"]) {
    const launch = buildLaunchConfig({
      profile: "claude",
      repositoryScope: "github.com/hawk-demo/governed-repo",
      keychainService: CLAUDE_KEYCHAIN_SERVICE,
      keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT,
      sessionId: CLAUDE_SESSION_ID,
      capabilityTokenReader: () => token,
      ...paths(configPath),
    });
    assert.equal(launch.env.HAWK_CAPABILITY_TOKEN, token.replace(/\r?\n$/, ""));
  }
});

test("Claude rejects unavailable or malformed Keychain capability tokens", async () => {
  const configPath = await writeEndpointConfig({
    ipc_trusted_device_thumbprint: VALID_PIN,
  });
  const values = [
    undefined,
    "",
    "\n",
    "multiple\nlines",
    "multiple\r\nlines",
    "capability\n\n",
    "x".repeat(4097),
  ];

  for (const value of values) {
    assert.throws(
      () => buildLaunchConfig({
        profile: "claude",
        repositoryScope: "github.com/hawk-demo/governed-repo",
        keychainService: CLAUDE_KEYCHAIN_SERVICE,
        keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT,
        sessionId: CLAUDE_SESSION_ID,
        capabilityTokenReader: () => value,
        ...paths(configPath),
      }),
      /Claude capability token unavailable/i,
    );
  }
  assert.throws(
    () => buildLaunchConfig({
      profile: "claude",
      repositoryScope: "github.com/hawk-demo/governed-repo",
      keychainService: CLAUDE_KEYCHAIN_SERVICE,
      keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT,
      sessionId: CLAUDE_SESSION_ID,
      capabilityTokenReader: () => { throw new Error("keychain failure"); },
      ...paths(configPath),
    }),
    /Claude capability token unavailable/i,
  );
});

test("Claude requires bounded single-line Keychain references", async () => {
  const configPath = await writeEndpointConfig({
    ipc_trusted_device_thumbprint: VALID_PIN,
  });
  const invalidReferences = [
    { keychainService: "", keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT },
    { keychainService: "service\nnewline", keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT },
    { keychainService: "x".repeat(129), keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT },
    { keychainService: CLAUDE_KEYCHAIN_SERVICE, keychainAccount: "" },
  ];

  for (const refs of invalidReferences) {
    assert.throws(
      () => buildLaunchConfig({
        profile: "claude",
        repositoryScope: "github.com/hawk-demo/governed-repo",
        ...refs,
        sessionId: CLAUDE_SESSION_ID,
        capabilityTokenReader: () => "capability-from-keychain",
        ...paths(configPath),
      }),
      /Claude Keychain reference unavailable/i,
    );
  }
});

test("Claude requires a bounded persisted session identifier", async () => {
  const configPath = await writeEndpointConfig({
    ipc_trusted_device_thumbprint: VALID_PIN,
  });
  const invalidSessionIds = [
    null,
    "",
    "mcp_sess_",
    "session_Claude-Desktop_01",
    "mcp_sess_contains\nnewline",
    `mcp_sess_${"x".repeat(120)}`,
  ];

  for (const sessionId of invalidSessionIds) {
    assert.throws(
      () => buildLaunchConfig({
        profile: "claude",
        repositoryScope: "github.com/hawk-demo/governed-repo",
        keychainService: CLAUDE_KEYCHAIN_SERVICE,
        keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT,
        sessionId,
        capabilityTokenReader: () => "capability-from-keychain",
        ...paths(configPath),
      }),
      /Claude session identifier unavailable/i,
    );
  }
});

test("direct launcher parsing retains Claude Keychain references", () => {
  assert.equal(typeof launcher.parseLaunchArguments, "function");
  assert.deepEqual(
    launcher.parseLaunchArguments([
      "claude",
      "--repository-scope", "github.com/hawk-demo/governed-repo",
      "--keychain-service", CLAUDE_KEYCHAIN_SERVICE,
      "--keychain-account", CLAUDE_KEYCHAIN_ACCOUNT,
      "--session-id", CLAUDE_SESSION_ID,
    ]),
    {
      profile: "claude",
      repositoryScope: "github.com/hawk-demo/governed-repo",
      keychainService: CLAUDE_KEYCHAIN_SERVICE,
      keychainAccount: CLAUDE_KEYCHAIN_ACCOUNT,
      sessionId: CLAUDE_SESSION_ID,
    },
  );
});

test("repository-scoped launch binds the proxy to one exact GitHub repository", async () => {
  const configPath = await writeEndpointConfig({
    ipc_trusted_device_thumbprint: VALID_PIN,
  });

  const launch = buildLaunchConfig({
    profile: "cli",
    repositoryScope: "github.com/hawk-demo/governed-repo",
    ...paths(configPath),
  });

  assert.deepEqual(
    launch.args.slice(0, 11),
    [
      "/test/hawk-mcp-proxy.mjs",
      "--endpoint-socket", "/test/agent.sock",
      "--endpoint-device-thumbprint", VALID_PIN,
      "--server-id", "github-pull-requests--hawk-demo--governed-repo",
      "--repository-scope", "github.com/hawk-demo/governed-repo",
      "--session-id", "github-pr-cli-20260809",
    ],
  );

  assert.throws(
    () => buildLaunchConfig({
      profile: "cli",
      repositoryScope: "github.com/hawk-demo/../other",
      ...paths(configPath),
    }),
    /GitHub repository scope must be github\.com\/<owner>\/<repository>/i,
  );
});

function paths(endpointConfigPath) {
  return {
    endpointConfigPath,
    endpointSocketPath: "/test/agent.sock",
    githubBinaryPath: "/test/github-mcp-server",
    nodePath: "/test/node",
    proxyPath: "/test/hawk-mcp-proxy.mjs",
    parentEnv: {},
  };
}

async function writeEndpointConfig(payload) {
  const directory = await mkdtemp(join(tmpdir(), "hawk-github-pr-launcher-"));
  const configPath = join(directory, "endpoint-agent.json");
  await writeFile(configPath, JSON.stringify(payload), { mode: 0o600 });
  return configPath;
}
