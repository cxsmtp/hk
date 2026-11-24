import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const targetRoot = path.resolve(process.argv[2] || extensionRoot);
const requiredFiles = [
  "manifest.json",
  "options.html",
  "dist/service-worker.js",
  "dist/content-script.js",
  "dist/options.js",
  "build-info.json",
];

function fail(message) {
  console.error(`pilot package validation failed: ${message}`);
  process.exitCode = 1;
}

function walk(root) {
  if (!existsSync(root)) return [];
  const files = [];
  for (const entry of readdirSync(root).sort()) {
    const fullPath = path.join(root, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      files.push(...walk(fullPath));
    } else {
      files.push(fullPath);
    }
  }
  return files;
}

for (const fileName of requiredFiles) {
  if (!existsSync(path.join(targetRoot, fileName))) {
    fail(`missing required runtime file: ${fileName}`);
  }
}

const files = walk(targetRoot);
const forbiddenPathParts = new Set(["src", "tests", "node_modules", ".git"]);
const forbiddenFileNames = new Set([".env", ".env.local", ".env.production", "id_rsa", "id_ed25519"]);
const forbiddenSuffixes = new Set([".pem", ".key", ".p12", ".pfx", ".crt", ".cer", ".zip"]);
const buildHashPattern = /^[a-fA-F0-9]{12,64}$/;
const tenantIdPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const versionPattern = /^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/;

function isHttpUrl(value) {
  try {
    const parsed = new URL(String(value || ""));
    return ["http:", "https:"].includes(parsed.protocol) && Boolean(parsed.hostname);
  } catch {
    return false;
  }
}

for (const filePath of files) {
  const relative = path.relative(targetRoot, filePath);
  const parts = relative.split(path.sep);
  const basename = path.basename(filePath);
  const lower = basename.toLowerCase();
  if (basename.startsWith("._") || basename === ".DS_Store" || parts.includes("__MACOSX")) {
    fail(`AppleDouble/macOS metadata file included: ${relative}`);
  }
  if (parts.some((part) => forbiddenPathParts.has(part))) {
    fail(`development directory included: ${relative}`);
  }
  if (forbiddenFileNames.has(lower) || forbiddenSuffixes.has(path.extname(lower))) {
    fail(`sensitive deployment artifact included: ${relative}`);
  }
  if (/\.(map|ts|tsx)$/.test(lower)) {
    fail(`source or sourcemap file included: ${relative}`);
  }
  if (lower.endsWith(".js")) {
    const body = readFileSync(filePath, "utf8");
    if (body.includes("sourceMappingURL=")) {
      fail(`sourceMappingURL marker included: ${relative}`);
    }
  }
}

try {
  const manifest = JSON.parse(readFileSync(path.join(targetRoot, "manifest.json"), "utf8"));
  if (!manifest.version) fail("manifest version is missing");
  if (!manifest.name) fail("manifest name is missing");
} catch (error) {
  fail(`manifest is invalid JSON: ${String(error)}`);
}

try {
  const buildInfo = JSON.parse(readFileSync(path.join(targetRoot, "build-info.json"), "utf8"));
  if (!buildHashPattern.test(String(buildInfo.build_hash || ""))) {
    fail("build-info.json is missing a valid production build_hash");
  }
  if (buildInfo.source_maps_included !== false || buildInfo.dev_files_included !== false) {
    fail("build-info.json does not attest source_maps_included=false and dev_files_included=false");
  }
} catch (error) {
  fail(`build-info.json is invalid JSON: ${String(error)}`);
}

for (const policyName of ["pilot-managed-policy.json", "managed-config.json", "policy.json"]) {
  const policyPath = path.join(targetRoot, policyName);
  if (!existsSync(policyPath)) continue;
  try {
    const policy = JSON.parse(readFileSync(policyPath, "utf8"));
    const locked = policy.policy_locked === true || policy.policyLocked === true;
    const managed = policy.enterprise_managed === true || policy.enterpriseManaged === true;
    const apiUrl = policy.api_base_url || policy.backend_url || policy.backendUrl;
    const tenantId = policy.tenant_id || policy.tenantId;
    const minimumExtensionVersion = policy.minimum_extension_version || policy.minimumExtensionVersion;
    const incognitoPolicy = policy.incognito_policy || policy.incognitoPolicy;
    if (!locked || !managed) {
      fail(`${policyName} must set policy_locked=true and enterprise_managed=true`);
    }
    if (!isHttpUrl(apiUrl)) {
      fail(`${policyName} must set a valid managed API URL`);
    }
    if (!tenantIdPattern.test(String(tenantId || ""))) {
      fail(`${policyName} must set a valid tenant ID`);
    }
    if (!versionPattern.test(String(minimumExtensionVersion || ""))) {
      fail(`${policyName} must set minimum_extension_version`);
    }
    if (incognitoPolicy && !["disabled", "enabled_monitored"].includes(String(incognitoPolicy))) {
      fail(`${policyName} incognito_policy must be disabled or enabled_monitored`);
    }
  } catch (error) {
    fail(`${policyName} is invalid JSON: ${String(error)}`);
  }
}

if (!process.exitCode) {
  console.log(`pilot package validation ok: ${targetRoot}`);
}
