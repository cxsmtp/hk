import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const projectRoot = path.resolve(extensionRoot, "..", "..");
const distDir = path.join(extensionRoot, "dist");
const manifestPath = path.join(extensionRoot, "manifest.json");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const version = String(manifest.version || "0.0.0");

function packageNameFor(buildHash) {
  return `hawk-extension-pilot-${version}-${buildHash}`;
}

function walkFiles(root, predicate = () => true) {
  if (!existsSync(root)) return [];
  const entries = readdirSync(root).sort();
  const files = [];
  for (const entry of entries) {
    if (entry === "node_modules" || entry === "dist") continue;
    const fullPath = path.join(root, entry);
    const stat = statSync(fullPath);
    if (stat.isDirectory()) {
      files.push(...walkFiles(fullPath, predicate));
    } else if (predicate(fullPath)) {
      files.push(fullPath);
    }
  }
  return files;
}

function computeBuildHash() {
  const hash = createHash("sha256");
  const files = [
    manifestPath,
    path.join(extensionRoot, "options.html"),
    path.join(extensionRoot, "build.mjs"),
    path.join(extensionRoot, "package.json"),
    ...walkFiles(path.join(extensionRoot, "src"), (filePath) => /\.(ts|tsx|js|mjs|json|css|html)$/.test(filePath)),
    ...walkFiles(path.join(extensionRoot, "rules"), (filePath) => /\.json$/.test(filePath)),
  ];
  for (const filePath of files.sort()) {
    hash.update(path.relative(extensionRoot, filePath));
    hash.update("\0");
    hash.update(readFileSync(filePath));
    hash.update("\0");
  }
  return hash.digest("hex").slice(0, 16);
}

function copyRuntimeFiles(buildHash, packageDir) {
  rmSync(packageDir, { recursive: true, force: true });
  mkdirSync(path.join(packageDir, "dist"), { recursive: true });
  cpSync(manifestPath, path.join(packageDir, "manifest.json"));
  cpSync(path.join(extensionRoot, "options.html"), path.join(packageDir, "options.html"));
  if (existsSync(path.join(extensionRoot, "rules"))) {
    cpSync(path.join(extensionRoot, "rules"), path.join(packageDir, "rules"), {
      recursive: true,
      filter: (src) => !path.basename(src).startsWith("._") && !src.endsWith(".map"),
    });
  }
  for (const fileName of readdirSync(distDir).sort()) {
    if (!fileName.endsWith(".js")) continue;
    cpSync(path.join(distDir, fileName), path.join(packageDir, "dist", fileName));
  }
  writeFileSync(
    path.join(packageDir, "build-info.json"),
    `${JSON.stringify({
      name: manifest.name,
      version,
      build_hash: buildHash,
      packaged_at: new Date().toISOString(),
      source_maps_included: false,
      dev_files_included: false,
    }, null, 2)}\n`,
  );
  const managedApiBaseUrl = String(process.env.HAWK_MANAGED_API_BASE_URL || "").trim();
  const managedTenantId = String(process.env.HAWK_MANAGED_TENANT_ID || "").trim();
  const managedMinimumExtensionVersion = String(process.env.HAWK_MANAGED_MIN_EXTENSION_VERSION || version).trim() || version;
  if (managedApiBaseUrl || managedTenantId) {
    if (!managedApiBaseUrl || !managedTenantId) {
      throw new Error("Set both HAWK_MANAGED_API_BASE_URL and HAWK_MANAGED_TENANT_ID to emit pilot-managed-policy.json");
    }
    const packagedManifestPath = path.join(packageDir, "manifest.json");
    const packagedManifest = JSON.parse(readFileSync(packagedManifestPath, "utf8"));
    const apiUrl = new URL(managedApiBaseUrl);
    const apiPermission = `${apiUrl.protocol}//${apiUrl.host}/*`;
    packagedManifest.host_permissions = Array.from(new Set([
      ...(packagedManifest.host_permissions || []),
      apiPermission,
    ]));
    writeFileSync(packagedManifestPath, `${JSON.stringify(packagedManifest, null, 2)}\n`);
    writeFileSync(
      path.join(packageDir, "pilot-managed-policy.json"),
      `${JSON.stringify({
        api_base_url: managedApiBaseUrl.replace(/\/+$/, ""),
        tenant_id: managedTenantId,
        policy_locked: true,
        enterprise_managed: true,
        minimum_extension_version: managedMinimumExtensionVersion,
        browser: String(process.env.HAWK_MANAGED_BROWSER || "chrome").trim() || "chrome",
        incognito_policy: String(process.env.HAWK_MANAGED_INCOGNITO_POLICY || "disabled").trim() || "disabled",
      }, null, 2)}\n`,
    );
  }
}

function removeMacMetadata(root) {
  if (!existsSync(root)) return;
  for (const entry of readdirSync(root)) {
    const fullPath = path.join(root, entry);
    if (entry.startsWith("._") || entry === ".DS_Store" || entry === "__MACOSX") {
      rmSync(fullPath, { recursive: true, force: true });
      continue;
    }
    if (statSync(fullPath).isDirectory()) {
      removeMacMetadata(fullPath);
    }
  }
}

function run(command, args, options = {}) {
  const result = spawnSync(command, args, {
    cwd: options.cwd || extensionRoot,
    env: options.env || process.env,
    stdio: "inherit",
  });
  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with status ${result.status}`);
  }
}

function createZip(packageDir, zipPath) {
  rmSync(zipPath, { force: true });
  run("zip", ["-qry", zipPath, path.basename(packageDir), "-x", "*/._*", "*/.DS_Store", "__MACOSX/*"], {
    cwd: projectRoot,
  });
}

function validatePackage(packageDir) {
  run("node", ["scripts/validate-pilot-package.mjs", packageDir]);
}

const buildHash = computeBuildHash();
const packageName = packageNameFor(buildHash);
const packageDir = path.join(projectRoot, packageName);
const zipPath = path.join(projectRoot, `${packageName}.zip`);
rmSync(distDir, { recursive: true, force: true });
run("node", ["build.mjs", "--pilot"], {
  env: { ...process.env, HAWK_EXTENSION_BUILD_HASH: buildHash },
});
copyRuntimeFiles(buildHash, packageDir);
removeMacMetadata(packageDir);
validatePackage(packageDir);
createZip(packageDir, zipPath);
removeMacMetadata(packageDir);

console.log(JSON.stringify({
  package_dir: packageDir,
  zip_path: zipPath,
  version,
  build_hash: buildHash,
}, null, 2));
