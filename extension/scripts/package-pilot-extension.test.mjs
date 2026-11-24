import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const extensionRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function runPackager() {
  const output = execFileSync("node", ["scripts/package-pilot-extension.mjs"], {
    cwd: extensionRoot,
    encoding: "utf8",
    env: {
      ...process.env,
      HAWK_MANAGED_API_BASE_URL: "http://192.168.102.35:8000",
      HAWK_MANAGED_TENANT_ID: "5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb",
      HAWK_MANAGED_BROWSER: "chrome",
    },
  });
  const jsonStart = output.indexOf("{");
  if (jsonStart < 0) {
    throw new Error(`packager did not print JSON output: ${output}`);
  }
  return JSON.parse(output.slice(jsonStart));
}

function listZip(zipPath) {
  return execFileSync("zipinfo", ["-1", zipPath], {
    cwd: extensionRoot,
    encoding: "utf8",
  }).split(/\r?\n/).filter(Boolean);
}

describe("pilot extension packager", () => {
  it("creates a uniquely named clean pilot zip without source maps or dev files", () => {
    const result = runPackager();
    const zipName = path.basename(result.zip_path);
    const packageName = path.basename(result.package_dir);

    expect(zipName).toBe(`hawk-extension-pilot-${result.version}-${result.build_hash}.zip`);
    expect(packageName).toBe(`hawk-extension-pilot-${result.version}-${result.build_hash}`);
    expect(existsSync(result.zip_path)).toBe(true);
    expect(existsSync(path.join(result.package_dir, "manifest.json"))).toBe(true);
    expect(existsSync(path.join(result.package_dir, "pilot-managed-policy.json"))).toBe(true);

    const buildInfo = JSON.parse(readFileSync(path.join(result.package_dir, "build-info.json"), "utf8"));
    expect(buildInfo.build_hash).toBe(result.build_hash);
    expect(buildInfo.source_maps_included).toBe(false);
    expect(buildInfo.dev_files_included).toBe(false);
    const managedPolicy = JSON.parse(readFileSync(path.join(result.package_dir, "pilot-managed-policy.json"), "utf8"));
    expect(managedPolicy.api_base_url).toBe("http://192.168.102.35:8000");
    expect(managedPolicy.tenant_id).toBe("5e7edf8e-0ff7-4bcb-97bb-85a547e1b9bb");
    expect(managedPolicy.policy_locked).toBe(true);
    expect(managedPolicy.enterprise_managed).toBe(true);
    expect(managedPolicy.incognito_policy).toBe("disabled");
    expect(managedPolicy.minimum_extension_version).toBe(result.version);
    const packagedManifest = JSON.parse(readFileSync(path.join(result.package_dir, "manifest.json"), "utf8"));
    expect(packagedManifest.host_permissions).toContain("http://192.168.102.35:8000/*");
    expect(packagedManifest.content_scripts[0].matches).not.toContain("https://*/*");
    expect(packagedManifest.content_scripts[0].matches).not.toContain("http://*/*");

    const entries = listZip(result.zip_path);
    expect(entries).toContain(`${packageName}/manifest.json`);
    expect(entries).toContain(`${packageName}/pilot-managed-policy.json`);
    expect(entries).toContain(`${packageName}/dist/content-script.js`);
    expect(entries).toContain(`${packageName}/dist/service-worker.js`);
    expect(entries.some((entry) => entry.endsWith(".map"))).toBe(false);
    expect(entries.some((entry) => entry.includes("/src/"))).toBe(false);
    expect(entries.some((entry) => entry.includes("/tests/") || entry.includes(".test."))).toBe(false);
    expect(entries.some((entry) => path.basename(entry).startsWith("._") || entry.includes("__MACOSX"))).toBe(false);
  });

  it("rejects managed policy files without a pinned API, tenant, and version floor", () => {
    const tmpRoot = mkdtempSync(path.join(os.tmpdir(), "hawk-extension-validator-"));
    try {
      mkdirSync(path.join(tmpRoot, "dist"), { recursive: true });
      writeFileSync(path.join(tmpRoot, "manifest.json"), JSON.stringify({ name: "Hawk", version: "0.1.8" }));
      writeFileSync(path.join(tmpRoot, "options.html"), "");
      writeFileSync(path.join(tmpRoot, "dist", "service-worker.js"), "console.log('ok');");
      writeFileSync(path.join(tmpRoot, "dist", "content-script.js"), "console.log('ok');");
      writeFileSync(path.join(tmpRoot, "dist", "options.js"), "console.log('ok');");
      writeFileSync(
        path.join(tmpRoot, "build-info.json"),
        JSON.stringify({
          build_hash: "abcdef1234567890",
          source_maps_included: false,
          dev_files_included: false,
        }),
      );
      writeFileSync(
        path.join(tmpRoot, "pilot-managed-policy.json"),
        JSON.stringify({
          policy_locked: true,
          enterprise_managed: true,
        }),
      );

      let failed = false;
      try {
        execFileSync("node", ["scripts/validate-pilot-package.mjs", tmpRoot], {
          cwd: extensionRoot,
          encoding: "utf8",
          stdio: "pipe",
        });
      } catch (error) {
        failed = true;
        const stderr = String(error.stderr || "");
        expect(stderr).toContain("managed API URL");
        expect(stderr).toContain("tenant ID");
        expect(stderr).toContain("minimum_extension_version");
      }
      expect(failed).toBe(true);
    } finally {
      rmSync(tmpRoot, { recursive: true, force: true });
    }
  });
});
