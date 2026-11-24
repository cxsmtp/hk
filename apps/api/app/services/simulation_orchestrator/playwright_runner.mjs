#!/usr/bin/env node

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

async function loadPlaywright() {
  const fromPackage = process.env.SIMULATION_PLAYWRIGHT_PACKAGE;
  if (fromPackage) {
    const entry = path.join(fromPackage, "index.mjs");
    return await import(pathToFileURL(entry).href);
  }
  return await import("playwright");
}

function truncate(value, max = 800) {
  const text = String(value ?? "");
  return text.length <= max ? text : `${text.slice(0, max)}...`;
}

async function captureResponseExcerpt(page, payload) {
  const selectors = []
    .concat(Array.isArray(payload.response_selectors) ? payload.response_selectors : [])
    .concat(["main", "article", "body"]);

  for (const selector of selectors) {
    try {
      const locator = page.locator(selector).first();
      if (!(await locator.count())) {
        continue;
      }
      const text = await locator.innerText({ timeout: 1500 });
      if (text && text.trim()) {
        return truncate(text.trim(), 1200);
      }
    } catch {
      // Continue trying other selectors.
    }
  }
  return "";
}

async function injectPrompt(page, payload) {
  const prompt = String(payload.prompt ?? "");
  const selectors = []
    .concat(Array.isArray(payload.prompt_selectors) ? payload.prompt_selectors : [])
    .concat([
      "textarea",
      "[contenteditable='true']",
      "div[contenteditable='true']",
      "input[type='text']",
    ]);
  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    if (!(await locator.count())) {
      continue;
    }
    try {
      await locator.click({ timeout: 1500 });
      await locator.fill(prompt, { timeout: 2000 });
      return { prompt_injected: true, selector_used: selector };
    } catch {
      try {
        await locator.click({ timeout: 1500 });
        await locator.type(prompt, { delay: 2, timeout: 3000 });
        return { prompt_injected: true, selector_used: selector };
      } catch {
        // Try the next selector.
      }
    }
  }
  return { prompt_injected: false, selector_used: null };
}

async function uploadFile(page, payload) {
  const selectors = []
    .concat(Array.isArray(payload.file_input_selectors) ? payload.file_input_selectors : [])
    .concat(["input[type='file']"]);

  const uploadPath = String(payload.file_path ?? "").trim();
  if (!uploadPath || !fs.existsSync(uploadPath)) {
    return { upload_status: "missing_file", file_path: uploadPath };
  }

  for (const selector of selectors) {
    const locator = page.locator(selector).first();
    if (!(await locator.count())) {
      continue;
    }
    try {
      await locator.setInputFiles(uploadPath, { timeout: 3000 });
      return { upload_status: "uploaded", file_path: uploadPath, selector_used: selector };
    } catch {
      // Try the next selector.
    }
  }
  return { upload_status: "input_not_found", file_path: uploadPath };
}

async function run() {
  const inputPath = process.argv[2];
  if (!inputPath || !fs.existsSync(inputPath)) {
    throw new Error("Input JSON path is required");
  }

  const request = JSON.parse(fs.readFileSync(inputPath, "utf8"));
  const kind = String(request.kind ?? "").trim();
  const payload = request.payload ?? {};
  const timeoutMs = Number(request.timeout_ms || 45000);
  const artifactsDir = request.artifacts_dir;
  const extensionDir = String(request.extension_dir ?? "").trim();
  const userDataDir = String(request.user_data_dir ?? "").trim();
  const requestedHeadless = Boolean(request.headless);
  const apiUrl = String(request.api_url ?? "").trim();
  const testUrl = String(request.test_url ?? "").trim();
  if (!artifactsDir) {
    throw new Error("artifacts_dir is required");
  }
  if (!extensionDir || !fs.existsSync(path.join(extensionDir, "manifest.json"))) {
    throw new Error(`Hawk extension dist is required and must contain manifest.json: ${extensionDir || "(missing)"}`);
  }
  if (!userDataDir) {
    throw new Error("user_data_dir is required for extension-backed browser execution");
  }
  if (!apiUrl) {
    throw new Error("api_url is required for extension-backed browser execution");
  }
  if (!testUrl) {
    throw new Error("test_url is required for extension-backed browser execution");
  }
  fs.mkdirSync(artifactsDir, { recursive: true });
  fs.mkdirSync(userDataDir, { recursive: true });

  const { chromium } = await loadPlaywright();
  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: requestedHeadless,
    args: [
      `--disable-extensions-except=${extensionDir}`,
      `--load-extension=${extensionDir}`,
    ],
  });
  const page = await context.newPage();
  page.setDefaultTimeout(Math.max(5000, timeoutMs));

  let extensionLoaded = false;
  try {
    const existingWorker = context.serviceWorkers().find((worker) => worker.url().startsWith("chrome-extension://"));
    const worker = existingWorker || await context.waitForEvent("serviceworker", { timeout: 5000 }).catch(() => null);
    extensionLoaded = Boolean(worker && worker.url().startsWith("chrome-extension://"));
  } catch {
    extensionLoaded = false;
  }

  const network = { requests: 0, responses: 0, failed: 0 };
  page.on("request", () => {
    network.requests += 1;
  });
  page.on("response", () => {
    network.responses += 1;
  });
  page.on("requestfailed", () => {
    network.failed += 1;
  });

  const targetUrl = String(payload.url ?? testUrl);
  await page.goto(targetUrl, { waitUntil: "domcontentloaded", timeout: timeoutMs });
  if (payload.wait_ms) {
    await page.waitForTimeout(Number(payload.wait_ms));
  }

  let stepData = {};
  if (kind === "browser_prompt_inject") {
    stepData = await injectPrompt(page, payload);
  } else if (kind === "browser_upload_file") {
    stepData = await uploadFile(page, payload);
  }

  const screenshotPath = path.join(artifactsDir, "screenshot.png");
  const domPath = path.join(artifactsDir, "dom.html");
  await page.screenshot({ path: screenshotPath, fullPage: true });
  fs.writeFileSync(domPath, await page.content(), "utf8");
  const responseExcerpt = await captureResponseExcerpt(page, payload);

  const output = {
    status: "ok",
    kind,
    title: kind,
    target_url: targetUrl,
    final_url: page.url(),
    response_excerpt: responseExcerpt,
    network_summary: network,
    artifacts: {
      screenshot: screenshotPath,
      dom: domPath,
    },
    extension_loaded: extensionLoaded,
    extension_dir: extensionDir,
    api_url: apiUrl,
    ...stepData,
  };

  await context.close();
  process.stdout.write(`${JSON.stringify(output)}\n`);
}

run().catch((error) => {
  process.stderr.write(`${String(error?.stack || error)}\n`);
  process.exit(1);
});
