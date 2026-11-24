#!/usr/bin/env node
import fs from "node:fs";
import http from "node:http";
import https from "node:https";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "../..");
const certPath = process.env.NATIVE_GATEWAY_CERT || path.join(repoRoot, "infra/tls/local/hawk-local.crt");
const keyPath = process.env.NATIVE_GATEWAY_KEY || path.join(repoRoot, "infra/tls/local/hawk-local.key");
const listenHost = process.env.NATIVE_GATEWAY_HOST || "127.0.0.1";
const listenPort = Number(process.env.NATIVE_GATEWAY_PORT || "3443");
const apiHost = process.env.NATIVE_API_HOST || "127.0.0.1";
const apiPort = Number(process.env.NATIVE_API_PORT || "8000");
const webHost = process.env.NATIVE_WEB_HOST || "127.0.0.1";
const webPort = Number(process.env.NATIVE_WEB_PORT || "3000");

const apiPathPrefixes = [
  "/ai-systems",
  "/asset-intelligence",
  "/auth",
  "/control-coverage",
  "/dashboard",
  "/deployment-surfaces",
  "/discovery",
  "/ecosystem",
  "/endpoint-agent",
  "/evidence",
  "/extension",
  "/findings",
  "/github",
  "/governance",
  "/maturity-curve",
  "/mcp",
  "/monitoring",
  "/native-control",
  "/policies",
  "/policy-packs",
  "/runtime",
  "/scan",
  "/surface-coverage",
  "/users",
  "/validation",
];

function isApiPath(url) {
  const pathname = new URL(url || "/", "https://hawk.localhost").pathname;
  return apiPathPrefixes.some((prefix) => pathname === prefix || pathname.startsWith(`${prefix}/`));
}

function acceptsHtml(req) {
  const accept = String(req.headers.accept || "").toLowerCase();
  return accept.includes("text/html") && !accept.includes("application/json");
}

export function targetFor(req) {
  const host = String(req.headers.host || "").split(":")[0].toLowerCase();
  if (host === "api.hawk.localhost" || req.url?.startsWith("/api/") || (isApiPath(req.url) && !acceptsHtml(req))) {
    const targetPath = req.url?.startsWith("/api/") ? req.url.slice(4) || "/" : req.url || "/";
    return { host: apiHost, port: apiPort, path: targetPath };
  }
  return { host: webHost, port: webPort, path: req.url || "/" };
}

export function buildUpstreamHeaders(inboundHeaders, target) {
  const inboundHost = inboundHeaders.host || "hawk.localhost:3443";
  return {
    ...inboundHeaders,
    host: inboundHost,
    "x-forwarded-host": inboundHost,
    "x-forwarded-proto": "https",
  };
}

function startGateway() {
const server = https.createServer(
  {
    cert: fs.readFileSync(certPath),
    key: fs.readFileSync(keyPath),
  },
  (clientReq, clientRes) => {
    const target = targetFor(clientReq);
    const headers = buildUpstreamHeaders(clientReq.headers, target);

    const proxyReq = http.request(
      {
        host: target.host,
        port: target.port,
        path: target.path,
        method: clientReq.method,
        headers,
      },
      (proxyRes) => {
        clientRes.writeHead(proxyRes.statusCode || 502, proxyRes.headers);
        proxyRes.pipe(clientRes);
      },
    );

    proxyReq.on("error", (error) => {
      clientRes.writeHead(502, { "content-type": "text/plain; charset=utf-8" });
      clientRes.end(`Native gateway upstream unavailable: ${error.message}\n`);
    });

    clientReq.pipe(proxyReq);
  },
);

server.on("upgrade", (req, socket, head) => {
  const target = targetFor(req);
  const upstream = net.connect(target.port, target.host, () => {
    upstream.write(
      `${req.method} ${target.path} HTTP/${req.httpVersion}\r\n` +
        Object.entries(buildUpstreamHeaders(req.headers, target))
          .map(([key, value]) => `${key}: ${value}`)
          .join("\r\n") +
        "\r\n\r\n",
    );
    if (head?.length) {
      upstream.write(head);
    }
    upstream.pipe(socket);
    socket.pipe(upstream);
  });

  upstream.on("error", () => socket.destroy());
});

server.listen(listenPort, listenHost, () => {
  console.log(`Native HTTPS gateway listening on https://hawk.localhost:${listenPort}`);
  console.log(`API upstream: http://${apiHost}:${apiPort}`);
  console.log(`Web upstream: http://${webHost}:${webPort}`);
});
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  startGateway();
}
