// The one origin of the browser tests, as deploy/compose.yaml's front proxy makes it (infra/Caddyfile.local-native):
// /api/* goes to the API with /api taken off and X-Forwarded-Prefix: /api (so the refresh cookie gets the right Path),
// everything else goes to the console. Plain http on 127.0.0.1: the API then sets the unprefixed, non-Secure cookie
// names (apps/api/app/core/session_cookies.py), the rest of the cookie and CSRF behaviour is the production one.
//
//   node e2e/harness/proxy.mjs   (E2E_PORT, E2E_API_PORT, E2E_WEB_PORT)

import http from "node:http";

const port = Number(process.env.E2E_PORT || 13100);
const apiPort = Number(process.env.E2E_API_PORT || 18000);
const webPort = Number(process.env.E2E_WEB_PORT || 13000);

function forward(req, res) {
  const url = req.url || "/";
  const toApi = url === "/api" || url.startsWith("/api/") || url.startsWith("/api?");
  const path = toApi ? url.slice(4) || "/" : url;
  const headers = { ...req.headers };
  headers["x-forwarded-host"] = req.headers.host || "";
  headers["x-forwarded-proto"] = "http";
  headers["x-forwarded-for"] = req.socket.remoteAddress || "127.0.0.1";
  if (toApi) headers["x-forwarded-prefix"] = "/api";
  else delete headers["x-forwarded-prefix"];
  const upstream = http.request(
    { host: "127.0.0.1", port: toApi ? apiPort : webPort, method: req.method, path: path.startsWith("/") ? path : `/${path}`, headers },
    (answer) => {
      res.writeHead(answer.statusCode || 502, answer.rawHeaders);
      answer.pipe(res);
    },
  );
  upstream.on("error", (error) => {
    if (!res.headersSent) res.writeHead(502, { "content-type": "text/plain" });
    res.end(`e2e proxy: ${toApi ? "API" : "console"} unreachable (${error.code || error.message})`);
  });
  // A page closed while a stream (server-sent events) is open: stop the upstream request too.
  res.on("close", () => upstream.destroy());
  req.pipe(upstream);
}

const server = http.createServer(forward);
server.keepAliveTimeout = 65_000;
server.listen(port, "127.0.0.1", () => {
  console.log(`e2e proxy on http://127.0.0.1:${port} (/api -> :${apiPort}, rest -> :${webPort})`);
});
for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => server.close(() => process.exit(0)));
