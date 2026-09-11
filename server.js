// Generic HTTP relay: forwards whitelisted requests to a fixed target host,
// gated by a shared-secret header. Used so a server whose own IP is blocked
// by the target can still reach it, by routing through this process's
// network instead.
//
// RELAY_KEY and OX_TARGET_HOST are read from the environment (set them in
// the hosting platform's dashboard) - never hardcode secrets in this file,
// since this repo is public.

const http = require("http");
const https = require("https");

const RELAY_KEY = process.env.RELAY_KEY || "";
const OX_TARGET_HOST = process.env.OX_TARGET_HOST || "";
const PORT = process.env.PORT || 3000;

if (!RELAY_KEY || !OX_TARGET_HOST) {
  console.error("RELAY_KEY and OX_TARGET_HOST env vars are required");
}

const server = http.createServer((req, res) => {
  if (!RELAY_KEY || req.headers["x-relay-key"] !== RELAY_KEY) {
    res.writeHead(403, { "Content-Type": "text/plain" });
    res.end("relay: forbidden");
    return;
  }
  if (!OX_TARGET_HOST) {
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("relay: not configured");
    return;
  }

  const chunks = [];
  req.on("data", (chunk) => chunks.push(chunk));
  req.on("end", () => {
    const body = Buffer.concat(chunks);

    // Forward every incoming header as-is, except hop-by-hop / relay-only
    // ones - a hardcoded per-header whitelist here silently drops whatever
    // the caller adds next and is easy to forget to update.
    const dropHeaders = new Set(["host", "connection", "x-relay-key", "content-length"]);
    const forwardHeaders = {};
    for (const [key, value] of Object.entries(req.headers)) {
      if (!dropHeaders.has(key.toLowerCase())) {
        forwardHeaders[key] = value;
      }
    }
    if (!forwardHeaders["accept"]) {
      forwardHeaders["accept"] = "application/json";
    }
    if (!forwardHeaders["user-agent"]) {
      forwardHeaders["user-agent"] = "TradeLink OX Relay";
    }
    if (body.length > 0) {
      forwardHeaders["content-length"] = String(body.length);
    }

    const oxReq = https.request(
      {
        hostname: OX_TARGET_HOST,
        path: req.url,
        method: req.method,
        headers: forwardHeaders,
      },
      (oxRes) => {
        const responseChunks = [];
        oxRes.on("data", (chunk) => responseChunks.push(chunk));
        oxRes.on("end", () => {
          res.writeHead(oxRes.statusCode, {
            "Content-Type": oxRes.headers["content-type"] || "application/json",
          });
          res.end(Buffer.concat(responseChunks));
        });
      }
    );
    oxReq.on("error", (err) => {
      res.writeHead(502, { "Content-Type": "text/plain" });
      res.end(`relay: upstream error: ${err.message}`);
    });
    if (body.length > 0) {
      oxReq.write(body);
    }
    oxReq.end();
  });
});

server.listen(PORT, () => {
  console.log(`Relay listening on port ${PORT}, target ${OX_TARGET_HOST || "(unset)"}`);
});
