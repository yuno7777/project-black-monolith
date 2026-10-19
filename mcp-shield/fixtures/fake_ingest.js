// Stand-in for the dashboard, so the outbox can be driven end-to-end without
// the Docker stack. It models the two endpoints the module actually talks to:
//
//   POST /api/ingest          — record the envelope (auth header + body) to a
//                                file, and answer with a configurable status.
//                                That is what lets verify_outbox.sh test the
//                                dead-letter path (RESPOND=401) as well as the
//                                happy path (RESPOND=201).
//   GET  /api/sessions/revoked — the cross-layer circuit breaker's snapshot.
//                                The module polls it so a revoked session is
//                                cut off even when the proxy emits no events
//                                of its own.
//
// The two are kept apart deliberately. The revocation poll is a GET with no
// body, and it is not an ingest envelope: recording it would make the
// envelope checks parse an empty string as JSON, and it would count a
// request that was never an event delivery.
const http = require("http");
const fs = require("fs");

const received = [];
const status = Number(process.env.RESPOND || 201);
const out = process.env.OUT || "received.json";

function json(res, code, body) {
  res.writeHead(code, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

http
  .createServer((req, res) => {
    const path = (req.url || "").split("?")[0];

    if (req.method === "GET" && path.endsWith("/api/sessions/revoked")) {
      // The real snapshot carries the revoked session ids. An empty list is
      // the honest answer for a stand-in that has no breaker.
      json(res, 200, {
        tenant_id: "default",
        generated_at_ms: Date.now(),
        revoked_sessions: [],
      });
      return;
    }

    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ auth: req.headers.authorization || null, body });
      fs.writeFileSync(out, JSON.stringify(received, null, 2));
      // The real ingest response also carries the breaker's snapshot, which
      // the module reads to learn about revocations without polling.
      json(res, status, {
        accepted: status < 400 ? 1 : 0,
        duplicates: 0,
        event_ids: [],
        revoked_sessions: [],
      });
    });
  })
  .listen(Number(process.env.PORT || 4599), () => console.log("fake ingest listening"));
