// Stand-in for the dashboard's /api/ingest, so the outbox can be driven
// end-to-end without the Docker stack. Records every POST (auth header + body)
// to a file and answers with a configurable status, which is what lets
// verify_outbox.sh test the dead-letter path (RESPOND=401) as well as the
// happy path (RESPOND=201).
const http = require("http");
const fs = require("fs");

const received = [];
const status = Number(process.env.RESPOND || 201);
const out = process.env.OUT || "received.json";

http
  .createServer((req, res) => {
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      received.push({ auth: req.headers.authorization || null, body });
      fs.writeFileSync(out, JSON.stringify(received, null, 2));
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ accepted: 1, duplicates: 0 }));
    });
  })
  .listen(Number(process.env.PORT || 4599), () => console.log("fake ingest listening"));
