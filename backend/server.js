const express = require("express");
const bodyParser = require("body-parser");
const cors = require("cors");
const fetch = require("node-fetch");
const jwt = require("jsonwebtoken");
const path = require("path");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Serve frontend static
app.use("/", express.static(path.join(__dirname, "..", "frontend")));

// Simple in-memory comment list for XSS demo
let comments = [];
// In-memory users for demos (replaces sqlite3 usage)
let users = [
  { id: 1, name: "alice", email: "alice@example.com" },
  { id: 2, name: "bob", email: "bob@example.com" },
];

// 1. SQL Injection (vulnerable on purpose)
app.get("/api/sqli", (req, res) => {
  const name = req.query.name || "";
  // This endpoint intentionally demonstrates unsafe handling of input.
  // We simulate SQL injection by returning all users when the input
  // contains SQL-like operators (e.g. "OR" or a single quote).
  const lowered = name.toLowerCase();
  if (name.includes("'") || lowered.includes(" or ")) {
    // Simulate injection result
    return res.json(users);
  }
  const rows = users.filter((u) => u.name === name);
  res.json(rows);
});

// 2. XSS demo: post and get comments (no output encoding)
app.post("/api/xss", (req, res) => {
  const c = req.body.comment || "";
  comments.push({ id: comments.length + 1, comment: c });
  res.json({ ok: true });
});
app.get("/api/xss/comments", (req, res) => {
  // returns JSON; frontend intentionally renders without escaping
  res.json(comments);
});

// 3. CSRF demo: naive cookie-based session and change-email with no CSRF token
const sessions = {};
app.post("/api/csrf/login", (req, res) => {
  const user = req.body.user || "alice";
  const sid = "sess-" + Math.random().toString(36).slice(2);
  sessions[sid] = { user, email: user + "@example.com" };
  res.cookie && res.cookie("sid", sid); // if cookie middleware present
  // also return sid for simplicity
  res.json({ sid });
});
app.post("/api/csrf/change-email", (req, res) => {
  const sid = req.headers["x-demo-session"] || req.body.sid;
  const session = sessions[sid];
  if (!session) return res.status(401).send("No session");
  session.email = req.body.email || session.email;
  res.json({ ok: true, email: session.email });
});

// 4. Broken Auth - naive JWT issuance with weak secret
const WEAK_SECRET = "secret";
app.post("/api/auth/login", (req, res) => {
  const username = req.body.username || "alice";
  const token = jwt.sign({ sub: username }, WEAK_SECRET, { expiresIn: "7d" });
  res.json({ token });
});
app.get("/api/auth/me", (req, res) => {
  const auth = req.headers.authorization || "";
  const token = auth.replace("Bearer ", "");
  try {
    const payload = jwt.verify(token, WEAK_SECRET);
    res.json(payload);
  } catch (e) {
    res.status(401).send("Invalid token: " + e.message);
  }
});

// 5. IDOR demo
app.get("/api/idor/user/:id", (req, res) => {
  const id = req.params.id;
  // no authorization check - returns any user (IDOR demo)
  const row = users.find((u) => String(u.id) === String(id));
  if (!row) return res.status(404).send("Not found");
  res.json(row);
});

// 6. IAM / Over-privileged demo (simulated)
app.post("/api/iam/do", (req, res) => {
  // In a real deployed demo this would use a service account with wide permissions.
  // Here we just echo the requested action and warn.
  const resource =
    req.body.resource ||
    req.query.resource ||
    "projects/PROJECT_ID/secrets/mysecret";
  res.json({
    ok: true,
    action: "access",
    resource,
    note: "Simulated over-privileged access. In real environments this could expose resources.",
  });
});

// 7. Vulnerable dependencies: show package.json and a simulated audit
app.get("/api/vuln-deps", (req, res) => {
  const pkg = require("./package.json");
  const deps = pkg.dependencies || {};
  // Simulated audit result (do not include exploit code)
  const simulated = Object.keys(deps).map((d) => ({
    name: d,
    version: deps[d],
    severity: Math.random() > 0.7 ? "HIGH" : "LOW",
    advisory: "Simulated advisory for demo",
  }));
  res.json({ deps, simulated });
});

// 8. Container info
app.get("/api/container-info", (req, res) => {
  let runningAsRoot = false;
  try {
    runningAsRoot = process.getuid && process.getuid() === 0;
  } catch (e) {}
  res.json({
    runningAsRoot,
    platform: process.platform,
    node_version: process.version,
  });
});

// 9. Kubernetes misconfig (simulated)
app.get("/api/k8s-misconfig", (req, res) => {
  const example = {
    pod: {
      name: "vulnerable-pod",
      spec: {
        hostNetwork: true,
        containers: [{ name: "app", securityContext: { privileged: true } }],
      },
    },
    risk: "privileged pods and hostNetwork allow host access and lateral movement",
  };
  res.json(example);
});

// 10. SSRF demo
app.get("/api/ssrf", async (req, res) => {
  const url = req.query.url;
  if (!url) return res.status(400).send("Provide url query param");
  try {
    const r = await fetch(url, { timeout: 5000 });
    const text = await r.text();
    res.send(text.slice(0, 4000));
  } catch (e) {
    res.status(500).send("Fetch error: " + e.message);
  }
});

// Health check for Kubernetes liveness/readiness probes
app.get("/healthz", (req, res) => {
  res.status(200).send("ok");
});

// small helper to return raw text for many API responses in frontend
app.use((req, res, next) => {
  res.setHeader("X-Demo", "vuln-demo");
  next();
});

// Start server
const port = process.env.PORT || 8080;
app.listen(port, () => console.log("Demo backend listening on", port));
