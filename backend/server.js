// Hugeware Dev Portal API — hardened rewrite of the vulnlab.
// Dependency-free (node:sqlite + node:crypto only). Deployable to any Node 22+ host.
//
// Threat-model fixes over the lab version:
//  1. SQLi    -> every query parameterized; no string concatenation anywhere.
//  2. Tokens  -> 256-bit crypto.randomBytes, looked up in a server-side map.
//  3. Cookies -> HttpOnly; SameSite=Strict; Path=/; Max-Age set.
//  4. Enumer. -> single generic "Invalid credentials." for every failure;
//                a dummy scrypt compare runs for unknown users so timing matches.
//  5. IDOR    -> notes queries always scoped by session user_id.
//  6. XSS     -> all output escaped via esc(); Content-Type nosniff; CSP default-src 'none'.
//  7. Traversal -> /files serves from a fixed allowlist; no filesystem paths from input.
//  8. Debug   -> none. Also: rate limiting on login, Origin check on mutations (CSRF),
//                strict input validation, generic error handler, security headers.
"use strict";
const http = require("http");
const { DatabaseSync } = require("node:sqlite");
const crypto = require("crypto");

const db = new DatabaseSync(":memory:");
db.exec(`CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, salt TEXT, hash TEXT, role TEXT);
CREATE TABLE notes(id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, body TEXT);
INSERT INTO notes VALUES (1, 1, 'Flag', 'FLAG{only_reachable_by_its_owner}');`);
const DUMMY_SALT = crypto.randomBytes(16).toString("hex");

function hashPassword(password, saltHex) {
  return crypto.scryptSync(password, Buffer.from(saltHex, "hex"), 32, { N: 16384, r: 8, p: 1 }).toString("hex");
}
function register(username, password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = hashPassword(password, salt);
  db.prepare("INSERT INTO users(username,salt,hash,role) VALUES(?,?,?,'user')").run(username, salt, hash);
}

// Seeded demo account: admin / correct horse battery staple
register("admin", "correct horse battery staple");

const SESSIONS = new Map(); // 256-bit token -> { userId, expires }
const SESSION_TTL_MS = 30 * 60 * 1000;
const LOGIN_ATTEMPTS = new Map(); // ip -> { count, windowStart }
const LOGIN_LIMIT = 5;
const LOGIN_WINDOW_MS = 60 * 1000;

const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const esc = s => String(s).replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const body = (title, inner, session) => `<!doctype html><html><head><title>${title}</title></head>
<body><h1>${title}</h1>${session ? `<p>user ${session.userId} · <a href="/logout">logout</a></p>` : ""}${inner}
<p style="font-family:monospace"><a href="/">home</a></p></body></html>`;

function securityHeaders(res) {
  res.setHeader("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
  res.setHeader("Cache-Control", "no-store");
}

function parseCookies(req) {
  return Object.fromEntries((req.headers.cookie || "").split(";").filter(Boolean).map(c => {
    const i = c.indexOf("=");
    return [c.slice(0, i).trim(), c.slice(i + 1).trim()];
  }));
}
function readBody(req, limit = 8192) {
  return new Promise((resolve, reject) => {
    let data = "", bytes = 0;
    req.on("data", chunk => {
      bytes += chunk.length;
      if (bytes > limit) { reject(new Error("too large")); req.destroy(); return; }
      data += chunk;
    });
    req.on("end", () => resolve(data));
    req.on("error", reject);
  });
}
function originAllowed(req) {
  // SameSite=Strict blocks most CSRF; Origin check closes cross-site non-GET entirely.
  const origin = req.headers.origin;
  if (!origin) return true; // non-browser client (curl/tests)
  const host = req.headers.host;
  try { return new URL(origin).host === host; } catch { return false; }
}
function loginLimited(ip) {
  const now = Date.now();
  const rec = LOGIN_ATTEMPTS.get(ip);
  if (!rec || now - rec.windowStart > LOGIN_WINDOW_MS) { LOGIN_ATTEMPTS.set(ip, { count: 1, windowStart: now }); return false; }
  rec.count++;
  return rec.count > LOGIN_LIMIT;
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, "http://x");
  const p = url.pathname;
  const cookies = parseCookies(req);
  const token = cookies.session;
  const session = token && SESSIONS.get(token);
  if (session && session.expires < Date.now()) SESSIONS.delete(token);
  securityHeaders(res);

  try {
    if (p === "/") {
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.end(body("Dev Portal", "<p>Notes API. <a href=/login>login</a></p>", session));
    }

    if (p === "/register" && req.method === "POST") {
      if (!originAllowed(req)) { res.writeHead(403); return res.end("forbidden"); }
      const { username = "", password = "" } = Object.fromEntries(new URLSearchParams(await readBody(req)));
      if (!USERNAME_RE.test(username) || typeof password !== "string" || password.length < 10 || password.length > 200) {
        res.writeHead(400); return res.end("invalid input");
      }
      try { register(username, password); }
      catch { res.writeHead(409); return res.end("username taken"); }
      res.writeHead(302, { Location: "/login" }); return res.end();
    }

    if (p === "/login" && req.method === "POST") {
      const ip = req.socket.remoteAddress || "?";
      if (loginLimited(ip)) { res.setHeader("Retry-After", "60"); res.writeHead(429); return res.end("too many attempts"); }
      if (!originAllowed(req)) { res.writeHead(403); return res.end("forbidden"); }
      const { username = "", password = "" } = Object.fromEntries(new URLSearchParams(await readBody(req)));
      if (typeof username !== "string" || typeof password !== "string") { res.writeHead(400); return res.end("invalid input"); }
      const row = db.prepare("SELECT * FROM users WHERE username=?").get(username);
      // Constant-ish work either way: unknown users still pay a scrypt compare.
      const hash = row ? row.hash : hashPassword("decoy-value-9f3a", DUMMY_SALT);
      const given = hashPassword(password, row ? row.salt : DUMMY_SALT);
      const ok = crypto.timingSafeEqual(Buffer.from(hash, "hex"), Buffer.from(given, "hex"));
      if (!row || !ok) { res.writeHead(401, { "Content-Type": "text/plain; charset=utf-8" }); return res.end("Invalid credentials."); }
      const t = crypto.randomBytes(32).toString("base64url");
      SESSIONS.set(t, { userId: row.id, expires: Date.now() + SESSION_TTL_MS });
      res.writeHead(302, {
        "Set-Cookie": `session=${t}; Path=/; HttpOnly; SameSite=Strict; Max-Age=1800`,
        Location: "/notes"
      });
      return res.end();
    }

    if (p === "/logout") {
      if (token) SESSIONS.delete(token);
      res.writeHead(302, { "Set-Cookie": "session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0", Location: "/" });
      return res.end();
    }

    if (p === "/notes") {
      if (!session) { res.writeHead(302, { Location: "/login" }); return res.end(); }
      const idParam = url.searchParams.get("id");
      let note;
      if (idParam !== null) {
        // IDOR fix: scope every read by the session owner. Id must be an integer.
        if (!/^\d+$/.test(idParam)) { res.writeHead(400); return res.end("invalid id"); }
        note = db.prepare("SELECT id,title,body FROM notes WHERE id=? AND user_id=?").get(idParam, session.userId);
        res.setHeader("Content-Type", "text/html; charset=utf-8");
        return res.end(body("Note", note
          ? `<p><b>${esc(note.title)}</b></p><p>${esc(note.body)}</p>`
          : "<p>not found</p>", session));
      }
      const notes = db.prepare("SELECT id,title FROM notes WHERE user_id=?").all(session.userId);
      res.setHeader("Content-Type", "text/html; charset=utf-8");
      return res.end(body("My notes", `<ul>${notes.map(n =>
        `<li><a href="/notes?id=${n.id}">${esc(n.title)}</a></li>`).join("")}</ul>`, session));
    }

    if (p === "/files") {
      // Traversal fix: allowlist only. Input never touches the filesystem.
      const DOCS = new Map([
        ["README", "Dev Portal docs.\nThis server only serves the files listed in its allowlist."],
        ["CHANGELOG", "v2: parameterized queries, scrypt, rate limiting, origin checks, allowlisted docs."]
      ]);
      const doc = url.searchParams.get("doc");
      const content = DOCS.get(doc);
      if (content === undefined) { res.writeHead(404); return res.end("not found"); }
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      return res.end(content);
    }

    res.writeHead(404, { "Content-Type": "text/plain; charset=utf-8" });
    res.end("not found");
  } catch {
    // No stack traces, no reflected input, no debugging hints.
    if (!res.headersSent) res.writeHead(500);
    res.end("error");
  }
});
server.listen(3131, () => console.log("hardened portal on :3131"));
