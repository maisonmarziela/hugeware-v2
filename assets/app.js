// Hugeware v2 client code.
// Security posture: no innerHTML/outerHTML/document.write anywhere, no eval,
// no network calls, no third-party code. All DOM writes go through
// createElement + textContent so untrusted strings can never become markup.
"use strict";

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];

/* ---------- year ---------- */
$("#year").textContent = String(new Date().getFullYear());

/* ---------- field notes (static content, built with safe DOM APIs) ---------- */
const NOTES = [
  { title: "Your email is the front door.", body: "Recovery flows for your other accounts usually run through it. Protect it first." },
  { title: "Unique keys everywhere.", body: "One passphrase per account, kept by a password manager. Reuse turns one leak into many." },
  { title: "Write the plan before you need it.", body: "Who do you call, what do you restore first, and where is that written down?" }
];
const notesList = $("#notes-list");
for (const note of NOTES) {
  const li = document.createElement("li");
  const h = document.createElement("h3");
  h.textContent = note.title;
  const p = document.createElement("p");
  p.textContent = note.body;
  li.append(h, p);
  notesList.append(li);
}

/* ---------- topic tabs: ?topic= preselect, exact-match only ---------- */
const TOPICS = new Set(["personal", "business", "response"]);
const params = new URLSearchParams(location.search);
function setTopic(topic) {
  const active = TOPICS.has(topic) ? topic : "personal";
  $$("[data-topic]").forEach(btn => {
    const on = btn.dataset.topic === active;
    btn.setAttribute("aria-pressed", String(on));
  });
}
$$("[data-topic]").forEach(btn =>
  btn.addEventListener("click", () => setTopic(btn.dataset.topic))
);
setTopic(params.get("topic")); // untrusted value is only compared, never rendered

/* ---------- ?ref= attribution badge: sanitized, capped, textContent only ---------- */
function showRefBadge(raw) {
  const badge = $("#ref-badge");
  const value = $("#ref-value");
  if (typeof raw !== "string") return;
  // strip control chars, cap length; rendered via textContent so it stays text
  const clean = raw.replace(/[\u0000-\u001f\u007f]/g, "").slice(0, 40);
  if (!clean) return;
  value.textContent = clean;
  badge.hidden = false;
}
showRefBadge(params.get("ref"));

/* ---------- passphrase estimator: pure math, zero transmission ---------- */
const COMMON = ["password", "123456", "qwerty", "letmein", "admin", "welcome",
  "iloveyou", "monkey", "dragon", "summer", "winter", "hugeware"];
function estimate(pass) {
  let pool = 0;
  if (/[a-z]/.test(pass)) pool += 26;
  if (/[A-Z]/.test(pass)) pool += 26;
  if (/[0-9]/.test(pass)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(pass)) pool += 33;
  const entropy = pass.length * Math.log2(Math.max(pool, 2));
  const lower = pass.toLowerCase();
  const isCommon = COMMON.some(w => lower === w || lower.includes(w) && pass.length <= w.length + 4);
  let level, label, color;
  if (isCommon || entropy < 28) { level = 0; label = "WEAK"; color = "var(--red)"; }
  else if (entropy < 60) { level = 1; label = "FAIR"; color = "var(--warn)"; }
  else { level = 2; label = "STRONG"; color = "var(--ok)"; }
  const guessesPerSecond = 1e11; // offline attack, ballpark
  const seconds = Math.pow(2, isCommon ? 10 : entropy) / guessesPerSecond;
  return { entropy: Math.round(entropy), label, color, level, seconds };
}
function humanTime(seconds) {
  if (seconds < 1) return "under a second";
  const units = [["second", 60], ["minute", 60], ["hour", 24], ["day", 365], ["year", 1e9]];
  let value = seconds, name = "second";
  for (const [unit, step] of units) { name = unit; if (value < step) break; value /= step; }
  if (name === "year" && value > 1e6) return "longer than the universe has existed";
  const rounded = value >= 10 ? Math.round(value) : Math.round(value * 10) / 10;
  return `about ${rounded} ${name}${rounded === 1 ? "" : "s"}`;
}
$("#check-form").addEventListener("submit", event => {
  event.preventDefault(); // form-action 'self' + no action attr: never navigates anywhere
  const pass = $("#pass-input").value;
  const box = $("#check-result");
  const result = estimate(pass);
  const label = $("#result-label");
  label.textContent = `STRENGTH: ${result.label} · ~${result.entropy} bits of entropy`;
  label.style.color = result.color;
  $("#result-detail").textContent =
    `A fast offline attacker would need ${humanTime(result.seconds)} to guess it.`;
  $("#result-note").textContent =
    "Estimate only. Long passphrases beat clever passwords. Nothing you typed left this page.";
  box.hidden = false;
});
