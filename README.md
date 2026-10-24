# Hugeware v2

Security-hardened rebuild of the Hugeware site.

- **`/`** — static site (GitHub Pages). Strict CSP, zero third-party resources,
  zero inline script, safe DOM APIs only. The passphrase checker is pure local math.
- **`backend/`** — hardened Node API (runs anywhere Node 22+ runs; **not** on Pages).
  Dependency-free: `node:sqlite` + `node:crypto`. Run with `node backend/server.js`.

## Static-site security notes (GitHub Pages reality)

Pages serves files and nothing else, so header-based protections are limited —
the CSP lives in a `<meta>` tag (works, except `frame-ancestors`, which meta ignores).
HSTS, `X-Frame-Options`, and nosniff cannot be set on Pages. Everything that CAN be
done client-side is: no remote origins in the CSP, no inline script/style, no
`innerHTML`, no eval, no storage of anything you type.

## Backend security controls

Parameterized queries everywhere · scrypt password hashing · timing-equalized
login with a single generic error · 256-bit random session tokens in HttpOnly
SameSite=Strict cookies · per-IP login rate limiting · Origin checks on mutations ·
allowlisted file serving · input validation · CSP/nosniff/DENY/no-referrer headers ·
generic error handler (no stack traces).

Lab admin credentials (demo only): `admin` / `correct horse battery staple`.

## Verify the static site locally

`npx serve .` or any static file server, then open index.html.
