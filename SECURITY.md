# Security Policy

## Static site (this repo, GitHub Pages)

Everything runs client-side. The passphrase checker transmits nothing: the CSP
(`default-src 'none'`) blocks any network request the page itself did not initiate
by navigation. There is no account system, no database, no form submission target.

## Reporting

This is a hardening exercise / fictional brand. If you find something anyway:
`security@hugeware.example`.

## Threat model accepted by design

- GitHub Pages serves only what is committed to this repository.
- Domain/DNS compromise is out of scope for app code — protect the GitHub account
  (2FA) and registrar.
- The `backend/` API is reference code for a future non-Pages deployment.
