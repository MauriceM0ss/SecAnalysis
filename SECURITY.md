# Security

SecAnalysis is a **self-hosted, single-operator** security toolkit. By design it
sends traffic to hosts and clones repositories that *you* specify — that is the
whole point of the tool. The security model below assumes a trusted operator on
a trusted network.

## Intended deployment

- Run it on a machine you control, reachable only by you — the default
  `docker-compose.yml` publishes it on `http://localhost:8090`.
- **There is no built-in authentication.** Do not expose the port to an
  untrusted network. If you need remote access, put it behind a reverse proxy
  that enforces authentication (and TLS).
- Only scan / probe / audit hosts and repositories you own or are explicitly
  authorised to test. This is repeated in the app footer for a reason.

## What the app deliberately does (not vulnerabilities)

- **Outbound requests to targets you enter** (Network Scan, URL Analyzer,
  Exposure Probe, Subdomains' liveness check). This is SSRF *by function*.
  The liveness and subdomain endpoints additionally require a valid DNS
  hostname (`is_valid_domain`), which rejects raw IP literals (e.g. cloud
  metadata `169.254.169.254`) and bare single-label hosts like `localhost`.
- **Cloning / reading repositories** for Repo Audit (remote `github.com` /
  `gitlab.com` URLs, or local clones under the read-only `AUDIT_ROOT` mount).

## Guards in place

- **Cross-origin (CSRF) block** — state-changing requests (`POST/PUT/PATCH/
  DELETE`) whose `Origin` header doesn't match the host are rejected `403`, so a
  malicious page can't drive the tool from your browser. JSON-only bodies mean
  form-based CSRF also fails.
- **Request size cap** — `MAX_CONTENT_LENGTH = 16 MB`; saved reports are capped
  at 8 MB. Prevents memory-exhaustion via oversized bodies.
- **Path-traversal guard** — saved-report file access resolves strictly under
  `HISTORY_DIR/<tool>/` (`_resolve_history_file`); the stored filename is
  generated server-side, never taken from the client.
- **Locked-down CSP on served reports** — opened history reports are returned
  with `default-src 'none'; style-src 'unsafe-inline'; img-src data:` so a
  stored report can never execute scripts or make network requests.
- **Baseline headers** on every response — `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`.
- **Local-clone path guard** — Repo Audit resolves local clone names strictly
  under `AUDIT_ROOT`, which is mounted read-only.

## Data at rest

The `/data` volume holds the SQLite store (`secanalysis.db`) and saved reports
(`history/<tool>/*.html`). These contain scan results and target names — treat
the volume as sensitive and back it up / dispose of it accordingly. It is
git-ignored.

## Running the tests

```sh
docker cp test_app.py netscan:/app/ \
  && docker exec netscan pip install -q pytest \
  && docker exec netscan python -m pytest test_app.py -q
```

The suite is hermetic — it points `DB_PATH` / `HISTORY_DIR` at a temp directory
before importing the app and exercises no network.

## Reporting an issue

This is a personal project; open an issue on the repository with details and a
reproduction.
