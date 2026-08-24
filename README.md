# SecAnalysis 👽

> ⚠️ **Disclaimer:** This is a Claude Code "vibe coding" project. It was built
> iteratively with the [Claude Code](https://claude.com/claude-code) AI agent
> and is intended for personal/experimental use. Review the code before relying
> on it.

A self-hosted security toolbox: point it at a host, a URL, a subnet, a domain,
or a git repo and it tells you what's exposed. Dark, blue-tinted, single page,
runs in Docker. No accounts, no build step, no cloud.

> ⚠️ **Only scan hosts you own or are explicitly authorised to test.**
> Port scanning other people's machines may be illegal where you live.

## Run it

```bash
docker compose up --build
```

Then open <http://localhost:8090>.

## What's in it

Seven tools in the left-hand menu — plus Saved Reports below them, and a few
things in the top bar.

| Tool | What it does |
|------|--------------|
| **Network Scan** | `nmap` against one host: open ports, service/version, OS guess, DNS name ⇄ IP |
| **Subnet Scan** | Sweeps a CIDR range for live hosts (IP, hostname, MAC, vendor) |
| **URL Analyzer** | Security headers, TLS, DNS, WHOIS, mail auth, mixed content, cookies → a graded scorecard |
| **Exposure Probe** | Sensitive files and misconfigurations left open on a staging host |
| **Repo Audit** | Secrets, dependency CVEs, IaC misconfig, licences, SBOM, Dockerfiles, GitHub Actions |
| **Subdomain Finder** | Passive subdomain discovery from CT logs, with liveness checks |
| **Availability Dashboard** | Persistent uptime monitors (HTTP/TCP/ICMP/API) checked in the background |

### Network Scan
- **DNS resolution** — forward and reverse lookup, so you see the name ⇄ IP mapping.
- **Port scan** — Fast (~100 ports), Standard (top 1000), or Full (all 65,535).
- **Service & version detection** (`-sV`), **OS detection** (`-O`), **default
  scripts** (`-sC`), and **skip host discovery** (`-Pn`) for hosts that don't ping.
- **Detect my router** — fills in the address of the router you're behind, so you
  can scan it without knowing it. See [Finding your router](#finding-your-router).

### Subnet Scan
- **Host discovery** (`nmap -sn`) across a CIDR range — ARP on the local segment,
  ICMP/TCP elsewhere. Capped at 1024 addresses (≈ a /22) so a fat prefix can't
  turn into a 65k-host sweep.
- **MAC + vendor** for hosts on the local segment, which is usually enough to
  recognise a device.
- **Save the scan** (see [Saved scans](#saved-scans)) to re-sweep later and diff.

### URL Analyzer
- **Security headers** — CSP, HSTS, X-Frame-Options, and more. CSP and HSTS are
  *graded*, not just presence-checked: an `unsafe-inline` script policy or a
  wildcard source is reported as weak, and HSTS is checked for browser
  preload-list eligibility.
- **TLS** — certificate subject/issuer/validity/SANs/fingerprint, self-signed
  detection, full chain verification, which protocol versions the server still
  accepts (TLS 1.0–1.3), and weak-cipher detection.
- **DNS records** — A, AAAA, PTR, NS, MX, TXT, CAA.
- **WHOIS registration** (optional) — registrar, registrant (where not redacted),
  creation/update/expiry dates, domain age, EPP status codes and name servers,
  plus the raw record. The lookup walks up from the hostname to the registrable
  domain, so `www.example.co.uk` is answered by `example.co.uk` without a Public
  Suffix List. A domain registered within the last month, or one about to
  expire, is flagged — both are common on throwaway phishing hosts.
- **Mail authentication** (optional) — DMARC (honouring organizational-domain
  inheritance), SPF (with the RFC 7208 10-lookup limit), DKIM, MTA-STS, TLS-RPT,
  and a DNSSEC signing indicator.
- **Mixed content & third parties** — parses the page HTML for sub-resources
  loaded over `http://` on an HTTPS page, split into active (blocked by
  browsers) and passive, plus an inventory of third-party hosts. No requests are
  made to those hosts.
- **Redirect chain** — followed up to 10 hops and checked for downgrades and loops.
- **Cookies** (Secure/HttpOnly/SameSite), **security.txt**, **robots.txt**.
- **Scorecard** — the findings roll into per-category verdicts and a weighted
  0–100 score. Categories that don't apply are excluded rather than penalised.
- Optional **port scan** of ports 1–1024, and **HTTP Basic auth** credentials.
- **Save the scan** (see [Saved scans](#saved-scans)) to reopen it later, re-run
  it with the same options, and see which checks changed grade.
- **Collapsible input panel** — the chevron folds the form to a one-line bar so a
  long report gets the whole pane, exactly as Network Scan's does.

### Exposure Probe
- **Sensitive paths** — `.git/HEAD`, `.git/config`, `.env`, `.svn/entries`,
  Apache `server-status`, Spring `actuator/env`, `swagger.json`, `.DS_Store`.
- **Signature-gated** — a path only counts as exposed if the response body
  matches a known signature, so a soft-404 site doesn't flag every check.
- **Misconfigurations** — clickjacking (missing X-Frame-Options / CSP
  frame-ancestors), CORS arbitrary-origin reflection, weak cookie flags, and
  framework debug mode (Flask/Django stack traces).
- **HTTP Basic auth** — optional credentials for staging behind a Basic-auth prompt.

### Repo Audit
- **Secrets** (`gitleaks`) — committed credentials/keys, redacted to a short
  preview in the results.
- **Vulnerable dependencies** (`trivy fs`) — known CVEs with installed/fixed
  versions, severity, CVSS score/vector, CWEs, and references.
- **IaC misconfiguration** (`trivy`) — Terraform, Kubernetes, Dockerfiles.
- **License risks** (`trivy`) — risky/copyleft licences, for ecosystems that
  expose licence metadata.
- **SBOM** (`trivy`) — a downloadable CycloneDX bill of materials.
- **Dockerfile lint** (`hadolint`) and **GitHub Actions audit** (`zizmor`,
  offline) — `pull_request_target` abuse, unpinned actions, token over-scoping.
- **Repo posture** — supply-chain and hygiene checks read from the clone: which
  ecosystems Dependabot *doesn't* cover, missing lockfiles, credential files that
  shouldn't be tracked, absent `SECURITY.md` / `CODEOWNERS` / `LICENSE`. Needs no
  token and no privileged access; the checks that would need org admin (branch
  protection, secret scanning, alert counts) are **listed as unassessed** rather
  than silently skipped.
- **Remote or local** — audit a `github.com`/`gitlab.com` URL (shallow clone), or
  a repo you've cloned yourself. Private GitHub repos work by URL once you set a
  token. See [Auditing private repos](#auditing-private-repos).

### Subdomain Finder
- **Passive discovery** across [crt.sh](https://crt.sh), CertSpotter, and
  HackerTarget — keyless CT-log / passive-DNS sources, queried concurrently and
  merged, so one being down doesn't sink the lookup.
- **Resolution** — every name found is resolved, so hosts that are actually live
  are separated from names that only ever appeared in a certificate.
- **Liveness probe** — per-name DNS + ICMP + HTTP + HTTPS check on demand.
- Capped at 500 names. Save it to track what appears and disappears over time.

### Availability Dashboard
- **Monitor types** — HTTP(S), TCP port, ICMP ping, or API (HTTP plus an
  `Authorization` header).
- **Expectations** — an expected status code and/or a keyword that must appear
  in the body.
- **Background scheduler** — checks run on each monitor's own interval
  (30s–24h) whether or not the page is open; status transitions are recorded as
  events, and per-monitor history is kept.
- **Export / import** monitors as JSON (Settings → Data).
- Persisted to SQLite on the `./data` volume, so it survives restarts.

## Top bar

- **Public IP** 🌐 — shows the address this app leaves the network from, i.e.
  the WAN address of the router it sits behind, with reverse DNS and the owning
  network where available. Nothing inside a LAN knows its own public address
  (the router rewrites it on the way out), so this is resolved via an external
  echo service — the one outbound call the app makes on its own behalf.
- **Console** — a fixed menu of read-only network tools: `ping`, `traceroute`,
  `dig`, `whois`. Deliberately **not** a shell: you pick a tool and supply one
  target, and every flag is pinned server-side.
- **Reset** — clears all results and returns to the default view.
- **Settings** — theme picker (Dark Terminal / Deep Blue / Light / GitHub /
  Amber), an availability-notification switch, monitor export/import.

## Saved reports & saved scans

Two different things, and the difference matters:

- **Report history** (menu → Saved Reports) — freezes a result as a
  self-contained HTML file on the data volume. Good for "this is what it looked
  like on the day". Served back with a locked-down CSP so a stored report can
  never run scripts. Available for every tool. Each entry also stores the run's
  **raw findings** beside the HTML as `<report>.json`, readable at
  `GET /api/history/<tool>/<report>.html/data` (add `?download=1` to save it).
  The HTML is what you read; the JSON is what a later audit can be diffed
  against — findings not recorded on the day can't be reconstructed afterwards.
  Reports saved before this existed have no JSON and report `hasData: false`.
- **Saved scans** (Subnet Scan, Subdomain Finder and URL Analyzer) — stores the
  tool's own result data, so reopening it re-renders through the normal UI with
  every button still working. **Refresh** re-runs the tool against the same
  target and marks what's **new** or **gone** since last time, and you can attach
  a **note** to any row. Notes are keyed to the scan, so they survive a host
  dropping out of a refresh and coming back.

  The URL Analyzer's rows are its **scorecard checks**, since one analysis is a
  report rather than a list of hosts. So a note lands on a check ("we accept the
  missing CSP because …"), and because that list of checks never changes, a
  refresh reports what a new/gone diff can't: which checks **changed grade**, and
  what the score was before. A saved URL scan also remembers which optional
  checks it was run with (port scan / DNS & email / WHOIS) and replays them on
  refresh. It does **not** store Basic-auth credentials — a refresh of a
  password-protected URL re-runs anonymously.

## Auditing private repos

Two ways, depending on whether you'd rather give the app a token or not.

### By URL, with a token (GitHub only)

Set `GITHUB_TOKEN` and private `github.com` repos audit by URL like public ones —
no manual clone step. Put it in a `.env` file next to `docker-compose.yml`
(`.env` is gitignored):

```bash
echo 'GITHUB_TOKEN=github_pat_...' > .env
docker compose up --build
```

Use a **fine-grained PAT** with **Contents: Read-only**, scoped to just the repos
you audit, with an expiry set. It's the least privilege that lets git clone.

How the token is handled:

- **Public repos never use it.** Clones are tried anonymously first, and the
  token is only attempted if that fails in a way a credential could fix. This
  isn't just hygiene — GitHub rejects any request carrying a bad credential, so
  an expired token attached to every clone would break public audits too.
- **It's scoped to `https://github.com/`**, so a redirect can't carry it to
  another host. GitLab never sees it.
- **It never reaches the command line or the clone URL.** It's passed through
  git's env-var config, because argv is world-readable via `ps`, and a
  URL-embedded credential gets echoed back in git's error output and written
  into the clone's `.git/config` — where gitleaks would then report it as a leak.
- **It's stripped from error messages** before they reach the UI, so it can't
  ride along into a saved report.
- Unset it and everything behaves exactly as it did before: public repos by URL,
  private ones via a local clone.

### By local clone (any host, no token)

To audit a private repo — or anything on GitLab, or a working tree with
uncommitted changes — clone it yourself and point **Repo Audit → Local clone** at
it. The host folder set by `AUDIT_DIR` (default `./audit`) is mounted
**read-only** at `/audit`; any repo you drop in there appears in the dropdown:

```bash
git clone git@github.com:my-org/private-app.git ./audit/private-app
AUDIT_DIR=./audit docker compose up --build      # ./audit is the default
```

Your credentials never enter the app — git does the clone, not SecAnalysis. This
also scans full history, where a URL audit is a shallow clone of the tip commit.

## Scanning the host machine or its LAN

With the default bridge network, the container reaches other machines on your
LAN through the host's routing, which is fine for most scans. To scan the
**host itself**, or to get the most accurate results, switch to host networking:
in `docker-compose.yml`, comment out the `ports:` block and uncomment
`network_mode: host`, then browse to <http://localhost:8080>.

Note that on the default bridge network the container's own default gateway is
the Docker bridge (`172.x.0.1`), not your router — so "the gateway" as seen from
inside the container is the Docker host.

## Finding your router

**Network Scan → Detect my router** fills in the address of the router this app
sits behind. Because of the gateway quirk just above, it can't simply read its
own default route: on the default bridge network that returns the Docker bridge.
Instead it traceroutes outward and takes the **last hop still inside private
address space** — which skips the bridge on bridge networking, and still lands
on the router when running with host networking. The note next to the button
shows which hop it picked, so you can see where the answer came from.

Detecting only fills the field; nothing is scanned until you press **Scan**, and
the scan is an ordinary Network Scan, so every option, report, and save works.

This answers "what does my router expose **to my LAN?**" — typically the admin
UI and DNS. It is *not* the same question as "what does the **internet** see?".
Nothing inside the LAN can answer that one: you need a vantage point outside it,
and scanning your own public IP from the inside hits the NAT from the wrong side
and gives misleading results. (The **Public IP** button tells you the address an
outside scanner would need, but the scan itself has to come from outside.)

## Configuration

| Variable       | Default                  | Meaning                                              |
|----------------|--------------------------|------------------------------------------------------|
| `SCAN_TIMEOUT` | `300`                    | Max seconds before a scan aborts                     |
| `GITHUB_TOKEN` | _(unset)_                | Fine-grained PAT for auditing private GitHub repos by URL |
| `AUDIT_DIR`    | `./audit`                | Host folder of local clones, mounted at `/audit`     |
| `AUDIT_ROOT`   | `/audit`                 | In-container path Repo Audit reads local clones from |
| `DATA_DIR`     | `./data`                 | Host folder for the database + saved reports         |
| `DB_PATH`      | `/data/secanalysis.db`   | SQLite store (monitors, saved scans, report index)   |
| `HISTORY_DIR`  | `<DB_PATH dir>/history`  | Where saved HTML reports are written                 |
| `SCHED_TICK`   | `10`                     | Seconds between monitor-scheduler ticks              |

## How it works

A single Flask app (`app.py`) serves every tool from one page, with client-side
menu switching — no framework, no build step. `templates/index.html` holds the
markup and all the JS; `static/style.css` holds the themes.

**Network Scan** and **Subnet Scan** build an `nmap` argument list and parse its
XML. **URL Analyzer** probes over HTTP(S)/TLS using the stdlib plus `dnspython`
and `cryptography`, and shells out to `whois` for the optional registration
lookup. **Exposure Probe** uses the stdlib only. **Repo Audit**
shallow-clones into a temp dir (or reads a mounted clone) and runs `gitleaks`,
`trivy`, `hadolint`, and `zizmor` — all bundled in the image. Trivy downloads
its vulnerability database on first use, so the first audit per container is
slower. The **Availability Dashboard** runs a background scheduler thread and
persists to SQLite.

The container gets `NET_RAW` / `NET_ADMIN` (see `docker-compose.yml`) so nmap
can send raw packets — what SYN scans and OS detection need. Without them nmap
still works but falls back to slower TCP-connect scans and can't fingerprint
the OS.

### Security notes

The app has no authentication and is meant to run on a host you control — it can
scan your network, so don't expose it to one you don't trust. Beyond that:

- Every external command is invoked with an **argument list, never a shell
  string**, so no input is ever parsed by a shell.
- Scan targets are validated to a single IP/hostname with no leading dash, so a
  target can't be smuggled in as an nmap flag.
- The Console's tool list and flags live **server-side**; the browser only sends
  a tool id and a target.
- Local clone names and saved-report filenames are resolved against their root
  with **path traversal blocked**.
- State-changing requests are **origin-checked** (CSRF), request bodies are
  capped, and gitleaks findings are **redacted** to a 4-character preview.
- `GITHUB_TOKEN`, if set, is **never** put on a command line or in a clone URL,
  is scoped to `https://github.com/`, is withheld from anonymous clones, and is
  stripped from any error text on its way to the UI. See
  [Auditing private repos](#auditing-private-repos).

See `SECURITY.md` for how to report an issue.

## Tests

```bash
docker cp test_app.py netscan:/app/ \
  && docker exec netscan python -m pytest test_app.py -q
```

Smoke tests for routing, the pure helpers (grading, parsing, validation), the
history/saved-scan CRUD, and the security guards. Hermetic — they point the DB
at a temp dir and never touch the network or the real data volume.

## Notes & limits

- Scans run synchronously, so the browser waits while nmap works. Full (`-p-`)
  scans on a slow host can hit the timeout — bump `SCAN_TIMEOUT` or use a
  smaller range.
- Passive subdomain sources are third-party and rate-limited; results vary with
  what the CT logs have seen.
- The DKIM check probes a list of common selectors, so "no common selectors"
  is not proof DKIM is unused.

## Stack

Flask · SQLite · nmap · gitleaks · trivy · hadolint · zizmor · dnspython ·
cryptography · vanilla JS/CSS · Docker.
