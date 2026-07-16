# SecAnalysis 👽

> ⚠️ **Disclaimer:** This is a Claude Code "vibe coding" project. It was built
> iteratively with the [Claude Code](https://claude.com/claude-code) AI agent
> and is intended for personal/experimental use. Review the code before relying
> on it, and handle your GitHub token with care.

A tiny self-hosted web UI with four tools in a left-hand menu:

1. **Network Scan** — point it at an IP or hostname and it runs
   [`nmap`](https://nmap.org/) to map open ports, running services/versions,
   and guess the OS, plus resolve the DNS name ⇄ IP.
2. **URL Analyzer** — point it at a website and it inspects security headers,
   the TLS certificate, DNS records, the redirect chain, cookies, and
   `security.txt`/`robots.txt`.
3. **Exposure Probe** — point it at a test/staging URL and it checks for
   sensitive files commonly left open (`.git/`, `.env`, debug endpoints,
   Swagger docs), each confirmed by a content signature.
4. **Repo Audit** — point it at a git repo and it runs a suite of scanners:
   [`gitleaks`](https://github.com/gitleaks/gitleaks) (secrets),
   [`trivy`](https://github.com/aquasecurity/trivy) (dependency CVEs, IaC
   misconfiguration, license risks, SBOM),
   [`hadolint`](https://github.com/hadolint/hadolint) (Dockerfiles), and
   [`zizmor`](https://github.com/woodruffw/zizmor) (GitHub Actions workflows).
   Audits a remote URL or a repo you've cloned locally.

Dark, blue-tinted, single page. Runs in Docker.

> ⚠️ **Only scan hosts you own or are explicitly authorised to test.**
> Port scanning other people's machines may be illegal where you live.

## Features

### Network Scan
- **DNS resolution** — forward and reverse lookup, so you see the name ⇄ IP mapping.
- **Port scan** — Fast (~100 ports), Standard (top 1000), or Full (all 65,535).
- **Service & version detection** (`-sV`) — what's running on each open port.
- **OS detection** (`-O`) — best-effort guess from the TCP/IP fingerprint.
- **Default scripts** (`-sC`) — banners, certs, common misconfigurations.
- **Skip host discovery** (`-Pn`) — scan hosts that don't answer pings.

### URL Analyzer
- **Basic info** — resolved IP, HTTP status, disclosed server.
- **Security headers** — CSP, HSTS, X-Frame-Options, and more (present/missing).
- **TLS certificate** — subject, issuer, validity, SANs, cipher, fingerprint,
  self-signed detection.
- **DNS records** — A, AAAA, PTR, NS, MX, TXT, CAA.
- **Redirect chain**, **cookie flags** (Secure/HttpOnly/SameSite), and
  `security.txt`/`robots.txt` discovery.
- Optional **port scan** of the first 1024 ports (reuses nmap).
- **HTTP Basic auth** — optional username/password for URLs behind a Basic-auth
  prompt; sent as an `Authorization` header on every HTTP(S) probe.

### Exposure Probe
- **Sensitive paths** — `.git/HEAD`, `.git/config`, `.env`, `.svn/entries`,
  Apache `server-status`, Spring `actuator/env`, `swagger.json`, `.DS_Store`.
- **Signature-gated** — a path only counts as exposed if the response body
  matches a known signature, so a soft-404 site doesn't flag every check.
- **Misconfigurations** — active checks for clickjacking (missing
  X-Frame-Options / CSP frame-ancestors), CORS arbitrary-origin reflection,
  weak cookie flags, and framework debug mode (Flask/Django stack traces).
- **HTTP Basic auth** — optional credentials for staging behind a Basic-auth prompt.

### Repo Audit
- **Secrets** (`gitleaks`) — committed credentials/keys; the full secret is
  redacted to a short preview in the results.
- **Vulnerable dependencies** (`trivy fs`) — known CVEs in your dependency
  manifests, with installed/fixed versions and severity.
- **IaC misconfiguration** (`trivy`) — insecure settings in Terraform,
  Kubernetes manifests, and Dockerfiles.
- **License risks** (`trivy`) — risky/copyleft licenses in dependencies
  (populates for ecosystems that expose license metadata).
- **SBOM** (`trivy`) — a downloadable CycloneDX software bill of materials.
- **Dockerfile lint** (`hadolint`) — root user, unpinned base images, and other
  Dockerfile smells.
- **GitHub Actions audit** (`zizmor`, offline) — `pull_request_target` abuse,
  unpinned third-party actions, token over-scoping, and more.
- **Remote or local** — audit a public `github.com`/`gitlab.com` URL (shallow
  clone), or pick a repo you've cloned yourself into the mounted audit folder.
  The local mode is for **private / organisation repos**: clone them with your
  own credentials, then audit them here — no GitHub token ever enters this app.

## Run it

```bash
docker compose up --build
```

Then open <http://localhost:8090>.

## How it works

A single Flask app (`app.py`) serves all four tools from one page (client-side
menu switching). **Network Scan** builds and runs an `nmap` command and parses its XML
output. **URL Analyzer** probes the target over HTTP(S) and TLS using Python's
stdlib plus `dnspython` (for MX/NS/TXT/CAA records) and `cryptography` (to read
certificate details, including self-signed certs). nmap is installed inside the
container and is also reused for the URL Analyzer's optional port scan.

The container is granted `NET_RAW` and `NET_ADMIN` capabilities (see
`docker-compose.yml`) so nmap can send raw packets — this is what SYN scans and
OS detection need. Without them, nmap still works but falls back to slower
TCP-connect scans and can't fingerprint the OS.

**Repo Audit** clones a remote repo (shallow) into a temp dir, or scans a repo
you've mounted locally, then runs `gitleaks` (secrets), `trivy` (CVEs, IaC
misconfiguration, licenses, and a CycloneDX SBOM in one pass), `hadolint` (over
any Dockerfiles), and `zizmor` (over `.github/workflows`, offline) — all bundled
in the container. **Exposure Probe** runs its path and misconfiguration checks
with Python's stdlib only. Trivy downloads its vulnerability database on first
use, so the first audit per container is slower.

### Auditing private repos with local clones

To audit a private / organisation repo without giving this app a GitHub token,
clone it yourself and point the **Repo Audit → Local clone** mode at it. The host
folder set by `AUDIT_DIR` (default `./audit`) is mounted **read-only** at `/audit`
in the container; any repo you drop in there shows up in the Local clone dropdown:

```bash
git clone git@github.com:my-org/private-app.git ./audit/private-app
AUDIT_DIR=./audit docker compose up --build      # ./audit is the default
```

### Scanning the host machine or its LAN

With the default bridge network, the container reaches other machines on your
LAN through the host's routing, which is fine for most scans. To scan the
**host itself**, or to get the most accurate results, switch to host networking:
in `docker-compose.yml`, comment out the `ports:` block and uncomment
`network_mode: host`, then browse to <http://localhost:8080>.

## Configuration

| Variable       | Default   | Meaning                                            |
|----------------|-----------|----------------------------------------------------|
| `SCAN_TIMEOUT` | `300`     | Max seconds before a scan aborts                   |
| `AUDIT_DIR`    | `./audit` | Host folder of local clones, mounted at `/audit`   |
| `AUDIT_ROOT`   | `/audit`  | In-container path Repo Audit reads local clones from |

## Notes & limits

- This is an MVP: scans run synchronously, so the browser waits while nmap
  works. Full (`-p-`) scans on a slow host can hit the timeout — bump
  `SCAN_TIMEOUT` or use a smaller range.
- The target input is validated to a single IP/hostname and nmap is always
  invoked with an argument list (never a shell string), so the form can't be
  used for command injection.

## Stack

Flask · nmap · gitleaks · trivy · hadolint · zizmor · vanilla JS/CSS · Docker. No database, no build step.
