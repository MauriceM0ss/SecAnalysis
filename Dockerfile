FROM python:3.12-slim

# Tooling behind the scanners:
#   nmap  — Network Scan + the URL Analyzer's port scan
#   git   — clone repos for the Repo Audit
#   curl  — fetch the trivy/gitleaks release binaries below
RUN apt-get update \
    && apt-get install -y --no-install-recommends nmap git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Trivy — dependency CVE scanning (Repo Audit). Release tarball, pinned.
# (Linux-64bit = amd64; use Linux-ARM64 on ARM hosts.)
ARG TRIVY_VERSION=0.71.0
RUN curl -sfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
        | tar -xz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

# gitleaks — committed-secret scanning (Repo Audit). Release tarball, pinned.
# (linux_x64 = amd64; use linux_arm64 on ARM hosts.)
ARG GITLEAKS_VERSION=8.21.2
RUN curl -sfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# hadolint — Dockerfile linter (Repo Audit). Single static binary.
ARG HADOLINT_VERSION=2.12.0
RUN curl -sfL "https://github.com/hadolint/hadolint/releases/download/v${HADOLINT_VERSION}/hadolint-Linux-x86_64" \
        -o /usr/local/bin/hadolint \
    && chmod +x /usr/local/bin/hadolint

# zizmor — GitHub Actions workflow security auditor (Repo Audit). pip-installed.
ARG ZIZMOR_VERSION=1.25.2
RUN pip install --no-cache-dir "zizmor==${ZIZMOR_VERSION}"

# Locally-mounted clones are owned by the host user, not root, so git would
# otherwise refuse to read them ("dubious ownership"). Trust any mounted repo.
RUN git config --system --add safe.directory '*'

# Network CLI tools, in their own late layer so the pinned downloads above stay
# cached. iputils-ping backs the Availability Dashboard's ICMP checks; ping,
# traceroute, dnsutils (dig) and whois are also the tools the Console offers.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iputils-ping traceroute dnsutils whois \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

ENV SCAN_TIMEOUT=300

CMD ["python", "app.py"]
