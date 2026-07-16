import os
import re
import ssl
import time
import base64
import socket
import shutil
import hashlib
import sqlite3
import http.client
import ipaddress
import json
import threading
import subprocess
import tempfile
import urllib.request
import urllib.error
import concurrent.futures
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from html.parser import HTMLParser
from urllib.parse import urlparse, urljoin, quote

import dns.resolver
import dns.reversename
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID, ExtensionOID

from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
# Cap request bodies so no endpoint can be used to exhaust memory. The largest
# legitimate body is a saved report (MAX_REPORT_BYTES, 8 MB) plus JSON overhead.
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024 * 1024

APP_VERSION = "1.0"
SCAN_TIMEOUT = int(os.environ.get("SCAN_TIMEOUT", "300"))
UA = "SecAnalysis/1.0"
# Host folder of pre-cloned repos, mounted read-only into the container. The
# Repo Audit "local clone" mode scans anything under here — so you can audit
# private / organisation repos you've cloned yourself, without ever putting a
# GitHub token in this app.
AUDIT_ROOT = os.environ.get("AUDIT_ROOT", "/audit")

# A target is a single IPv4/IPv6 address or a hostname. We deliberately keep
# this tight: no spaces, no leading dash (so it can never be read as an nmap
# flag), no shell metacharacters. nmap is always invoked with an argument list
# (never a shell string), so this is defence in depth rather than the only guard.
TARGET_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._:-]{0,253}[A-Za-z0-9])?$")

# Port-range presets. The value is the nmap flag(s) we add for that choice.
PORT_PRESETS = {
    "fast":     ["-F"],            # ~100 most common ports
    "standard": [],               # nmap default: top 1000 ports
    "full":     ["-p-"],          # all 65535 ports (slow)
}

# Subnet Scan caps the sweep so a fat prefix can't turn into a 65k-host scan.
# 1024 addresses ≈ a /22 (or /118 for IPv6); anything larger is rejected.
MAX_SUBNET_HOSTS = 1024

# Well-known service names for the URL analyzer's 1-1024 port scan.
WELL_KNOWN_PORTS = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3", 111: "RPCbind", 123: "NTP",
    135: "MS-RPC", 139: "NetBIOS-SSN", 143: "IMAP", 161: "SNMP", 389: "LDAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-Submission", 631: "IPP",
    636: "LDAPS", 873: "rsync", 993: "IMAPS", 995: "POP3S",
}


# ════════════════════════════════════════════════════════════════════════════
#  Network Scan — nmap-backed port / service / OS scanner
# ════════════════════════════════════════════════════════════════════════════
def is_valid_target(target: str) -> bool:
    return bool(target) and not target.startswith("-") and bool(TARGET_RE.match(target))


def resolve(target: str) -> dict:
    """Forward + reverse DNS so the user sees the name <-> IP mapping."""
    info = {"input": target, "ip": None, "hostname": None, "aliases": []}
    try:
        info["ip"] = socket.gethostbyname(target)
    except OSError:
        info["ip"] = target if re.match(r"^[0-9.]+$", target) else None
    if info["ip"]:
        try:
            host, aliases, _ = socket.gethostbyaddr(info["ip"])
            info["hostname"] = host
            info["aliases"] = [a for a in aliases if a != host]
        except OSError:
            pass
    return info


def build_nmap_args(target: str, opts: dict) -> list:
    args = ["nmap", "-oX", "-", "--reason", "-T4"]
    args += PORT_PRESETS.get(opts.get("ports", "standard"), [])
    if opts.get("sV"):
        args.append("-sV")           # service / version detection
    if opts.get("os"):
        args.append("-O")            # OS detection
    if opts.get("scripts"):
        args.append("-sC")           # default NSE scripts
    if opts.get("skip_ping"):
        args.append("-Pn")           # treat host as up, skip discovery
    args.append(target)
    return args


def parse_nmap_xml(xml_text: str) -> dict:
    """Pull the interesting bits out of nmap's XML into plain dicts."""
    out = {"state": None, "ports": [], "os": [], "hostnames": []}
    root = ET.fromstring(xml_text)
    host = root.find("host")
    if host is None:
        return out

    status = host.find("status")
    if status is not None:
        out["state"] = status.get("state")

    for hn in host.findall("./hostnames/hostname"):
        out["hostnames"].append({"name": hn.get("name"), "type": hn.get("type")})

    for port in host.findall("./ports/port"):
        state = port.find("state")
        service = port.find("service")
        svc_bits = []
        if service is not None:
            for key in ("product", "version", "extrainfo"):
                if service.get(key):
                    svc_bits.append(service.get(key))
        out["ports"].append({
            "port": int(port.get("portid")),
            "protocol": port.get("protocol"),
            "state": state.get("state") if state is not None else "unknown",
            "reason": state.get("reason") if state is not None else "",
            "service": service.get("name") if service is not None else "",
            "detail": " ".join(svc_bits),
        })

    for match in host.findall("./os/osmatch"):
        out["os"].append({
            "name": match.get("name"),
            "accuracy": int(match.get("accuracy", "0")),
        })

    return out


def validate_subnet(cidr: str):
    """Validate a CIDR subnet for the sweep. Returns (network, None) on success
    or (None, message) on failure. strict=False so a host address (192.168.1.5/24)
    is accepted and normalised to its network (192.168.1.0/24)."""
    if not cidr or cidr.startswith("-") or "/" not in cidr:
        return None, "Enter a subnet in CIDR notation, e.g. 192.168.1.0/24."
    try:
        net = ipaddress.ip_network(cidr, strict=False)
    except ValueError:
        return None, "Enter a valid subnet in CIDR notation, e.g. 192.168.1.0/24."
    if net.num_addresses > MAX_SUBNET_HOSTS:
        return None, (f"Subnet too large: {net.num_addresses} addresses. "
                      f"The limit is {MAX_SUBNET_HOSTS} (≈ a /22 or smaller).")
    return net, None


def parse_nmap_hosts_xml(xml_text: str) -> list:
    """Parse an `nmap -sn` host-discovery run into a list of live hosts. Unlike
    parse_nmap_xml (single host, ports), this walks every <host> that came back up."""
    hosts = []
    root = ET.fromstring(xml_text)
    for host in root.findall("host"):
        status = host.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = mac = vendor = None
        for addr in host.findall("address"):
            kind = addr.get("addrtype")
            if kind in ("ipv4", "ipv6") and not ip:
                ip = addr.get("addr")
            elif kind == "mac":
                mac = addr.get("addr")
                vendor = addr.get("vendor") or None
        hn = host.find("./hostnames/hostname")
        hosts.append({
            "ip": ip,
            "hostname": hn.get("name") if hn is not None else None,
            "mac": mac,
            "vendor": vendor,
            "reason": status.get("reason", ""),
        })
    return hosts


# ════════════════════════════════════════════════════════════════════════════
#  URL Analyzer — ported from the url-analyzer tool
# ════════════════════════════════════════════════════════════════════════════
SECURITY_HEADERS = {
    "Content-Security-Policy":   "content-security-policy",
    "Strict-Transport-Security": "strict-transport-security",
    "X-Frame-Options":           "x-frame-options",
    "X-Content-Type-Options":    "x-content-type-options",
    "Referrer-Policy":           "referrer-policy",
    "Permissions-Policy":        "permissions-policy",
}


def _basic_auth_header(username, password):
    """Build an HTTP Basic Authorization header, or {} when no username is given."""
    if not username:
        return {}
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return {"Authorization": "Basic " + token}


def _connect(parsed, timeout=10):
    host = parsed.hostname
    if parsed.scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return http.client.HTTPSConnection(host, parsed.port or 443, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, parsed.port or 80, timeout=timeout)


def _path_of(parsed):
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return path


def head_request(url, auth=None):
    """HEAD request -> (status, headers dict, response message for cookies)."""
    parsed = urlparse(url)
    conn = _connect(parsed)
    try:
        conn.request("HEAD", _path_of(parsed), headers={"User-Agent": UA, **(auth or {})})
        resp = conn.getresponse()
        resp.read()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers
    finally:
        conn.close()


def fetch_text_file(parsed_base, file_path, auth=None):
    """GET a text file, capped at 10 KB. Returns {found, content}."""
    parsed = urlparse(urljoin(f"{parsed_base.scheme}://{parsed_base.netloc}", file_path))
    conn = _connect(parsed, timeout=5)
    try:
        conn.request("GET", _path_of(parsed), headers={"User-Agent": UA, **(auth or {})})
        resp = conn.getresponse()
        if resp.status != 200:
            resp.read()
            return {"found": False, "content": None}
        MAX = 10240
        body = resp.read(MAX + 1)
        truncated = len(body) > MAX
        content = body[:MAX].decode("utf-8", "replace")
        if truncated:
            content += "\n[content truncated at 10 KB]"
        return {"found": True, "content": content}
    except OSError:
        return {"found": False, "content": None}
    finally:
        conn.close()


def get_cookies(url, auth=None):
    """GET request, parse Set-Cookie headers into security flags."""
    parsed = urlparse(url)
    conn = _connect(parsed)
    try:
        conn.request("GET", _path_of(parsed), headers={"User-Agent": UA, **(auth or {})})
        resp = conn.getresponse()
        raw_cookies = resp.msg.get_all("set-cookie") or []
        resp.read()
    except OSError:
        return []
    finally:
        conn.close()

    cookies = []
    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0].strip()
        attrs = [a.lower() for a in parts[1:]]
        same_site = next((a.split("=")[1] for a in attrs if a.startswith("samesite=")), None)
        cookies.append({
            "name": name,
            "secure": "secure" in attrs,
            "httpOnly": "httponly" in attrs,
            "sameSite": same_site,
        })
    return cookies


# Protocol versions we actively probe. 1.0/1.1 are deprecated (RFC 8996).
_TLS_VERSIONS = [
    ("TLS 1.0", ssl.TLSVersion.TLSv1),
    ("TLS 1.1", ssl.TLSVersion.TLSv1_1),
    ("TLS 1.2", ssl.TLSVersion.TLSv1_2),
    ("TLS 1.3", ssl.TLSVersion.TLSv1_3),
]
_DEPRECATED_PROTOCOLS = {"TLS 1.0", "TLS 1.1"}
# Cipher families considered weak/broken if negotiated.
_WEAK_CIPHER_RE = re.compile(r"RC4|3DES|DES-CBC3|DES-CBC|NULL|EXP|EXPORT|MD5|ADH|AECDH|ANON", re.I)


def _probe_one_tls(hostname, port, ver):
    """True if the server completes a handshake pinned to exactly `ver`,
    False if it refuses, None if the local OpenSSL can't offer that version."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        ctx.minimum_version = ver
        ctx.maximum_version = ver
    except (ValueError, OSError):
        return None
    # Let old protocols/ciphers negotiate even on hardened OpenSSL builds
    # (no effect on TLS 1.3, whose suites are always enabled).
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    try:
        with socket.create_connection((hostname, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True
    except ssl.SSLError:
        return False
    except OSError:
        return None  # network/timeout — inconclusive, don't claim "unsupported"


def probe_tls_versions(hostname, port=443):
    """Concurrently probe each protocol version so total latency stays near a
    single handshake rather than four sequential ones."""
    out = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(_TLS_VERSIONS)) as ex:
        futs = {ex.submit(_probe_one_tls, hostname, port, ver): label
                for label, ver in _TLS_VERSIONS}
        for fut in concurrent.futures.as_completed(futs):
            out[futs[fut]] = fut.result()
    return out


def _verify_chain(hostname, port):
    """Attempt a fully-verifying handshake (trusted CA chain + hostname match).
    Returns (trusted: bool, error: str|None)."""
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname):
                return True, None
    except ssl.SSLCertVerificationError as e:
        return False, e.verify_message or str(e)
    except (ssl.SSLError, OSError) as e:
        return False, str(e)


def get_certificate_info(hostname, port=443):
    """TLS certificate details. Uses cryptography so we can read self-signed certs."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                der = ssock.getpeercert(binary_form=True)
                protocol = ssock.version()
                cipher = ssock.cipher()
    except (OSError, ssl.SSLError):
        return None
    if not der:
        return None

    cert = x509.load_der_x509_certificate(der)

    def _cn(name, *oids):
        for oid in oids:
            attrs = name.get_attributes_for_oid(oid)
            if attrs:
                return attrs[0].value
        return "Unknown"

    try:
        sans = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        ).value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []

    not_after = cert.not_valid_after_utc
    not_before = cert.not_valid_before_utc
    days_left = (not_after - datetime.now(timezone.utc)).days
    fmt = "%b %d %H:%M:%S %Y GMT"

    protocols = probe_tls_versions(hostname, port)
    deprecated = sorted(p for p in _DEPRECATED_PROTOCOLS if protocols.get(p) is True)
    cipher_name = cipher[0] if cipher else None
    trusted, trust_error = _verify_chain(hostname, port)

    return {
        "subject": _cn(cert.subject, NameOID.COMMON_NAME, NameOID.ORGANIZATION_NAME),
        "issuer": _cn(cert.issuer, NameOID.ORGANIZATION_NAME, NameOID.COMMON_NAME),
        "validFrom": not_before.strftime(fmt),
        "validTo": not_after.strftime(fmt),
        "daysUntilExpiry": days_left,
        "sans": sans,
        "selfSigned": cert.issuer == cert.subject,
        "serialNumber": format(cert.serial_number, "x"),
        "fingerprint256": cert.fingerprint(hashes.SHA256()).hex(),
        "protocol": protocol,
        "cipher": cipher_name,
        "protocols": protocols,
        "deprecatedProtocols": deprecated,
        "weakCipher": bool(cipher_name and _WEAK_CIPHER_RE.search(cipher_name)),
        "chainTrusted": trusted,
        "trustError": None if trusted else trust_error,
    }


def get_dns_records(hostname):
    """A / AAAA / MX / NS / TXT / CAA / PTR records via dnspython."""
    records = {}
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    def q(rtype):
        try:
            return list(resolver.resolve(hostname, rtype))
        except Exception:
            return []

    records["A"] = [r.address for r in q("A")]
    records["AAAA"] = [r.address for r in q("AAAA")]
    records["NS"] = [r.target.to_text().rstrip(".") for r in q("NS")]
    records["MX"] = [{"priority": r.preference, "exchange": r.exchange.to_text().rstrip(".")}
                     for r in q("MX")]
    records["TXT"] = ["".join(s.decode() if isinstance(s, bytes) else s for s in r.strings)
                      for r in q("TXT")]
    records["CAA"] = [{"critical": bool(r.flags), "tag": r.tag.decode() if isinstance(r.tag, bytes) else r.tag,
                       "value": r.value.decode() if isinstance(r.value, bytes) else r.value}
                      for r in q("CAA")]

    records["PTR"] = []
    if records["A"]:
        try:
            rev = dns.reversename.from_address(records["A"][0])
            records["PTR"] = [r.target.to_text().rstrip(".") for r in resolver.resolve(rev, "PTR")]
        except Exception:
            pass
    return records


def _parse_dmarc(txt: str) -> dict:
    """Split a DMARC TXT record into its tag=value pairs."""
    tags = {}
    for part in txt.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def get_dmarc(hostname: str) -> dict:
    """DMARC policy for a host, honouring organizational-domain inheritance.

    A subdomain with no `_dmarc` record of its own inherits its parent's
    policy — the parent's `sp=` (subdomain policy) if set, otherwise its `p=`
    (RFC 7489). We look the record up on the host, then walk up the parent
    labels (stopping before the TLD) until one is found."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    def dmarc_at(domain):
        try:
            for r in resolver.resolve("_dmarc." + domain, "TXT"):
                txt = "".join(s.decode() if isinstance(s, bytes) else s for s in r.strings)
                if txt.lower().startswith("v=dmarc1"):
                    return txt
        except Exception:
            return None
        return None

    own = dmarc_at(hostname)
    if own:
        tags = _parse_dmarc(own)
        return {"found": True, "record": own, "tags": tags, "inherited": False,
                "inheritedFrom": None, "policy": tags.get("p", "none")}

    labels = hostname.split(".")
    for i in range(1, len(labels) - 1):
        parent = ".".join(labels[i:])
        rec = dmarc_at(parent)
        if rec:
            tags = _parse_dmarc(rec)
            return {"found": True, "record": rec, "tags": tags, "inherited": True,
                    "inheritedFrom": parent, "policy": tags.get("sp", tags.get("p", "none"))}

    return {"found": False, "record": None, "tags": {}, "inherited": False,
            "inheritedFrom": None, "policy": None}


def get_dnssec(hostname: str) -> dict:
    """DNSSEC signing indicator (not a full validation).

    Reports the closest ancestor zone (host first, then up the parents) that
    publishes a DNSKEY, and whether the parent delegates securely to it with a
    DS record — i.e. a chain of trust exists."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0

    def has(domain, rtype):
        try:
            return len(resolver.resolve(domain, rtype)) > 0
        except Exception:
            return False

    labels = hostname.split(".")
    for i in range(0, len(labels) - 1):
        domain = ".".join(labels[i:])
        if has(domain, "DNSKEY"):
            return {"signed": True, "zone": domain, "ds": has(domain, "DS")}
    return {"signed": False, "zone": None, "ds": False}


# ── Email security (SPF / DKIM / MTA-STS / TLS-RPT) ─────────────────────────
def _domain_candidates(hostname: str) -> list:
    """The host itself, then each parent domain up to (but excluding) the TLD.

    Mail-authentication records usually live on the organizational domain, so
    for `www.example.com` we probe `www.example.com` then `example.com`. This
    is a heuristic — it does not consult the Public Suffix List, so multi-label
    TLDs like `co.uk` are only approximated."""
    labels = hostname.split(".")
    return [".".join(labels[i:]) for i in range(0, max(1, len(labels) - 1))]


def _txt_records(resolver, domain: str) -> list:
    try:
        return ["".join(s.decode() if isinstance(s, bytes) else s for s in r.strings)
                for r in resolver.resolve(domain, "TXT")]
    except Exception:
        return []


_SPF_ALL_RE = re.compile(r"([-~?+]?)all\b", re.I)
_SPF_QUALIFIER = {"-": "fail", "~": "softfail", "?": "neutral", "+": "pass", "": "pass"}


def _analyze_spf(txt: str, domain: str, inherited: bool) -> dict:
    """Parse an SPF record: count DNS-lookup mechanisms (the RFC 7208 limit is
    10) and read the final `all` qualifier (`-all` hard-fail is strongest)."""
    lookups = 0
    for tok in txt.split():
        t = tok.lower().lstrip("+-~?")
        if (t.startswith(("include:", "exists:", "redirect=")) or t in ("a", "mx", "ptr")
                or t.startswith(("a:", "a/", "mx:", "mx/", "ptr:"))):
            lookups += 1
    m = _SPF_ALL_RE.search(txt)
    qualifier = m.group(1) if m else None
    return {"found": True, "record": txt, "domain": domain, "inherited": inherited,
            "lookups": lookups, "tooManyLookups": lookups > 10,
            "all": _SPF_QUALIFIER.get(qualifier) if qualifier is not None else None}


def get_spf(hostname: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    for domain in _domain_candidates(hostname):
        for txt in _txt_records(resolver, domain):
            if txt.lower().startswith("v=spf1"):
                return _analyze_spf(txt, domain, domain != hostname)
    return {"found": False, "record": None, "domain": None, "inherited": False,
            "lookups": 0, "tooManyLookups": False, "all": None}


# Selectors published by common mail providers. Absence is not proof DKIM is
# unused (operators pick arbitrary selectors) — hence "no common selectors".
_DKIM_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "k2",
                   "mail", "dkim", "s1", "s2", "smtp", "mandrill", "mxvault", "zmail")


def get_dkim(hostname: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    base = _domain_candidates(hostname)[-1]
    found = []
    for sel in _DKIM_SELECTORS:
        for txt in _txt_records(resolver, f"{sel}._domainkey.{base}"):
            low = txt.lower()
            if "v=dkim1" in low or "k=rsa" in low or "p=" in low:
                found.append(sel)
                break
    return {"found": bool(found), "selectors": found, "domain": base,
            "checked": list(_DKIM_SELECTORS)}


def get_mta_sts(hostname: str) -> dict:
    """MTA-STS: the `_mta-sts` TXT flag plus the HTTPS-hosted policy (for the
    enforcement mode). Only the policy file states `enforce`/`testing`/`none`."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    base = _domain_candidates(hostname)[-1]
    dns_found = any(t.lower().startswith("v=stsv1")
                    for t in _txt_records(resolver, "_mta-sts." + base))
    mode = None
    if dns_found:
        try:
            req = urllib.request.Request(
                f"https://mta-sts.{base}/.well-known/mta-sts.txt",
                headers={"User-Agent": UA})
            with urllib.request.urlopen(req, timeout=6) as resp:
                body = resp.read(8192).decode("utf-8", "replace")
            for line in body.splitlines():
                if line.lower().startswith("mode:"):
                    mode = line.split(":", 1)[1].strip().lower()
                    break
        except Exception:
            pass
    return {"found": dns_found, "domain": base, "mode": mode}


def get_tls_rpt(hostname: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 5.0
    base = _domain_candidates(hostname)[-1]
    for txt in _txt_records(resolver, "_smtp._tls." + base):
        if txt.lower().startswith("v=tlsrptv1"):
            return {"found": True, "record": txt, "domain": base}
    return {"found": False, "record": None, "domain": base}


def get_email_security(hostname: str) -> dict:
    """Bundle the DNS-based mail-security posture used by the URL analyzer."""
    return {"spf": get_spf(hostname), "dkim": get_dkim(hostname),
            "mtaSts": get_mta_sts(hostname), "tlsRpt": get_tls_rpt(hostname)}


# ── Header quality: CSP and HSTS aren't just present/absent ─────────────────
def _parse_csp(value: str) -> dict:
    """CSP text → {directive: [sources]}. Directive names are lower-cased."""
    out = {}
    for part in value.split(";"):
        toks = part.split()
        if toks:
            out[toks[0].lower()] = toks[1:]
    return out


def analyze_csp(value) -> dict:
    """Grade a Content-Security-Policy beyond mere presence: an `unsafe-inline`
    script policy or a wildcard source defeats most of CSP's XSS protection."""
    if not value or value == "Not found":
        return {"present": False, "issues": [], "grade": "bad"}

    d = _parse_csp(value)
    issues = []  # each: {"text", "severity": "high"|"med"|"low"}
    script = d.get("script-src", d.get("default-src", []))
    style = d.get("style-src", d.get("default-src", []))
    has_nonce_or_hash = any(s.startswith(("'nonce-", "'sha256-", "'sha384-", "'sha512-"))
                            for s in script)

    if "default-src" not in d and "script-src" not in d:
        issues.append({"text": "No default-src or script-src — no baseline restriction",
                       "severity": "high"})
    if "'unsafe-inline'" in script and not has_nonce_or_hash:
        issues.append({"text": "script-src allows 'unsafe-inline' (no nonce/hash) — XSS not mitigated",
                       "severity": "high"})
    if "*" in script or "*" in d.get("default-src", []):
        issues.append({"text": "Wildcard '*' source in script/default-src",
                       "severity": "high"})
    if "'unsafe-eval'" in script:
        issues.append({"text": "script-src allows 'unsafe-eval'", "severity": "med"})
    if "'unsafe-inline'" in style:
        issues.append({"text": "style-src allows 'unsafe-inline'", "severity": "low"})
    if any(s.startswith("http:") for srcs in d.values() for s in srcs):
        issues.append({"text": "Insecure http: source allowed", "severity": "med"})
    if d.get("object-src") != ["'none'"] and "object-src" not in d and "default-src" not in d:
        issues.append({"text": "object-src not locked to 'none' (plugin content)",
                       "severity": "low"})
    if "base-uri" not in d:
        issues.append({"text": "No base-uri directive (base-tag injection)",
                       "severity": "low"})

    sev = {i["severity"] for i in issues}
    grade = "bad" if "high" in sev else "warn" if issues else "good"
    return {"present": True, "issues": issues, "grade": grade,
            "directives": sorted(d.keys())}


def analyze_hsts(value) -> dict:
    """Parse HSTS and report browser-preload-list eligibility (max-age ≥ 1 year
    + includeSubDomains + preload)."""
    if not value or value == "Not found":
        return {"present": False, "maxAge": None, "includeSubDomains": False,
                "preload": False, "preloadEligible": False}
    low = value.lower()
    max_age = None
    m = re.search(r"max-age\s*=\s*(\d+)", low)
    if m:
        max_age = int(m.group(1))
    include_sub = "includesubdomains" in low
    preload = "preload" in low
    eligible = bool(max_age is not None and max_age >= 31536000 and include_sub and preload)
    return {"present": True, "maxAge": max_age, "includeSubDomains": include_sub,
            "preload": preload, "preloadEligible": eligible}


# ── Scorecard: turn the raw findings into per-category verdicts + a grade ────
# Each grader returns (verdict, detail). Verdicts: "good" | "warn" | "bad" |
# "na". Weights are only counted for graded (non-na) categories, so a scan run
# without DNS-auth still produces a fair score over what was actually checked.
_GRADE_SCORE = {"good": 1.0, "warn": 0.5, "bad": 0.0}
_CATEGORY_WEIGHTS = {
    "TLS/SSL": 25, "Security Headers": 20, "Mixed Content": 15, "DMARC": 15,
    "HTTPS Redirect": 10, "SPF": 10, "Cookies": 10, "Email Transport": 10,
    "DNSSEC": 5, "security.txt": 5,
}


def _grade_tls(r):
    if not (r.get("url") or "").startswith("https://"):
        return "na", "Served over plain HTTP"
    c = r.get("certInfo")
    if not c:
        return "bad", "HTTPS but no certificate could be read"
    proto = (c.get("protocol") or "")
    weak_proto = proto in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
    deprecated = c.get("deprecatedProtocols") or []
    # Hard failures first.
    if c.get("daysUntilExpiry", 0) < 0:
        return "bad", "Certificate has expired"
    if c.get("selfSigned"):
        return "bad", "Self-signed certificate (not browser-trusted)"
    if c.get("chainTrusted") is False:
        return "bad", f"Chain/hostname not trusted ({c.get('trustError') or 'verification failed'})"
    if weak_proto:
        return "bad", f"Deprecated protocol negotiated ({proto})"
    if c.get("weakCipher"):
        return "bad", f"Weak cipher negotiated ({c.get('cipher')})"
    # Then softer concerns.
    if deprecated:
        return "warn", f"Deprecated protocol(s) still enabled: {', '.join(deprecated)}"
    if c.get("daysUntilExpiry", 999) < 21:
        return "warn", f"Certificate expires in {c['daysUntilExpiry']}d"
    return "good", f"{proto}, trusted cert ({c.get('daysUntilExpiry')}d left)"


def _grade_headers(r):
    h = r.get("securityHeaders") or {}
    def present(k):
        v = h.get(k)
        return bool(v) and v != "Not found"
    critical = {"Content-Security-Policy": present("Content-Security-Policy"),
                "Strict-Transport-Security": present("Strict-Transport-Security")}
    others = ["X-Content-Type-Options", "X-Frame-Options",
              "Referrer-Policy", "Permissions-Policy"]
    count = sum(critical.values()) + sum(present(k) for k in others)
    missing = [k for k, v in critical.items() if not v]
    if missing:
        return ("bad" if len(missing) == 2 else "warn",
                "Missing " + ", ".join(missing))
    # CSP is present — its quality matters more than the raw header count.
    csp = r.get("cspAnalysis") or {}
    if csp.get("grade") == "bad":
        return "warn", "CSP present but weak (" + \
            (csp["issues"][0]["text"] if csp.get("issues") else "unsafe policy") + ")"
    if count >= 5:
        return "good", f"{count}/6 headers set (incl. CSP + HSTS)"
    return "warn", f"CSP + HSTS present, {count}/6 headers total"


def _grade_mixed_content(r):
    if not (r.get("url") or "").startswith("https://"):
        return "na", "Not an HTTPS page"
    pc = r.get("pageContent") or {}
    if not pc.get("analyzed"):
        return "na", "Page HTML could not be fetched"
    a, p = pc.get("mixedActiveCount", 0), pc.get("mixedPassiveCount", 0)
    if a:
        return "bad", f"{a} active mixed-content resource(s) loaded over http://"
    if p:
        return "warn", f"{p} passive mixed-content resource(s) over http://"
    return "good", f"No mixed content ({pc.get('resourceCount', 0)} resources checked)"


def _grade_https_redirect(r):
    hr = r.get("httpsRedirect") or {}
    if not hr.get("tested"):
        return "na", "No reachable HTTP endpoint to probe"
    if hr.get("upgradesToHttps"):
        return "good", "http:// redirects to https://"
    return "bad", "Plain HTTP is served with no HTTPS redirect"


def _grade_cookies(r):
    cookies = r.get("cookies") or []
    if not cookies:
        return "na", "No cookies set on this response"
    https = (r.get("url") or "").startswith("https://")
    weak = [c["name"] for c in cookies
            if (https and not c.get("secure")) or not c.get("httpOnly")
            or not c.get("sameSite")]
    if not weak:
        return "good", f"All {len(cookies)} cookie(s) Secure + HttpOnly + SameSite"
    return "warn", f"{len(weak)}/{len(cookies)} cookie(s) missing a security flag"


def _grade_dmarc(r):
    m = r.get("dmarc")
    if m is None:
        return "na", "Not checked (enable DNS authentication)"
    if not m.get("found"):
        return "bad", "No DMARC record — domain can be spoofed"
    pol = m.get("policy")
    if pol in ("reject", "quarantine"):
        return "good", f"p={pol}" + (" (inherited)" if m.get("inherited") else "")
    return "warn", f"p={pol or 'none'} — monitoring only, not enforced"


def _grade_spf(r):
    s = r.get("spf")
    if s is None:
        return "na", "Not checked (enable DNS authentication)"
    if not s.get("found"):
        return "bad", "No SPF record"
    if s.get("tooManyLookups"):
        return "warn", f"{s['lookups']} DNS lookups (>10 → PermError)"
    if s.get("all") in ("fail", "softfail"):
        return "good", f"-all/~all ({s['all']}), {s['lookups']} lookups"
    return "warn", f"Weak default ({s.get('all') or 'no all'} qualifier)"


def _grade_email_transport(r):
    mx = ((r.get("dnsRecords") or {}).get("MX")) or []
    mts, tls = r.get("mtaSts"), r.get("tlsRpt")
    if mts is None:
        return "na", "Not checked (enable DNS authentication)"
    if not mx:
        return "na", "Domain publishes no MX (receives no mail)"
    bits = []
    grade = "warn"
    if mts.get("found"):
        bits.append("MTA-STS " + (mts.get("mode") or "on"))
        if mts.get("mode") == "enforce":
            grade = "good"
    else:
        bits.append("no MTA-STS")
    bits.append("TLS-RPT" if (tls and tls.get("found")) else "no TLS-RPT")
    if not mts.get("found") and not (tls and tls.get("found")):
        grade = "bad"
    return grade, ", ".join(bits)


def _grade_dnssec(r):
    s = r.get("dnssec")
    if s is None:
        return "na", "Not checked (enable DNS authentication)"
    if s.get("signed"):
        return ("good" if s.get("ds") else "warn"), (
            f"Signed ({s.get('zone')})" + ("" if s.get("ds") else ", no DS at parent"))
    return "warn", "Zone is not DNSSEC-signed"


def _grade_securitytxt(r):
    txt = r.get("securityTxt") or {}
    if txt.get("found"):
        return "good", "Published at /.well-known/security.txt"
    return "warn", "No security.txt — no disclosure contact advertised"


def grade_analysis(r: dict) -> dict:
    """Roll the URL-analyzer findings into per-category verdicts and a weighted
    0–100 score. Categories that were not applicable/checked are excluded from
    the score rather than penalised."""
    graders = [
        ("TLS/SSL", _grade_tls), ("Security Headers", _grade_headers),
        ("Mixed Content", _grade_mixed_content), ("DMARC", _grade_dmarc),
        ("HTTPS Redirect", _grade_https_redirect), ("SPF", _grade_spf),
        ("Cookies", _grade_cookies), ("Email Transport", _grade_email_transport),
        ("DNSSEC", _grade_dnssec), ("security.txt", _grade_securitytxt),
    ]
    categories, earned, possible = [], 0.0, 0.0
    for name, fn in graders:
        grade, detail = fn(r)
        categories.append({"name": name, "grade": grade, "detail": detail})
        if grade != "na":
            weight = _CATEGORY_WEIGHTS[name]
            possible += weight
            earned += weight * _GRADE_SCORE[grade]
    score = round(100 * earned / possible) if possible else None
    rating = None
    if score is not None:
        rating = "good" if score >= 80 else "warn" if score >= 50 else "bad"
    return {"score": score, "rating": rating, "categories": categories}


_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SUBDOMAIN_CAP = 500


def is_valid_domain(domain: str) -> bool:
    return bool(_DOMAIN_RE.match((domain or "").strip().lower().rstrip(".")))


def _fetch_url_text(url: str, timeout: int) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", "replace")


def _src_crtsh(domain: str) -> set:
    txt = _fetch_url_text("https://crt.sh/?q=" + quote("%." + domain) + "&output=json", 15)
    names = set()
    for entry in json.loads(txt):
        for nm in (entry.get("name_value") or "").split("\n"):
            names.add(nm.strip().lower())
    return names


def _src_certspotter(domain: str) -> set:
    url = ("https://api.certspotter.com/v1/issuances?domain=" + quote(domain)
           + "&include_subdomains=true&expand=dns_names")
    names = set()
    for issuance in json.loads(_fetch_url_text(url, 20)):
        for nm in issuance.get("dns_names", []):
            names.add(nm.strip().lower())
    return names


def _src_hackertarget(domain: str) -> set:
    txt = _fetch_url_text("https://api.hackertarget.com/hostsearch/?q=" + quote(domain), 15)
    names = set()
    low = txt.lower()
    if "," in txt and "api count" not in low and "error" not in low:
        for line in txt.splitlines():
            host = line.split(",", 1)[0].strip().lower()
            if host:
                names.add(host)
    return names


# Passive sources are queried concurrently and merged, so one being down or slow
# doesn't sink the lookup. All are keyless CT-log / passive-DNS providers.
SUBDOMAIN_SOURCES = {"crt.sh": _src_crtsh, "certspotter": _src_certspotter,
                     "hackertarget": _src_hackertarget}


def find_subdomains(domain: str) -> dict:
    """Passive subdomain discovery across several CT-log / passive-DNS sources.

    Each source is queried concurrently and the results merged, then every name
    is resolved (concurrently) so live hosts and their current IPv4 addresses
    are flagged apart from names that only ever appeared in a certificate."""
    domain = (domain or "").strip().lower().rstrip(".")

    names, contributed, ok = set(), [], []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(SUBDOMAIN_SOURCES)) as ex:
        futs = {ex.submit(fn, domain): name for name, fn in SUBDOMAIN_SOURCES.items()}
        for fut in concurrent.futures.as_completed(futs):
            src = futs[fut]
            try:
                got = {n.lstrip("*.").rstrip(".") for n in fut.result()}
                got = {n for n in got if n == domain or n.endswith("." + domain)}
                ok.append(src)
                if got:
                    names |= got
                    contributed.append(src)
            except Exception as e:
                app.logger.info("subdomain source %s failed: %s", src, e)

    if not ok:
        return {"error": "All subdomain sources failed or timed out. Try again shortly."}

    names = sorted(names)
    truncated = len(names) > SUBDOMAIN_CAP
    names = names[:SUBDOMAIN_CAP]

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0

    def resolve_one(nm):
        try:
            return nm, [r.address for r in resolver.resolve(nm, "A")]
        except Exception:
            return nm, []

    resolved = {}
    if names:
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
                for nm, addrs in ex.map(resolve_one, names):
                    resolved[nm] = addrs
        except Exception:
            resolved = {nm: [] for nm in names}

    result = [{"name": nm, "resolves": bool(resolved.get(nm)),
               "addresses": resolved.get(nm, [])} for nm in names]
    result.sort(key=lambda x: (not x["resolves"], x["name"]))

    return {"domain": domain, "sources": contributed, "names": result,
            "count": len(result), "resolvingCount": sum(1 for n in result if n["resolves"]),
            "truncated": truncated}


def get_redirect_chain(url, auth=None):
    """Follow the HTTP redirect chain (HEAD), up to 10 hops."""
    chain = []
    current = url
    for _ in range(10):
        try:
            status, headers = head_request(current, auth)
        except OSError as e:
            chain.append({"url": current, "statusCode": None, "error": str(e)})
            break
        chain.append({"url": current, "statusCode": status, "error": None})
        location = headers.get("location")
        if status not in (301, 302, 303, 307, 308) or not location:
            break
        current = urljoin(current, location)
    return chain


# ── Page content: mixed content + third-party resource inventory ────────────
# Sub-resource-loading tags → (url attrs, kind). "active" resources (scripts,
# frames, stylesheets) are BLOCKED by browsers as mixed content; "passive" ones
# (images, media) are upgraded/warned. Hyperlinks (<a>) are intentionally ignored.
_RESOURCE_TAGS = {
    "script": (["src"], "active"),
    "img":    (["src", "srcset"], "passive"),
    "iframe": (["src"], "active"),
    "source": (["src", "srcset"], "passive"),
    "object": (["data"], "active"),
    "embed":  (["src"], "active"),
    "video":  (["src", "poster"], "passive"),
    "audio":  (["src"], "passive"),
}


def _link_kind(rel):
    rel = (rel or "").lower()
    if any(k in rel for k in ("stylesheet", "preload", "modulepreload")):
        return "active"
    if any(k in rel for k in ("icon", "manifest")):
        return "passive"
    if any(k in rel for k in ("preconnect", "dns-prefetch", "prefetch")):
        return "hint"   # a host hint, not a fetched sub-resource
    return None


class _ResourceParser(HTMLParser):
    """Collect (raw_url, kind) for every sub-resource a browser would load."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.resources = []

    def handle_starttag(self, tag, attrs):
        ad = dict(attrs)
        if tag == "link":
            kind = _link_kind(ad.get("rel"))
            if kind and ad.get("href"):
                self.resources.append((ad["href"], kind))
            return
        spec = _RESOURCE_TAGS.get(tag)
        if not spec:
            return
        attr_list, kind = spec
        for attr in attr_list:
            val = ad.get(attr)
            if not val:
                continue
            if attr == "srcset":
                for cand in val.split(","):
                    parts = cand.strip().split()
                    if parts:
                        self.resources.append((parts[0], kind))
            else:
                self.resources.append((val, kind))


def fetch_page_html(url, auth=None, cap=524288):
    """GET a page body (HTML only, capped at 512 KB). Returns the text or None."""
    parsed = urlparse(url)
    conn = _connect(parsed, timeout=8)
    try:
        conn.request("GET", _path_of(parsed),
                     headers={"User-Agent": UA, "Accept": "text/html,*/*", **(auth or {})})
        resp = conn.getresponse()
        ctype = (resp.getheader("Content-Type") or "").lower()
        if resp.status >= 400 or (ctype and "html" not in ctype):
            resp.read()
            return None
        return resp.read(cap).decode("utf-8", "replace")
    except OSError:
        return None
    finally:
        conn.close()


def analyze_page_content(html, page_url):
    """From page HTML: mixed-content resources (on HTTPS pages) and the set of
    distinct third-party hosts the page pulls resources from. No requests are
    made to those hosts — only the URLs already in the markup are inspected."""
    if not html:
        return {"analyzed": False}
    parser = _ResourceParser()
    try:
        parser.feed(html)
    except Exception:
        pass

    page = urlparse(page_url)
    is_https = page.scheme == "https"
    page_host = (page.hostname or "").lower()
    mixed_active, mixed_passive, hosts, total = [], [], {}, 0

    for raw, kind in parser.resources:
        raw = (raw or "").strip()
        if not raw or raw.startswith(("data:", "blob:", "javascript:", "about:",
                                      "#", "mailto:", "tel:")):
            continue
        resolved = urljoin(page_url, raw)
        pr = urlparse(resolved)
        if pr.scheme not in ("http", "https"):
            continue
        total += 1
        host = (pr.hostname or "").lower()
        if host and host != page_host:
            hosts[host] = hosts.get(host, 0) + 1
        if is_https and pr.scheme == "http" and kind != "hint":
            item = {"url": resolved, "kind": kind}
            (mixed_active if kind == "active" else mixed_passive).append(item)

    third = sorted(({"host": h, "count": c} for h, c in hosts.items()),
                   key=lambda x: (-x["count"], x["host"]))
    return {
        "analyzed": True,
        "resourceCount": total,
        "mixedActive": mixed_active[:50],
        "mixedPassive": mixed_passive[:50],
        "mixedActiveCount": len(mixed_active),
        "mixedPassiveCount": len(mixed_passive),
        "thirdPartyHosts": third[:40],
        "thirdPartyCount": len(third),
    }


def get_https_redirect(hostname):
    """Does the plain-HTTP site redirect to HTTPS? HEADs http://host/ + follows."""
    chain = get_redirect_chain(f"http://{hostname}/")
    final = next((h["url"] for h in reversed(chain) if h.get("url")), None)
    reached = any(h.get("statusCode") for h in chain)
    upgrades = bool(final and urlparse(final).scheme == "https")
    return {"tested": reached, "upgradesToHttps": upgrades, "finalUrl": final}


def analyze_redirects(chain):
    """Flag hygiene problems in a redirect chain (downgrade / loop / cap / error)."""
    issues = []
    urls = [h.get("url") for h in chain if h.get("url")]
    schemes = [urlparse(u).scheme for u in urls]
    if any(a == "https" and b == "http" for a, b in zip(schemes, schemes[1:])):
        issues.append("HTTPS→HTTP downgrade in the redirect chain")
    if len(urls) != len(set(urls)):
        issues.append("Redirect loop — a URL repeats")
    if len(chain) >= 10:
        issues.append("Chain hit the 10-hop limit (possible loop)")
    if any(h.get("error") for h in chain):
        issues.append("A hop failed to connect")
    return issues


def nmap_port_scan(ip, port_range="1-1024"):
    """Reuse nmap for the URL analyzer's port scan -> [{port, service}]."""
    if not shutil.which("nmap"):
        return []
    args = ["nmap", "-oX", "-", "-T4", "--open", "-p", port_range, ip]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        parsed = parse_nmap_xml(proc.stdout)
    except (subprocess.TimeoutExpired, ET.ParseError):
        return []
    out = []
    for p in parsed["ports"]:
        if p["state"] == "open":
            out.append({"port": p["port"],
                        "service": p["service"] or WELL_KNOWN_PORTS.get(p["port"], "unknown")})
    return out


# ════════════════════════════════════════════════════════════════════════════
#  Exposure Probe — sensitive files / debug surfaces left open on staging
# ════════════════════════════════════════════════════════════════════════════
# path -> (label, severity, body signature). The signature must appear in the
# response body for us to call something "exposed", so a host that returns 200
# for everything (a soft-404) doesn't light up every row.
EXPOSURE_CHECKS = [
    ("/.git/HEAD",     "Git repository",       "high",   re.compile(rb"ref:\s*refs/")),
    ("/.git/config",   "Git config",           "high",   re.compile(rb"\[core\]")),
    ("/.env",          "Environment file",     "high",   re.compile(rb"(?mi)^[A-Z0-9_]+=")),
    ("/.svn/entries",  "SVN metadata",         "medium", re.compile(rb"^\d+")),
    ("/server-status", "Apache server-status", "medium", re.compile(rb"Apache Server Status")),
    ("/actuator/env",  "Spring Actuator env",  "high",   re.compile(rb'"propertySources"')),
    ("/swagger.json",  "Swagger / OpenAPI",    "low",    re.compile(rb'"(swagger|openapi)"')),
    ("/.DS_Store",     "macOS .DS_Store",      "low",    re.compile(rb"Bud1")),
]


def _probe_get(parsed_base, path, auth=None, cap=4096):
    """GET a single path on the target -> (status, body bytes capped at `cap`)."""
    parsed = urlparse(urljoin(f"{parsed_base.scheme}://{parsed_base.netloc}", path))
    conn = _connect(parsed, timeout=5)
    try:
        conn.request("GET", _path_of(parsed), headers={"User-Agent": UA, **(auth or {})})
        resp = conn.getresponse()
        return resp.status, resp.read(cap)
    except OSError:
        return None, b""
    finally:
        conn.close()


def probe_exposures(url, auth=None):
    """Check the target for known-sensitive paths, gated on a content signature."""
    parsed = urlparse(url)
    findings = []
    for path, label, severity, signature in EXPOSURE_CHECKS:
        status, body = _probe_get(parsed, path, auth)
        findings.append({
            "path": path, "label": label, "severity": severity, "status": status,
            "exposed": status == 200 and bool(signature.search(body)),
        })
    return findings


def _get_full(url, auth=None, extra_headers=None, cap=8192):
    """GET a URL -> (status, lowercased headers dict, body bytes capped)."""
    parsed = urlparse(url)
    conn = _connect(parsed)
    try:
        conn.request("GET", _path_of(parsed),
                     headers={"User-Agent": UA, **(auth or {}), **(extra_headers or {})})
        resp = conn.getresponse()
        headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, headers, resp.read(cap)
    except OSError:
        return None, {}, b""
    finally:
        conn.close()


# Signatures that betray a web framework running in debug mode on a public host.
DEBUG_SIGNATURES = [
    (re.compile(rb"Werkzeug Debugger"),                   "Werkzeug interactive debugger (Flask debug mode)"),
    (re.compile(rb"Traceback \(most recent call last\)"), "Python traceback exposed"),
    (re.compile(rb"DEBUG = True"),                         "Django debug page (DEBUG=True)"),
    (re.compile(rb"Django Version:"),                      "Django debug error page"),
]


def probe_misconfig(url, auth=None):
    """Active checks for common web misconfigurations on a staging host:
    clickjacking, CORS reflection, cookie flags, and framework debug mode."""
    findings = []
    parsed = urlparse(url)

    # 1. Clickjacking — no X-Frame-Options and no CSP frame-ancestors directive.
    _, headers, _ = _get_full(url, auth)
    xfo = headers.get("x-frame-options")
    csp = (headers.get("content-security-policy") or "").lower()
    framable = not xfo and "frame-ancestors" not in csp
    findings.append({
        "check": "Clickjacking protection", "severity": "medium",
        "status": "bad" if framable else "ok",
        "detail": "No X-Frame-Options or CSP frame-ancestors — page can be framed"
                  if framable else ("X-Frame-Options: " + xfo if xfo else "CSP frame-ancestors set"),
    })

    # 2. CORS — does the server reflect an arbitrary Origin? Worse with credentials.
    probe_origin = "https://evil.example"
    _, ch, _ = _get_full(url, auth, {"Origin": probe_origin})
    acao = ch.get("access-control-allow-origin")
    acac = (ch.get("access-control-allow-credentials") or "").lower() == "true"
    if acao in (probe_origin, "*"):
        findings.append({
            "check": "CORS policy",
            "severity": "high" if (acao == probe_origin and acac) else "medium",
            "status": "bad",
            "detail": f"Reflects arbitrary Origin ({acao})" + (" with credentials allowed" if acac else ""),
        })
    else:
        findings.append({"check": "CORS policy", "severity": "medium", "status": "ok",
                         "detail": "No arbitrary-origin reflection"})

    # 3. Cookie flags — reuse the URL Analyzer's Set-Cookie parser.
    cookies = get_cookies(url, auth)
    weak = [c["name"] for c in cookies if not (c["secure"] and c["httpOnly"])]
    if not cookies:
        findings.append({"check": "Cookie flags", "severity": "low", "status": "ok",
                         "detail": "No cookies set"})
    else:
        findings.append({
            "check": "Cookie flags", "severity": "medium",
            "status": "bad" if weak else "ok",
            "detail": (f"{len(weak)} cookie(s) missing Secure/HttpOnly: " + ", ".join(weak[:5]))
                      if weak else f"All {len(cookies)} cookie(s) Secure + HttpOnly",
        })

    # 4. Debug mode — force a 404 and look for framework debug pages.
    rnd = "/__secanalysis_probe_" + hashlib.sha1(url.encode()).hexdigest()[:8]
    _, _, body = _get_full(urljoin(f"{parsed.scheme}://{parsed.netloc}", rnd), auth)
    hit = next((label for sig, label in DEBUG_SIGNATURES if sig.search(body)), None)
    findings.append({
        "check": "Debug mode", "severity": "high",
        "status": "bad" if hit else "ok",
        "detail": hit if hit else "No framework debug output detected",
    })

    return findings


# ════════════════════════════════════════════════════════════════════════════
#  Repo Audit — gitleaks (secrets) + Trivy (vuln/misconfig/license/SBOM)
#  + hadolint (Dockerfiles) + zizmor (GitHub Actions) on a cloned repo
# ════════════════════════════════════════════════════════════════════════════
# Keep the input tight: only https clone URLs on known hosts. git/gitleaks/trivy
# are always invoked with an argument list (never a shell string).
REPO_RE = re.compile(r"^https://(github\.com|gitlab\.com)/[\w.-]+/[\w.-]+?(?:\.git)?$")


def is_valid_repo(url: str) -> bool:
    return bool(REPO_RE.match(url))


def scan_secrets(repo_dir: str, report_path: str) -> list:
    """Run gitleaks over a cloned repo. Returns findings with secrets redacted."""
    # gitleaks exits 1 when it finds leaks — that's a result, not an error, so we
    # don't check the return code and instead read the JSON report it writes.
    # Fall back to --no-git when the dir isn't a git repo (e.g. an exported tree).
    cmd = ["gitleaks", "detect", "--source", repo_dir, "--no-banner",
           "--report-format", "json", "--report-path", report_path]
    if not os.path.isdir(os.path.join(repo_dir, ".git")):
        cmd.append("--no-git")
    subprocess.run(cmd, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    try:
        with open(report_path) as fh:
            leaks = json.load(fh)
    except (OSError, json.JSONDecodeError):
        leaks = []
    return [{
        "rule": l.get("RuleID"),
        "file": l.get("File"),
        "line": l.get("StartLine"),
        "preview": (l.get("Secret") or "")[:4] + "…",   # never return the full secret
        "commit": (l.get("Commit") or "")[:10],
    } for l in leaks]


def _cvss_pick(cvss: dict):
    """Pick a single CVSS score + vector from Trivy's per-source CVSS map,
    preferring NVD, then Red Hat / GHSA, then whatever is present. Prefers v3."""
    for src in ("nvd", "redhat", "ghsa"):
        entry = cvss.get(src)
        if entry:
            return (entry.get("V3Score") or entry.get("V2Score"),
                    entry.get("V3Vector") or entry.get("V2Vector"))
    for entry in cvss.values():
        if entry:
            return (entry.get("V3Score") or entry.get("V2Score"),
                    entry.get("V3Vector") or entry.get("V2Vector"))
    return (None, None)


def scan_trivy(repo_dir: str) -> dict:
    """One Trivy filesystem pass for vuln + misconfig + license findings."""
    proc = subprocess.run(
        ["trivy", "fs", "--quiet", "--scanners", "vuln,misconfig,license",
         "--format", "json", repo_dir],
        capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    out = {"dependencies": [], "misconfigurations": [], "licenses": []}
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return out
    for res in data.get("Results") or []:
        target = res.get("Target", "")
        rtype = res.get("Type", "")
        for v in res.get("Vulnerabilities") or []:
            score, vector = _cvss_pick(v.get("CVSS") or {})
            out["dependencies"].append({
                "package": v.get("PkgName"),
                "version": v.get("InstalledVersion"),
                "fixedVersion": v.get("FixedVersion") or "",
                "id": v.get("VulnerabilityID"),
                "severity": (v.get("Severity") or "UNKNOWN").title(),
                "title": (v.get("Title") or "")[:160],
                # Extra detail surfaced in the in-app finding dialog.
                "description": (v.get("Description") or "")[:2000],
                "primaryUrl": v.get("PrimaryURL") or "",
                "references": (v.get("References") or [])[:25],
                "cweIDs": v.get("CweIDs") or [],
                "cvssScore": score,
                "cvssVector": vector,
                "publishedDate": v.get("PublishedDate") or "",
                "target": target,
            })
        for m in res.get("Misconfigurations") or []:
            cause = m.get("CauseMetadata") or {}
            out["misconfigurations"].append({
                "id": m.get("ID") or m.get("AVDID") or "",
                "title": m.get("Title", ""),
                "severity": (m.get("Severity") or "UNKNOWN").title(),
                "message": (m.get("Message") or "")[:200],
                "resolution": (m.get("Resolution") or "")[:160],
                "type": rtype,
                "target": target,
                "line": cause.get("StartLine"),
                # Extra detail surfaced in the in-app finding dialog.
                "description": (m.get("Description") or "")[:2000],
                "primaryUrl": m.get("PrimaryURL") or "",
                "references": (m.get("References") or [])[:25],
            })
        for lic in res.get("Licenses") or []:
            out["licenses"].append({
                "package": lic.get("PkgName") or lic.get("FilePath") or "",
                "name": lic.get("Name", ""),
                "category": (lic.get("Category") or "").replace("_", " ").title(),
                "severity": (lic.get("Severity") or "UNKNOWN").title(),
            })
    return out


def generate_sbom(repo_dir: str) -> dict:
    """Generate a CycloneDX SBOM of the repo's dependencies via Trivy."""
    proc = subprocess.run(
        ["trivy", "fs", "--quiet", "--format", "cyclonedx", repo_dir],
        capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    try:
        doc = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return {"componentCount": 0, "document": None}
    return {"format": doc.get("bomFormat", "CycloneDX"),
            "specVersion": doc.get("specVersion", ""),
            "componentCount": len(doc.get("components") or []),
            "document": doc}


def _find_dockerfiles(repo_dir: str, cap: int = 25) -> list:
    """Locate Dockerfiles, skipping .git. Capped so a pathological repo can't
    spawn hundreds of linter runs."""
    found = []
    for root, dirs, files in os.walk(repo_dir):
        if ".git" in dirs:
            dirs.remove(".git")
        for fn in files:
            low = fn.lower()
            if low == "dockerfile" or low.startswith("dockerfile.") or low.endswith(".dockerfile"):
                found.append(os.path.join(root, fn))
                if len(found) >= cap:
                    return found
    return found


def lint_dockerfiles(repo_dir: str) -> list:
    """Run hadolint over every Dockerfile in the repo."""
    findings = []
    for path in _find_dockerfiles(repo_dir):
        proc = subprocess.run(
            ["hadolint", "--format", "json", "--no-color", path],
            capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        try:
            items = json.loads(proc.stdout or "[]")
        except json.JSONDecodeError:
            items = []
        rel = os.path.relpath(path, repo_dir)
        for it in items:
            findings.append({
                "file": rel,
                "line": it.get("line"),
                "level": (it.get("level") or "").title(),
                "code": it.get("code", ""),
                "message": (it.get("message") or "")[:200],
            })
    return findings


def audit_actions(repo_dir: str) -> list:
    """Run zizmor (offline) over .github/workflows -> SARIF -> findings."""
    workflows = os.path.join(repo_dir, ".github", "workflows")
    if not os.path.isdir(workflows):
        return []
    proc = subprocess.run(
        ["zizmor", "--offline", "--format", "sarif", workflows],
        capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    try:
        sarif = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        return []
    findings = []
    for run in sarif.get("runs") or []:
        for r in run.get("results") or []:
            loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
            findings.append({
                "rule": (r.get("ruleId") or "").replace("zizmor/", ""),
                "level": (r.get("level") or "warning").title(),
                "message": (r.get("message", {}).get("text") or "")[:200],
                "file": loc.get("artifactLocation", {}).get("uri", ""),
                "line": loc.get("region", {}).get("startLine"),
            })
    return findings


def scan_path(repo_dir: str) -> dict:
    """Run every scanner against a directory. The gitleaks report goes to a
    throwaway temp dir, so this works even when repo_dir is mounted read-only."""
    with tempfile.TemporaryDirectory() as tmp:
        secrets = scan_secrets(repo_dir, os.path.join(tmp, "leaks.json"))
    trivy = scan_trivy(repo_dir)
    return {
        "secrets": secrets,
        "dependencies": trivy["dependencies"],
        "misconfigurations": trivy["misconfigurations"],
        "licenses": trivy["licenses"],
        "dockerfile": lint_dockerfiles(repo_dir),
        "actions": audit_actions(repo_dir),
        "sbom": generate_sbom(repo_dir),
    }


def audit_repo(repo_url: str) -> dict:
    """Shallow-clone a remote repo into a temp dir, then scan it."""
    with tempfile.TemporaryDirectory() as tmp:
        repo_dir = os.path.join(tmp, "repo")
        clone = subprocess.run(
            ["git", "clone", "--depth", "1", "--no-tags", repo_url, repo_dir],
            capture_output=True, text=True, timeout=SCAN_TIMEOUT)
        if clone.returncode != 0:
            return {"error": clone.stderr.strip()[:500] or "git clone failed"}
        return scan_path(repo_dir)


def _resolve_local_repo(name: str):
    """Resolve a user-supplied local repo name under AUDIT_ROOT, blocking path
    traversal. Returns the absolute path, or None if invalid / not a directory."""
    if not name:
        return None
    root = os.path.realpath(AUDIT_ROOT)
    target = os.path.realpath(os.path.join(root, name))
    if target != root and not target.startswith(root + os.sep):
        return None
    return target if os.path.isdir(target) else None


def list_local_repos() -> list:
    """Immediate sub-directories of AUDIT_ROOT, each tagged with whether it's a git repo."""
    root = os.path.realpath(AUDIT_ROOT)
    if not os.path.isdir(root):
        return []
    repos = []
    for entry in sorted(os.listdir(root)):
        path = os.path.join(root, entry)
        if os.path.isdir(path):
            repos.append({"name": entry, "git": os.path.isdir(os.path.join(path, ".git"))})
    return repos


# ════════════════════════════════════════════════════════════════════════════
#  Routes
# ════════════════════════════════════════════════════════════════════════════
@app.before_request
def _csrf_guard():
    """No cookies/auth here, but still block cross-origin state-changing calls so
    a malicious page can't drive the tool from the user's browser (CSRF)."""
    if request.method in ("POST", "PUT", "PATCH", "DELETE"):
        origin = request.headers.get("Origin")
        if origin and urlparse(origin).netloc != request.host:
            return jsonify({"error": "Cross-origin request blocked"}), 403


@app.after_request
def _security_headers(resp):
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    return resp


@app.route("/healthz")
def healthz():
    return jsonify({"status": "ok", "version": APP_VERSION})


@app.route("/")
def index():
    return render_template("index.html", version=APP_VERSION)


@app.route("/api/scan", methods=["POST"])
def scan():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()

    if not is_valid_target(target):
        return jsonify({"error": "Enter a valid IP address or hostname."}), 400
    if not shutil.which("nmap"):
        return jsonify({"error": "nmap is not installed in this container."}), 500

    opts = {
        "ports":     data.get("ports", "standard"),
        "sV":        bool(data.get("sV")),
        "os":        bool(data.get("os")),
        "scripts":   bool(data.get("scripts")),
        "skip_ping": bool(data.get("skip_ping")),
    }

    dns_info = resolve(target)
    args = build_nmap_args(target, opts)

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Scan timed out after {SCAN_TIMEOUT}s. Try a smaller port range.",
                        "command": " ".join(args)}), 504

    if not proc.stdout.strip():
        return jsonify({"error": (proc.stderr.strip() or "nmap returned no output."),
                        "command": " ".join(args)}), 500

    try:
        result = parse_nmap_xml(proc.stdout)
    except ET.ParseError:
        return jsonify({"error": "Could not parse nmap output.",
                        "command": " ".join(args), "raw": proc.stdout[:4000]}), 500

    return jsonify({"dns": dns_info, "result": result,
                    "command": " ".join(args), "stderr": proc.stderr.strip()})


def run_subnet_sweep(cidr: str):
    """Sweep a subnet for live hosts. Returns (payload, error_payload, status) —
    exactly one of payload / error_payload is set. Shared by the live scan
    endpoint and by refreshing a saved scan, so both produce the same shape."""
    net, err = validate_subnet(cidr)
    if err:
        return None, {"error": err}, 400
    if not shutil.which("nmap"):
        return None, {"error": "nmap is not installed in this container."}, 500

    # -sn = host discovery only (ARP on the local segment, ICMP/TCP otherwise),
    # no port scan. This is the fast "which machines are alive?" sweep.
    args = ["nmap", "-sn", "-oX", "-", "--reason", "-T4", str(net)]

    try:
        proc = subprocess.run(args, capture_output=True, text=True, timeout=SCAN_TIMEOUT)
    except subprocess.TimeoutExpired:
        return None, {"error": f"Subnet scan timed out after {SCAN_TIMEOUT}s. Try a smaller subnet.",
                      "command": " ".join(args)}, 504

    if not proc.stdout.strip():
        return None, {"error": (proc.stderr.strip() or "nmap returned no output."),
                      "command": " ".join(args)}, 500

    try:
        hosts = parse_nmap_hosts_xml(proc.stdout)
    except ET.ParseError:
        return None, {"error": "Could not parse nmap output.",
                      "command": " ".join(args), "raw": proc.stdout[:4000]}, 500

    return {"subnet": str(net), "hosts": hosts, "count": len(hosts),
            "command": " ".join(args), "stderr": proc.stderr.strip()}, None, 200


@app.route("/api/subnet", methods=["POST"])
def subnet_scan():
    data = request.get_json(silent=True) or {}
    payload, err, status = run_subnet_sweep((data.get("subnet") or "").strip())
    return jsonify(err or payload), status


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    do_port_scan = bool(data.get("portScan"))
    do_dns_auth = bool(data.get("dnsAuth"))
    auth = _basic_auth_header((data.get("username") or "").strip(), data.get("password") or "")

    if not url:
        return jsonify({"error": "URL is required"}), 400
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return jsonify({"error": "Enter a valid http:// or https:// URL"}), 400

    try:
        ip_address = socket.gethostbyname(parsed.hostname)
    except OSError:
        ip_address = "Unable to resolve"

    try:
        t0 = time.perf_counter()
        status, headers = head_request(url, auth)
        response_ms = round((time.perf_counter() - t0) * 1000)
    except OSError as e:
        status, headers, response_ms = None, {}, None
        app.logger.warning("HEAD failed: %s", e)

    security_headers = {label: headers.get(key, "Not found")
                        for label, key in SECURITY_HEADERS.items()}

    cert_info = (get_certificate_info(parsed.hostname, parsed.port or 443)
                 if parsed.scheme == "https" else None)

    port_scan = None
    if do_port_scan and ip_address != "Unable to resolve":
        port_scan = nmap_port_scan(ip_address)

    dmarc = get_dmarc(parsed.hostname) if do_dns_auth else None
    dnssec = get_dnssec(parsed.hostname) if do_dns_auth else None
    email_sec = get_email_security(parsed.hostname) if do_dns_auth else {}

    redirect_chain = get_redirect_chain(url, auth)
    final_url = next((h["url"] for h in reversed(redirect_chain)
                      if h.get("url") and not h.get("error")), url)
    page_html = fetch_page_html(final_url, auth)

    result = {
        "url": url,
        "ipAddress": ip_address,
        "statusCode": status,
        "responseTimeMs": response_ms,
        "server": headers.get("server", "Not disclosed"),
        "securityHeaders": security_headers,
        "cspAnalysis": analyze_csp(security_headers.get("Content-Security-Policy")),
        "hstsAnalysis": analyze_hsts(security_headers.get("Strict-Transport-Security")),
        "securityTxt": fetch_text_file(parsed, "/.well-known/security.txt", auth),
        "robotsTxt": fetch_text_file(parsed, "/robots.txt", auth),
        "certInfo": cert_info,
        "dnsRecords": get_dns_records(parsed.hostname),
        "dmarc": dmarc,
        "dnssec": dnssec,
        "spf": email_sec.get("spf"),
        "dkim": email_sec.get("dkim"),
        "mtaSts": email_sec.get("mtaSts"),
        "tlsRpt": email_sec.get("tlsRpt"),
        "redirectChain": redirect_chain,
        "redirectIssues": analyze_redirects(redirect_chain),
        "httpsRedirect": get_https_redirect(parsed.hostname),
        "pageContent": analyze_page_content(page_html, final_url),
        "cookies": get_cookies(url, auth),
        "portScan": port_scan,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    result["scorecard"] = grade_analysis(result)
    return jsonify(result)


@app.route("/api/subdomains", methods=["POST"])
def subdomains():
    data = request.get_json(silent=True) or {}
    payload, err, status = run_subdomain_scan((data.get("domain") or "").strip())
    return jsonify(err or payload), status


def run_subdomain_scan(domain: str):
    """Discover subdomains. Returns (payload, error_payload, status) — the same
    contract as run_subnet_sweep, so saved scans can refresh either tool."""
    if not domain:
        return None, {"error": "Domain is required"}, 400
    if not is_valid_domain(domain):
        return None, {"error": "Enter a valid domain, e.g. example.com"}, 400
    result = find_subdomains(domain)
    # find_subdomains reports total source failure in-band rather than raising.
    if result.get("error"):
        return None, {"error": result["error"]}, 502
    return result, None, 200


def _live_http(url: str, timeout: int = 6) -> dict:
    """Probe one URL. A host that answers with an HTTP error status (404/500…)
    is still alive, so those count as 'responded' with the returned code."""
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    start = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ms = int((time.perf_counter() - start) * 1000)
            return {"responded": True, "code": resp.status, "finalUrl": resp.geturl(),
                    "server": resp.headers.get("Server", ""), "latencyMs": ms}
    except urllib.error.HTTPError as e:
        ms = int((time.perf_counter() - start) * 1000)
        return {"responded": True, "code": e.code,
                "finalUrl": getattr(e, "url", url) or url,
                "server": (e.headers.get("Server", "") if e.headers else ""), "latencyMs": ms}
    except Exception as e:
        return {"responded": False, "error": type(e).__name__}


def _live_icmp(host: str) -> dict:
    """ICMP echo: reachable + round-trip time (needs NET_RAW, already granted)."""
    try:
        proc = subprocess.run(["ping", "-c", "1", "-W", "3", host],
                              capture_output=True, text=True, timeout=8)
        if proc.returncode != 0:
            return {"reachable": False}
        m = re.search(r"time[=<]\s*([\d.]+)\s*ms", proc.stdout)
        return {"reachable": True, "rttMs": float(m.group(1)) if m else None}
    except Exception:
        return {"reachable": False}


def check_subdomain_live(name: str) -> dict:
    """Combined liveness probe for one host: DNS + ICMP + HTTPS + HTTP. The three
    network probes run concurrently so the whole check stays snappy."""
    out = {"name": name, "ip": None, "icmp": None, "https": None, "http": None}
    try:
        out["ip"] = socket.gethostbyname(name)
    except Exception:
        out["ip"] = None
    probes = {"icmp": (_live_icmp, name),
              "https": (_live_http, "https://" + name),
              "http": (_live_http, "http://" + name)}
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as ex:
        futs = {k: ex.submit(fn, arg) for k, (fn, arg) in probes.items()}
        for k, fut in futs.items():
            try:
                out[k] = fut.result(timeout=12)
            except Exception as e:
                out[k] = {"error": type(e).__name__}
    return out


@app.route("/api/subdomain-live", methods=["POST"])
def subdomain_live():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip().lower().rstrip(".")
    if not name or not is_valid_domain(name):
        return jsonify({"error": "Enter a valid hostname"}), 400
    return jsonify(check_subdomain_live(name))


@app.route("/api/exposures", methods=["POST"])
def exposures():
    data = request.get_json(silent=True) or {}
    url = (data.get("url") or "").strip()
    auth = _basic_auth_header((data.get("username") or "").strip(), data.get("password") or "")

    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        return jsonify({"error": "Enter a valid http:// or https:// URL"}), 400

    findings = probe_exposures(url, auth)
    misconfig = probe_misconfig(url, auth)
    return jsonify({
        "url": url,
        "findings": findings,
        "exposedCount": sum(f["exposed"] for f in findings),
        "misconfig": misconfig,
        "misconfigCount": sum(1 for m in misconfig if m["status"] == "bad"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


@app.route("/api/local-repos")
def local_repos():
    return jsonify({"root": AUDIT_ROOT,
                    "mounted": os.path.isdir(AUDIT_ROOT),
                    "repos": list_local_repos()})


@app.route("/api/repo-audit", methods=["POST"])
def repo_audit():
    data = request.get_json(silent=True) or {}
    repo = (data.get("repo") or "").strip()
    local = (data.get("local") or "").strip()

    for tool in ("gitleaks", "trivy"):
        if not shutil.which(tool):
            return jsonify({"error": f"{tool} is not installed in this container."}), 500

    if local:
        repo_dir = _resolve_local_repo(local)
        if not repo_dir:
            return jsonify({"error": "Unknown local clone — pick one from the mounted "
                                     "audit folder."}), 400
        source = local
    elif repo:
        if not is_valid_repo(repo):
            return jsonify({"error": "Enter an https github.com / gitlab.com repository URL."}), 400
        if not shutil.which("git"):
            return jsonify({"error": "git is not installed in this container."}), 500
        source = repo
    else:
        return jsonify({"error": "Provide a repository URL or pick a local clone."}), 400

    try:
        result = scan_path(repo_dir) if local else audit_repo(repo)
    except subprocess.TimeoutExpired:
        return jsonify({"error": f"Repo audit timed out after {SCAN_TIMEOUT}s.",
                        "repo": source}), 504

    if "error" in result:
        return jsonify({**result, "repo": source}), 502

    return jsonify({
        "repo": source,
        "secrets": result["secrets"],
        "dependencies": result["dependencies"],
        "misconfigurations": result["misconfigurations"],
        "licenses": result["licenses"],
        "dockerfile": result["dockerfile"],
        "actions": result["actions"],
        "sbom": result["sbom"],
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })


# ════════════════════════════════════════════════════════════════════════════
#  Console — a fixed menu of read-only network commands
# ════════════════════════════════════════════════════════════════════════════
# This is deliberately *not* a shell. The user picks a tool from this table and
# supplies exactly one target; every flag is fixed here, server-side. Letting a
# caller pass their own flags is what would turn these harmless-looking tools
# into a foothold: `ping -f` floods, `dig -f` reads a file of queries, and
# whois' `-h` redirects the query to an attacker's server. So the argv list
# below is the entire vocabulary — the only thing that varies is the target,
# which must satisfy is_valid_target() (no leading dash, no shell characters).
# Commands run via an argument list, never a shell string, so nothing here is
# ever parsed by a shell.
#
# Adding a tool: keep it read-only, pin every flag, and make sure it cannot be
# talked into writing a file or reaching a host other than `target`.
CONSOLE_TOOLS = {
    "ping": {
        "argv": ["ping", "-n", "-c", "4", "-W", "3"],
        "timeout": 25,
        "label": "ping",
        "hint": "4 ICMP echo requests",
    },
    "traceroute": {
        "argv": ["traceroute", "-n", "-w", "2", "-q", "1", "-m", "20"],
        "timeout": 70,
        "label": "traceroute",
        "hint": "Hop-by-hop path, max 20 hops",
    },
    "dig": {
        "argv": ["dig", "+noall", "+answer", "+comments", "+tries=1", "+time=3"],
        "timeout": 20,
        "label": "dig",
        "hint": "DNS lookup for one record type",
    },
    "whois": {
        "argv": ["whois", "--"],
        "timeout": 40,
        "label": "whois",
        "hint": "Registration record",
    },
}

# Record types offered for `dig`. Allowlisted for the same reason the flags are:
# the value is appended to dig's argv, so it must never be caller-controlled text.
CONSOLE_DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "SOA", "CNAME", "PTR", "CAA")

# whois records in particular can run long; cap what we buffer and return.
CONSOLE_MAX_OUTPUT = 64 * 1024


def _console_text(chunk) -> str:
    """Normalise a captured stream to text. On timeout the partial output can be
    bytes, str, or None depending on how far the child got."""
    if chunk is None:
        return ""
    if isinstance(chunk, bytes):
        return chunk.decode("utf-8", "replace")
    return chunk


def run_console_tool(tool: str, target: str, record_type: str = "A"):
    """Run one allowlisted tool against one target. Returns (payload, error)."""
    spec = CONSOLE_TOOLS.get(tool)
    if not spec:
        return None, "Unknown tool"
    if not is_valid_target(target):
        return None, "Target must be a valid hostname or IP address"

    argv = list(spec["argv"]) + [target]
    if tool == "dig":
        rtype = (record_type or "A").strip().upper()
        if rtype not in CONSOLE_DNS_TYPES:
            return None, "Record type must be one of: " + ", ".join(CONSOLE_DNS_TYPES)
        argv.append(rtype)

    start = time.perf_counter()
    timed_out = False
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=spec["timeout"])
        output, code = proc.stdout + proc.stderr, proc.returncode
    except subprocess.TimeoutExpired as e:
        output, code, timed_out = _console_text(e.stdout) + _console_text(e.stderr), None, True
    except FileNotFoundError:
        return None, "%s is not installed in this container" % tool

    if len(output) > CONSOLE_MAX_OUTPUT:
        output = output[:CONSOLE_MAX_OUTPUT] + "\n… output truncated"
    if timed_out:
        output = (output.rstrip("\n") + "\n\n" if output.strip() else "")
        output += "… timed out after %ss" % spec["timeout"]

    return {
        # Echo back the exact argv we ran, so the pane can show the real command
        # rather than something reassembled (and misleading) in the browser.
        "command": " ".join(argv),
        "output": output,
        "exitCode": code,
        "timedOut": timed_out,
        "durationMs": int((time.perf_counter() - start) * 1000),
    }, None


@app.route("/api/console/tools")
def console_tools():
    """The menu the dialog renders. Sourced from CONSOLE_TOOLS so the UI can
    never offer a tool the server wouldn't run."""
    return jsonify({
        "tools": [{"id": k, "label": v["label"], "hint": v["hint"],
                   "argv": " ".join(v["argv"])}
                  for k, v in CONSOLE_TOOLS.items()],
        "dnsTypes": list(CONSOLE_DNS_TYPES),
    })


@app.route("/api/console", methods=["POST"])
def console_run():
    data = request.get_json(silent=True) or {}
    payload, err = run_console_tool(
        (data.get("tool") or "").strip().lower(),
        (data.get("target") or "").strip(),
        data.get("recordType") or "A",
    )
    if err:
        return jsonify({"error": err}), 400
    return jsonify(payload)


# ════════════════════════════════════════════════════════════════════════════
#  Availability Dashboard — persisted monitors + background checks
# ════════════════════════════════════════════════════════════════════════════
DB_PATH = os.environ.get("DB_PATH", "/data/secanalysis.db")
SCHED_TICK = int(os.environ.get("SCHED_TICK", "10"))   # seconds between scheduler ticks
MIN_INTERVAL = 30
MAX_INTERVAL = 86400
HISTORY_PER_MONITOR = 200
EVENTS_KEEP = 200
CHECK_TYPES = ("http", "tcp", "icmp", "api")

# Saved-report history. Reports live as HTML files on the writable data volume
# under HISTORY_DIR/<tool>/; the DB holds each one's metadata for listing.
HISTORY_DIR = os.environ.get("HISTORY_DIR", os.path.join(os.path.dirname(DB_PATH) or ".", "history"))
REPORT_TOOLS = ("netscan", "subnet", "url", "exposure", "repo", "subdomains")
MAX_REPORT_BYTES = 8 * 1024 * 1024
_SLUG_RE = re.compile(r"[^a-z0-9.-]+")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS monitors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  type TEXT NOT NULL,
  target TEXT NOT NULL,
  port INTEGER,
  expected_status INTEGER,
  expected_keyword TEXT,
  auth_header TEXT,
  interval_seconds INTEGER NOT NULL DEFAULT 300,
  enabled INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL,
  last_status TEXT NOT NULL DEFAULT 'unknown',
  last_checked TEXT,
  last_latency_ms INTEGER,
  last_error TEXT,
  last_changed TEXT
);
CREATE TABLE IF NOT EXISTS checks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id INTEGER NOT NULL,
  ts TEXT NOT NULL,
  status TEXT NOT NULL,
  latency_ms INTEGER,
  detail TEXT
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  monitor_id INTEGER NOT NULL,
  ts TEXT NOT NULL,
  from_status TEXT,
  to_status TEXT NOT NULL,
  name TEXT
);
CREATE TABLE IF NOT EXISTS history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tool TEXT NOT NULL,
  filename TEXT NOT NULL,
  target TEXT,
  label TEXT,
  size INTEGER,
  created_at TEXT NOT NULL
);
-- Saved scans, one row per saved result of any tool that supports saving (see
-- SAVED_SCAN_TOOLS). `data` is the exact payload that tool's live endpoint
-- returns, as JSON, so reopening a saved scan re-renders through the same
-- front-end path as a live one. new_keys / gone_items hold the last refresh's
-- diff — both bounded, since they're recomputed from scratch on every refresh
-- rather than accumulated.
CREATE TABLE IF NOT EXISTS saved_scans (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tool TEXT NOT NULL,
  name TEXT NOT NULL,
  target TEXT NOT NULL,
  data TEXT NOT NULL,
  new_keys TEXT NOT NULL DEFAULT '[]',
  gone_items TEXT NOT NULL DEFAULT '[]',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  last_refreshed TEXT
);
-- (idx_saved_scans_tool is created in init_db, after the migration below has
-- had a chance to add `tool` to a pre-existing table.)
-- Free-text notes, scoped to one host within one saved scan: the same IP (or
-- name) in two saved scans is two different machines, so notes must not
-- collide. Deliberately keyed on (scan_id, host) rather than on a row of
-- `data`, so a note survives its host dropping out of a refresh and coming back.
CREATE TABLE IF NOT EXISTS host_notes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  scan_id INTEGER NOT NULL,
  host TEXT NOT NULL,
  note TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(scan_id, host)
);
CREATE INDEX IF NOT EXISTS idx_host_notes_scan ON host_notes(scan_id);
"""


def get_db():
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db():
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    os.makedirs(HISTORY_DIR, exist_ok=True)
    conn = get_db()
    try:
        conn.execute("PRAGMA journal_mode=WAL")
        conn.executescript(_SCHEMA)
        # Migration: add the optional custom label to pre-existing history tables.
        cols = [r[1] for r in conn.execute("PRAGMA table_info(history)").fetchall()]
        if "label" not in cols:
            conn.execute("ALTER TABLE history ADD COLUMN label TEXT")

        # Migration: saved scans began as a subnet-only feature, so the first
        # version of these tables was named for subnets (cidr / ip / new_ips /
        # gone_hosts). They now hold any tool's scans. Renaming in place keeps
        # existing saved scans and their notes; the CREATEs above are no-ops on
        # a DB that already has the old shape, so this is what actually converts
        # it. RENAME COLUMN needs SQLite >= 3.25 (we ship 3.46).
        cols = [r[1] for r in conn.execute("PRAGMA table_info(saved_scans)").fetchall()]
        if "cidr" in cols:
            conn.execute("ALTER TABLE saved_scans RENAME COLUMN cidr TO target")
        if "new_ips" in cols:
            conn.execute("ALTER TABLE saved_scans RENAME COLUMN new_ips TO new_keys")
        if "gone_hosts" in cols:
            conn.execute("ALTER TABLE saved_scans RENAME COLUMN gone_hosts TO gone_items")
        if "tool" not in cols:
            # Everything saved before this column existed was a subnet scan.
            conn.execute("ALTER TABLE saved_scans ADD COLUMN tool TEXT NOT NULL DEFAULT 'subnet'")

        note_cols = [r[1] for r in conn.execute("PRAGMA table_info(host_notes)").fetchall()]
        if "ip" in note_cols:
            # SQLite carries the UNIQUE(scan_id, ip) constraint across the rename.
            conn.execute("ALTER TABLE host_notes RENAME COLUMN ip TO host")

        # Only safe once `tool` is guaranteed to exist, hence not in _SCHEMA.
        conn.execute("CREATE INDEX IF NOT EXISTS idx_saved_scans_tool ON saved_scans(tool)")
        conn.commit()
    finally:
        conn.close()


def _safe_slug(s: str) -> str:
    return (_SLUG_RE.sub("-", (s or "").lower()).strip("-")[:80]) or "report"


def _resolve_history_file(tool: str, name: str):
    """Map (tool, filename) to a real path strictly under HISTORY_DIR/<tool>/,
    blocking path traversal. Returns None if invalid."""
    if tool not in REPORT_TOOLS:
        return None
    base = os.path.basename(name or "")
    if not base.endswith(".html") or base.startswith("."):
        return None
    root = os.path.realpath(os.path.join(HISTORY_DIR, tool))
    path = os.path.realpath(os.path.join(root, base))
    if path != root and not path.startswith(root + os.sep):
        return None
    return path


@app.route("/api/history", methods=["GET"])
def history_list():
    tool = request.args.get("tool")
    conn = get_db()
    try:
        if tool in REPORT_TOOLS:
            rows = conn.execute("SELECT * FROM history WHERE tool=? ORDER BY created_at DESC",
                                (tool,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM history ORDER BY created_at DESC").fetchall()
    finally:
        conn.close()
    items = [{"id": r["id"], "tool": r["tool"], "filename": r["filename"],
              "target": r["target"], "label": r["label"], "size": r["size"],
              "createdAt": r["created_at"]}
             for r in rows]
    return jsonify({"items": items, "tools": REPORT_TOOLS})


@app.route("/api/history", methods=["POST"])
def history_add():
    data = request.get_json(silent=True) or {}
    tool = (data.get("tool") or "").strip()
    html = data.get("html") or ""
    target = (data.get("target") or "").strip()[:200]
    if tool not in REPORT_TOOLS:
        return jsonify({"error": "Unknown tool"}), 400
    if not isinstance(html, str) or not html.strip():
        return jsonify({"error": "Empty report"}), 400
    if len(html.encode("utf-8")) > MAX_REPORT_BYTES:
        return jsonify({"error": "Report too large"}), 413
    tool_dir = os.path.join(HISTORY_DIR, tool)
    os.makedirs(tool_dir, exist_ok=True)
    ts = datetime.now(timezone.utc)
    fname = "secanalysis-%s-%s-%s.html" % (tool, _safe_slug(target or tool),
                                           ts.strftime("%Y-%m-%d-%H%M%S"))
    path = os.path.join(tool_dir, fname)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(html)
    size = os.path.getsize(path)
    conn = get_db()
    try:
        conn.execute("INSERT INTO history (tool, filename, target, size, created_at) "
                     "VALUES (?,?,?,?,?)", (tool, fname, target, size, ts.isoformat()))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True, "tool": tool, "filename": fname,
                    "target": target, "size": size, "createdAt": ts.isoformat()})


@app.route("/api/history/<tool>/<path:name>", methods=["GET"])
def history_get(tool, name):
    path = _resolve_history_file(tool, name)
    if not path or not os.path.isfile(path):
        return jsonify({"error": "Not found"}), 404
    with open(path, "r", encoding="utf-8") as fh:
        html = fh.read()
    resp = app.response_class(html, mimetype="text/html")
    # Stored reports are self-contained (inline CSS only). Serve them with a
    # locked-down CSP so an opened report can never run scripts or fetch remotely.
    resp.headers["Content-Security-Policy"] = ("default-src 'none'; style-src 'unsafe-inline'; "
                                               "img-src data:; font-src data:")
    if request.args.get("download"):
        resp.headers["Content-Disposition"] = 'attachment; filename="%s"' % os.path.basename(path)
    return resp


@app.route("/api/history/<tool>/<path:name>", methods=["PATCH"])
def history_rename(tool, name):
    if not _resolve_history_file(tool, name):
        return jsonify({"error": "Invalid path"}), 400
    data = request.get_json(silent=True) or {}
    label = (data.get("label") or "").strip()[:120]
    conn = get_db()
    try:
        cur = conn.execute("UPDATE history SET label=? WHERE tool=? AND filename=?",
                           (label or None, tool, os.path.basename(name)))
        conn.commit()
    finally:
        conn.close()
    if not cur.rowcount:
        return jsonify({"error": "Not found"}), 404
    return jsonify({"ok": True, "label": label})


@app.route("/api/history/<tool>/<path:name>", methods=["DELETE"])
def history_delete(tool, name):
    path = _resolve_history_file(tool, name)
    if not path:
        return jsonify({"error": "Invalid path"}), 400
    if os.path.isfile(path):
        os.remove(path)
    conn = get_db()
    try:
        conn.execute("DELETE FROM history WHERE tool=? AND filename=?",
                     (tool, os.path.basename(path)))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


# ════════════════════════════════════════════════════════════════════════════
#  Saved scans — re-openable, refreshable, annotatable
# ════════════════════════════════════════════════════════════════════════════
# Unlike report history (frozen HTML), a saved scan stores the tool's own JSON
# payload, so the UI replays it through that tool's normal render path and every
# row action keeps working. Refreshing re-runs the tool against the stored target
# and diffs against the previous run; the scan keeps its id, so notes survive.
#
# Everything below is tool-agnostic. A tool opts in by adding an entry to
# SAVED_SCAN_TOOLS:
#   target_of  payload            -> the target it was run against
#   validate   raw target         -> (canonical target, error)
#   clean      (payload, target)  -> just the fields we store (never trust the
#                                    client's extras — the payload round-trips
#                                    through the browser before being saved)
#   sweep      target             -> (payload, error_payload, status), i.e. the
#                                    same contract the live endpoints use
#   items      payload            -> the list that diffs and notes are keyed on
#   key        item               -> that item's stable identity
MAX_SCAN_NAME = 80
MAX_NOTE_CHARS = 4000


def _validate_subnet_target(raw):
    net, err = validate_subnet((raw or "").strip())
    return (None, err) if err else (str(net), None)


def _validate_domain_target(raw):
    domain = (raw or "").strip().lower().rstrip(".")
    if not domain or not is_valid_domain(domain):
        return None, "Enter a valid domain, e.g. example.com"
    return domain, None


def _clean_subnet_result(data, target):
    hosts = [{"ip": h.get("ip"), "hostname": h.get("hostname"), "mac": h.get("mac"),
              "vendor": h.get("vendor"), "reason": h.get("reason", "")}
             for h in data.get("hosts", []) if isinstance(h, dict)]
    return {"subnet": target, "hosts": hosts, "count": len(hosts),
            "command": str(data.get("command") or ""),
            "stderr": str(data.get("stderr") or "")}


def _clean_subdomain_result(data, target):
    names = [{"name": n.get("name"), "resolves": bool(n.get("resolves")),
              "addresses": [str(a) for a in (n.get("addresses") or [])]}
             for n in data.get("names", []) if isinstance(n, dict) and n.get("name")]
    return {"domain": target, "names": names, "count": len(names),
            "resolvingCount": sum(1 for n in names if n["resolves"]),
            "truncated": bool(data.get("truncated")),
            "sources": [str(s) for s in (data.get("sources") or [])]}


SAVED_SCAN_TOOLS = {
    "subnet": {
        "items_key": "hosts",
        "target_of": lambda d: (d.get("subnet") or "").strip(),
        "validate": _validate_subnet_target,
        "clean": _clean_subnet_result,
        # Wrapped rather than referenced directly so the name is resolved when the
        # refresh runs, not when this dict is built — otherwise the entry pins the
        # original function object and no later rebinding (a test double, say) is
        # ever seen.
        "sweep": lambda target: run_subnet_sweep(target),
        "items": lambda d: d.get("hosts", []),
        "key": lambda i: i.get("ip"),
    },
    "subdomains": {
        "items_key": "names",
        "target_of": lambda d: (d.get("domain") or "").strip(),
        "validate": _validate_domain_target,
        "clean": _clean_subdomain_result,
        "sweep": lambda target: run_subdomain_scan(target),
        "items": lambda d: d.get("names", []),
        "key": lambda i: i.get("name"),
    },
}


def _scan_row(r, with_data=False):
    spec = SAVED_SCAN_TOOLS.get(r["tool"])
    data = json.loads(r["data"])
    d = {
        "id": r["id"], "tool": r["tool"], "name": r["name"], "target": r["target"],
        "createdAt": r["created_at"], "updatedAt": r["updated_at"],
        "lastRefreshed": r["last_refreshed"],
        "itemCount": len(spec["items"](data)) if spec else 0,
    }
    if with_data:
        d["data"] = data
        d["newKeys"] = json.loads(r["new_keys"])
        d["goneItems"] = json.loads(r["gone_items"])
    return d


def _notes_for(conn, scan_id):
    rows = conn.execute("SELECT host, note, updated_at FROM host_notes WHERE scan_id=?",
                        (scan_id,)).fetchall()
    return {r["host"]: {"note": r["note"], "updatedAt": r["updated_at"]} for r in rows}


def _diff_items(old_items, new_items, key):
    """(new_keys, gone_items) between two runs against the same target. Gone
    entries are returned whole, not just as keys, so the UI can still show their
    details (a host's MAC, a subdomain's addresses)."""
    old_keys = {key(i) for i in old_items if key(i)}
    new_keys = {key(i) for i in new_items if key(i)}
    return (sorted(new_keys - old_keys),
            [i for i in old_items if key(i) and key(i) not in new_keys])


def _get_scan(conn, sid):
    return conn.execute("SELECT * FROM saved_scans WHERE id=?", (sid,)).fetchone()


def _known_keys(spec, row):
    """Every item key this scan currently shows — live rows plus the ones that
    went away in the last refresh (still rendered, greyed out). Notes are limited
    to these so a scan can't accumulate keys for hosts it never saw."""
    keys = {spec["key"](i) for i in spec["items"](json.loads(row["data"]))}
    keys |= {spec["key"](i) for i in json.loads(row["gone_items"])}
    return {k for k in keys if k}


@app.route("/api/saved-scans", methods=["GET"])
def list_saved_scans():
    tool = (request.args.get("tool") or "").strip()
    if tool and tool not in SAVED_SCAN_TOOLS:
        return jsonify({"error": "Unknown tool"}), 400
    conn = get_db()
    try:
        if tool:
            rows = conn.execute("SELECT * FROM saved_scans WHERE tool=? "
                                "ORDER BY name COLLATE NOCASE", (tool,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM saved_scans "
                                "ORDER BY name COLLATE NOCASE").fetchall()
        return jsonify({"scans": [_scan_row(r) for r in rows]})
    finally:
        conn.close()


@app.route("/api/saved-scans", methods=["POST"])
def create_saved_scan():
    """Persist a result the browser has already fetched, so saving costs no re-run."""
    body = request.get_json(silent=True) or {}
    tool = (body.get("tool") or "").strip()
    spec = SAVED_SCAN_TOOLS.get(tool)
    if not spec:
        return jsonify({"error": "Unknown tool"}), 400
    name = (body.get("name") or "").strip()[:MAX_SCAN_NAME]
    data = body.get("data")
    if not name:
        return jsonify({"error": "Name is required"}), 400
    if not isinstance(data, dict) or not isinstance(data.get(spec["items_key"]), list):
        return jsonify({"error": "A scan result is required"}), 400

    target, err = spec["validate"](spec["target_of"](data))
    if err:
        return jsonify({"error": err}), 400

    ts = _now()
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO saved_scans (tool, name, target, data, created_at, updated_at) "
            "VALUES (?,?,?,?,?,?)",
            (tool, name, target, json.dumps(spec["clean"](data, target)), ts, ts))
        conn.commit()
        return jsonify(_scan_row(_get_scan(conn, cur.lastrowid))), 201
    finally:
        conn.close()


@app.route("/api/saved-scans/<int:sid>", methods=["GET"])
def get_saved_scan(sid):
    conn = get_db()
    try:
        row = _get_scan(conn, sid)
        if not row:
            return jsonify({"error": "Not found"}), 404
        out = _scan_row(row, with_data=True)
        out["notes"] = _notes_for(conn, sid)
        return jsonify(out)
    finally:
        conn.close()


@app.route("/api/saved-scans/<int:sid>", methods=["PATCH"])
def rename_saved_scan(sid):
    name = ((request.get_json(silent=True) or {}).get("name") or "").strip()[:MAX_SCAN_NAME]
    if not name:
        return jsonify({"error": "Name is required"}), 400
    conn = get_db()
    try:
        if not _get_scan(conn, sid):
            return jsonify({"error": "Not found"}), 404
        conn.execute("UPDATE saved_scans SET name=?, updated_at=? WHERE id=?",
                     (name, _now(), sid))
        conn.commit()
        return jsonify(_scan_row(_get_scan(conn, sid)))
    finally:
        conn.close()


@app.route("/api/saved-scans/<int:sid>", methods=["DELETE"])
def delete_saved_scan(sid):
    conn = get_db()
    try:
        if not _get_scan(conn, sid):
            return jsonify({"error": "Not found"}), 404
        # No FK cascade (foreign_keys is off by default in SQLite), so clear notes
        # explicitly or they'd linger and be inherited by a later scan's id.
        conn.execute("DELETE FROM host_notes WHERE scan_id=?", (sid,))
        conn.execute("DELETE FROM saved_scans WHERE id=?", (sid,))
        conn.commit()
        return jsonify({"ok": True})
    finally:
        conn.close()


@app.route("/api/saved-scans/<int:sid>/refresh", methods=["POST"])
def refresh_saved_scan(sid):
    """Re-run the tool against the stored target and replace the stored result,
    keeping the scan's id (and therefore its notes) intact."""
    conn = get_db()
    try:
        row = _get_scan(conn, sid)
        if not row:
            return jsonify({"error": "Not found"}), 404
        tool, target = row["tool"], row["target"]
        spec = SAVED_SCAN_TOOLS.get(tool)
        if not spec:
            return jsonify({"error": "Unknown tool"}), 400
        old_items = spec["items"](json.loads(row["data"]))
    finally:
        conn.close()

    # Re-run outside the DB connection: a sweep can take minutes, and holding the
    # connection would block the scheduler's writes for that whole time.
    payload, err, status = spec["sweep"](target)
    if err:
        return jsonify(err), status

    clean = spec["clean"](payload, target)
    new_keys, gone_items = _diff_items(old_items, spec["items"](clean), spec["key"])
    ts = _now()
    conn = get_db()
    try:
        conn.execute("UPDATE saved_scans SET data=?, new_keys=?, gone_items=?, "
                     "updated_at=?, last_refreshed=? WHERE id=?",
                     (json.dumps(clean), json.dumps(new_keys), json.dumps(gone_items),
                      ts, ts, sid))
        conn.commit()
        row = _get_scan(conn, sid)
        if not row:                     # deleted while the sweep was running
            return jsonify({"error": "Not found"}), 404
        out = _scan_row(row, with_data=True)
        out["notes"] = _notes_for(conn, sid)
        return jsonify(out)
    finally:
        conn.close()


@app.route("/api/saved-scans/<int:sid>/notes/<host>", methods=["PUT"])
def set_host_note(sid, host):
    note = ((request.get_json(silent=True) or {}).get("note") or "").strip()[:MAX_NOTE_CHARS]
    conn = get_db()
    try:
        row = _get_scan(conn, sid)
        if not row:
            return jsonify({"error": "Not found"}), 404
        spec = SAVED_SCAN_TOOLS.get(row["tool"])
        if not spec:
            return jsonify({"error": "Unknown tool"}), 400
        if host not in _known_keys(spec, row):
            return jsonify({"error": "That host isn't part of this scan"}), 400
        if not note:
            # Clearing the box deletes the note rather than storing an empty one,
            # so "has a note" stays a simple presence check.
            conn.execute("DELETE FROM host_notes WHERE scan_id=? AND host=?", (sid, host))
            conn.commit()
            return jsonify({"ok": True, "host": host, "note": ""})
        ts = _now()
        conn.execute(
            "INSERT INTO host_notes (scan_id, host, note, updated_at) VALUES (?,?,?,?) "
            "ON CONFLICT(scan_id, host) DO UPDATE SET note=excluded.note, "
            "updated_at=excluded.updated_at", (sid, host, note, ts))
        conn.commit()
        return jsonify({"ok": True, "host": host, "note": note, "updatedAt": ts})
    finally:
        conn.close()


def _now():
    return datetime.now(timezone.utc).isoformat()


# ── Check runners ────────────────────────────────────────────────────────────
def _check_http(mon):
    headers = {"User-Agent": UA}
    if mon["type"] == "api" and mon["auth_header"]:
        headers["Authorization"] = mon["auth_header"]
    req = urllib.request.Request(mon["target"], headers=headers, method="GET")
    body = ""
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            code = resp.status
            if mon["expected_keyword"]:
                body = resp.read(65536).decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        code = e.code
        if mon["expected_keyword"]:
            try:
                body = e.read(65536).decode("utf-8", "replace")
            except Exception:
                pass

    exp = mon["expected_status"]
    ok = (code == exp) if exp else (200 <= code < 400)
    detail = "HTTP %s" % code
    if not ok and exp:
        detail = "HTTP %s (expected %s)" % (code, exp)
    if ok and mon["expected_keyword"]:
        if mon["expected_keyword"].lower() not in body.lower():
            ok, detail = False, 'HTTP %s but keyword "%s" missing' % (code, mon["expected_keyword"])
    return ("up" if ok else "down"), detail


def _check_tcp(mon):
    host, port = mon["target"], int(mon["port"] or 0)
    with socket.create_connection((host, port), timeout=8):
        return "up", "TCP %s:%s open" % (host, port)


def _check_icmp(mon):
    proc = subprocess.run(["ping", "-c", "1", "-W", "3", mon["target"]],
                          capture_output=True, timeout=10)
    return ("up", "reachable") if proc.returncode == 0 else ("down", "no reply")


def run_check(mon):
    """Execute a monitor's check. Returns (status, latency_ms, detail)."""
    start = time.perf_counter()
    try:
        if mon["type"] in ("http", "api"):
            status, detail = _check_http(mon)
        elif mon["type"] == "tcp":
            status, detail = _check_tcp(mon)
        elif mon["type"] == "icmp":
            status, detail = _check_icmp(mon)
        else:
            return "down", None, "unknown check type"
    except Exception as e:
        return "down", int((time.perf_counter() - start) * 1000), str(e) or e.__class__.__name__
    return status, int((time.perf_counter() - start) * 1000), detail


def _store_result(mon, status, latency, detail):
    """Persist a check result, recording a status transition as an event."""
    conn = get_db()
    try:
        prev = mon["last_status"]
        ts = _now()
        changed = status != prev
        conn.execute(
            "UPDATE monitors SET last_status=?, last_checked=?, last_latency_ms=?, "
            "last_error=?, last_changed=? WHERE id=?",
            (status, ts, latency, None if status == "up" else detail,
             ts if changed else mon["last_changed"], mon["id"]))
        conn.execute("INSERT INTO checks (monitor_id, ts, status, latency_ms, detail) "
                     "VALUES (?,?,?,?,?)", (mon["id"], ts, status, latency, detail))
        # cap per-monitor history
        conn.execute(
            "DELETE FROM checks WHERE monitor_id=? AND id NOT IN "
            "(SELECT id FROM checks WHERE monitor_id=? ORDER BY id DESC LIMIT ?)",
            (mon["id"], mon["id"], HISTORY_PER_MONITOR))
        if changed and status in ("up", "down"):
            conn.execute("INSERT INTO events (monitor_id, ts, from_status, to_status, name) "
                         "VALUES (?,?,?,?,?)", (mon["id"], ts, prev, status, mon["name"]))
            conn.execute("DELETE FROM events WHERE id NOT IN "
                         "(SELECT id FROM events ORDER BY id DESC LIMIT ?)", (EVENTS_KEEP,))
        conn.commit()
    finally:
        conn.close()


# ── Scheduler ────────────────────────────────────────────────────────────────
def _due_monitors():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM monitors WHERE enabled=1").fetchall()
    finally:
        conn.close()
    now = datetime.now(timezone.utc)
    due = []
    for r in rows:
        if not r["last_checked"]:
            due.append(r)
            continue
        try:
            last = datetime.fromisoformat(r["last_checked"])
        except ValueError:
            due.append(r)
            continue
        if (now - last).total_seconds() >= r["interval_seconds"]:
            due.append(r)
    return due


def _perform(mon):
    status, latency, detail = run_check(mon)
    _store_result(mon, status, latency, detail)


def _scheduler_loop():
    while True:
        try:
            due = _due_monitors()
            if due:
                with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
                    list(ex.map(_perform, due))
        except Exception as e:
            app.logger.warning("scheduler tick failed: %s", e)
        time.sleep(SCHED_TICK)


_scheduler_started = False


def start_scheduler():
    global _scheduler_started
    if _scheduler_started:
        return
    _scheduler_started = True
    threading.Thread(target=_scheduler_loop, daemon=True, name="monitor-scheduler").start()


# ── Serialisation & validation ───────────────────────────────────────────────
def _monitor_dict(r):
    return {
        "id": r["id"], "name": r["name"], "type": r["type"], "target": r["target"],
        "port": r["port"], "expectedStatus": r["expected_status"],
        "expectedKeyword": r["expected_keyword"], "hasAuth": bool(r["auth_header"]),
        "interval": r["interval_seconds"], "enabled": bool(r["enabled"]),
        "status": r["last_status"], "lastChecked": r["last_checked"],
        "latencyMs": r["last_latency_ms"], "lastError": r["last_error"],
        "lastChanged": r["last_changed"], "createdAt": r["created_at"],
    }


def _validate_monitor(data):
    """Return (fields_dict, error). fields use DB column names."""
    name = (data.get("name") or "").strip()
    mtype = (data.get("type") or "").strip().lower()
    target = (data.get("target") or "").strip()
    if not name:
        return None, "Name is required"
    if mtype not in CHECK_TYPES:
        return None, "Type must be one of: " + ", ".join(CHECK_TYPES)
    if not target:
        return None, "Target is required"

    port = data.get("port")
    expected_status = data.get("expectedStatus")
    keyword = (data.get("expectedKeyword") or "").strip() or None
    auth = (data.get("authHeader") or "").strip() or None

    if mtype in ("http", "api"):
        p = urlparse(target)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None, "Target must be an http:// or https:// URL"
    else:
        if not is_valid_target(target):
            return None, "Target must be a valid host or IP"

    if mtype == "tcp":
        try:
            port = int(port)
        except (TypeError, ValueError):
            return None, "A TCP port (1-65535) is required"
        if not 1 <= port <= 65535:
            return None, "Port must be 1-65535"
    else:
        port = None

    if expected_status not in (None, "", 0):
        try:
            expected_status = int(expected_status)
        except (TypeError, ValueError):
            return None, "Expected status must be a number"
        if not 100 <= expected_status <= 599:
            return None, "Expected status must be 100-599"
    else:
        expected_status = None

    if mtype != "api":
        auth = None

    try:
        interval = int(data.get("interval") or 300)
    except (TypeError, ValueError):
        return None, "Interval must be a number of seconds"
    interval = max(MIN_INTERVAL, min(MAX_INTERVAL, interval))

    return {
        "name": name, "type": mtype, "target": target, "port": port,
        "expected_status": expected_status, "expected_keyword": keyword,
        "auth_header": auth, "interval_seconds": interval,
    }, None


# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/api/monitors", methods=["GET"])
def list_monitors():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM monitors ORDER BY name COLLATE NOCASE").fetchall()
    finally:
        conn.close()
    return jsonify([_monitor_dict(r) for r in rows])


@app.route("/api/monitors", methods=["POST"])
def create_monitor():
    fields, err = _validate_monitor(request.get_json(silent=True) or {})
    if err:
        return jsonify({"error": err}), 400
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO monitors (name, type, target, port, expected_status, "
            "expected_keyword, auth_header, interval_seconds, enabled, created_at) "
            "VALUES (?,?,?,?,?,?,?,?,1,?)",
            (fields["name"], fields["type"], fields["target"], fields["port"],
             fields["expected_status"], fields["expected_keyword"], fields["auth_header"],
             fields["interval_seconds"], _now()))
        conn.commit()
        row = conn.execute("SELECT * FROM monitors WHERE id=?", (cur.lastrowid,)).fetchone()
    finally:
        conn.close()
    return jsonify(_monitor_dict(row)), 201


@app.route("/api/monitors/<int:mid>", methods=["PATCH"])
def update_monitor(mid):
    data = request.get_json(silent=True) or {}
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM monitors WHERE id=?", (mid,)).fetchone()
        if not row:
            return jsonify({"error": "Monitor not found"}), 404
        # enable/disable-only toggle
        if set(data.keys()) <= {"enabled"}:
            conn.execute("UPDATE monitors SET enabled=? WHERE id=?",
                         (1 if data.get("enabled") else 0, mid))
            conn.commit()
            row = conn.execute("SELECT * FROM monitors WHERE id=?", (mid,)).fetchone()
            return jsonify(_monitor_dict(row))
        fields, err = _validate_monitor(data)
        if err:
            return jsonify({"error": err}), 400
        enabled = 1 if data.get("enabled", bool(row["enabled"])) else 0
        conn.execute(
            "UPDATE monitors SET name=?, type=?, target=?, port=?, expected_status=?, "
            "expected_keyword=?, auth_header=?, interval_seconds=?, enabled=? WHERE id=?",
            (fields["name"], fields["type"], fields["target"], fields["port"],
             fields["expected_status"], fields["expected_keyword"], fields["auth_header"],
             fields["interval_seconds"], enabled, mid))
        conn.commit()
        row = conn.execute("SELECT * FROM monitors WHERE id=?", (mid,)).fetchone()
    finally:
        conn.close()
    return jsonify(_monitor_dict(row))


@app.route("/api/monitors/<int:mid>", methods=["DELETE"])
def delete_monitor(mid):
    conn = get_db()
    try:
        conn.execute("DELETE FROM monitors WHERE id=?", (mid,))
        conn.execute("DELETE FROM checks WHERE monitor_id=?", (mid,))
        conn.execute("DELETE FROM events WHERE monitor_id=?", (mid,))
        conn.commit()
    finally:
        conn.close()
    return jsonify({"ok": True})


@app.route("/api/monitors/<int:mid>/check", methods=["POST"])
def check_monitor_now(mid):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM monitors WHERE id=?", (mid,)).fetchone()
    finally:
        conn.close()
    if not row:
        return jsonify({"error": "Monitor not found"}), 404
    _perform(row)
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM monitors WHERE id=?", (mid,)).fetchone()
    finally:
        conn.close()
    return jsonify(_monitor_dict(row))


@app.route("/api/dashboard")
def dashboard():
    conn = get_db()
    try:
        monitors = [_monitor_dict(r) for r in
                    conn.execute("SELECT * FROM monitors ORDER BY name COLLATE NOCASE").fetchall()]
        events = [{"id": e["id"], "monitorId": e["monitor_id"], "name": e["name"],
                   "ts": e["ts"], "from": e["from_status"], "to": e["to_status"]}
                  for e in conn.execute(
                      "SELECT * FROM events ORDER BY id DESC LIMIT 50").fetchall()]
    finally:
        conn.close()
    summary = {"total": len(monitors), "up": 0, "down": 0, "unknown": 0}
    for m in monitors:
        summary[m["status"]] = summary.get(m["status"], 0) + 1
    return jsonify({"summary": summary, "monitors": monitors, "events": events})


@app.route("/api/export")
def export_monitors():
    conn = get_db()
    try:
        rows = conn.execute("SELECT * FROM monitors ORDER BY id").fetchall()
    finally:
        conn.close()
    payload = {
        "app": "SecAnalysis", "version": APP_VERSION, "exportedAt": _now(),
        "monitors": [{
            "name": r["name"], "type": r["type"], "target": r["target"], "port": r["port"],
            "expectedStatus": r["expected_status"], "expectedKeyword": r["expected_keyword"],
            "authHeader": r["auth_header"], "interval": r["interval_seconds"],
            "enabled": bool(r["enabled"]),
        } for r in rows],
    }
    resp = jsonify(payload)
    resp.headers["Content-Disposition"] = "attachment; filename=secanalysis-monitors.json"
    return resp


@app.route("/api/import", methods=["POST"])
def import_monitors():
    data = request.get_json(silent=True) or {}
    monitors = data.get("monitors")
    if not isinstance(monitors, list):
        return jsonify({"error": "Expected a JSON object with a 'monitors' array"}), 400
    added, skipped, errors = 0, 0, []
    conn = get_db()
    try:
        for i, m in enumerate(monitors):
            fields, err = _validate_monitor(m if isinstance(m, dict) else {})
            if err:
                skipped += 1
                errors.append("#%d: %s" % (i + 1, err))
                continue
            enabled = 1 if m.get("enabled", True) else 0
            conn.execute(
                "INSERT INTO monitors (name, type, target, port, expected_status, "
                "expected_keyword, auth_header, interval_seconds, enabled, created_at) "
                "VALUES (?,?,?,?,?,?,?,?,?,?)",
                (fields["name"], fields["type"], fields["target"], fields["port"],
                 fields["expected_status"], fields["expected_keyword"], fields["auth_header"],
                 fields["interval_seconds"], enabled, _now()))
            added += 1
        conn.commit()
    finally:
        conn.close()
    return jsonify({"added": added, "skipped": skipped, "errors": errors[:20]})


init_db()
start_scheduler()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
