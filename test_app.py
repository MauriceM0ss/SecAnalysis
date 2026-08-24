"""Smoke tests for SecAnalysis — core routing, the report-history CRUD, and the
security guards (path traversal, cross-origin/CSRF, input validation).

Hermetic: DB_PATH / HISTORY_DIR are pointed at a temp dir *before* importing the
app, so nothing here touches the real /data volume. No network is exercised.

Run inside the container (it has the app's deps):
    docker cp test_app.py netscan:/app/ && docker exec netscan python -m pytest test_app.py -q
"""
import json
import os
import tempfile

_TMP = tempfile.mkdtemp(prefix="secanalysis-test-")
os.environ["DB_PATH"] = os.path.join(_TMP, "test.db")
os.environ["HISTORY_DIR"] = os.path.join(_TMP, "history")
os.environ.setdefault("AUDIT_ROOT", os.path.join(_TMP, "audit"))

import pytest  # noqa: E402
import app as appmod  # noqa: E402


@pytest.fixture
def client():
    appmod.app.config["TESTING"] = True
    return appmod.app.test_client()


# ── Routing ────────────────────────────────────────────────────────────────
def test_healthz(client):
    r = client.get("/healthz")
    assert r.status_code == 200
    assert r.get_json()["status"] == "ok"


def test_index_renders(client):
    r = client.get("/")
    assert r.status_code == 200
    assert b"SecAnalysis" in r.data


def test_security_headers(client):
    r = client.get("/")
    assert "frame-ancestors" in r.headers.get("Content-Security-Policy", "")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"


# ── Pure helpers ───────────────────────────────────────────────────────────
def test_is_valid_domain():
    assert appmod.is_valid_domain("example.com")
    assert appmod.is_valid_domain("a.b.example.co.uk")
    # blocks raw IPs (SSRF to metadata) and bare single-label hosts
    assert not appmod.is_valid_domain("169.254.169.254")
    assert not appmod.is_valid_domain("localhost")
    assert not appmod.is_valid_domain("not a host")


def test_validate_subnet():
    net, err = appmod.validate_subnet("192.168.1.0/24")
    assert err is None and str(net) == "192.168.1.0/24"
    # a host address is accepted and normalised to its network
    net, err = appmod.validate_subnet("192.168.1.5/24")
    assert err is None and str(net) == "192.168.1.0/24"
    # missing prefix, junk, leading dash, and oversize prefixes are rejected
    assert appmod.validate_subnet("192.168.1.5")[1]
    assert appmod.validate_subnet("not a subnet")[1]
    assert appmod.validate_subnet("-oX/24")[1]
    assert appmod.validate_subnet("10.0.0.0/8")[1]   # > MAX_SUBNET_HOSTS


def test_parse_nmap_hosts_xml():
    xml = ('<nmaprun><host><status state="up" reason="arp-response"/>'
           '<address addr="192.168.1.1" addrtype="ipv4"/>'
           '<address addr="AA:BB:CC:DD:EE:FF" addrtype="mac" vendor="Acme"/>'
           '<hostnames><hostname name="router.local" type="PTR"/></hostnames></host>'
           '<host><status state="down" reason="no-response"/>'
           '<address addr="192.168.1.2" addrtype="ipv4"/></host></nmaprun>')
    hosts = appmod.parse_nmap_hosts_xml(xml)
    assert len(hosts) == 1                       # the down host is dropped
    assert hosts[0]["ip"] == "192.168.1.1"
    assert hosts[0]["hostname"] == "router.local"
    assert hosts[0]["vendor"] == "Acme"


def test_subnet_scan_rejects_bad_input(client):
    assert client.post("/api/subnet", json={"subnet": "nope"}).status_code == 400
    assert client.post("/api/subnet", json={"subnet": "10.0.0.0/8"}).status_code == 400


def test_safe_slug():
    assert appmod._safe_slug("192.168.1.10") == "192.168.1.10"
    assert appmod._safe_slug("Hello World!") == "hello-world"
    assert appmod._safe_slug("") == "report"


def test_cvss_pick_prefers_nvd():
    assert appmod._cvss_pick({"nvd": {"V3Score": 9.8, "V3Vector": "AV:N"}}) == (9.8, "AV:N")
    assert appmod._cvss_pick({"redhat": {"V2Score": 5.0, "V2Vector": "X"}}) == (5.0, "X")
    assert appmod._cvss_pick({}) == (None, None)


def test_domain_candidates():
    assert appmod._domain_candidates("www.example.com") == ["www.example.com", "example.com"]
    assert appmod._domain_candidates("example.com") == ["example.com"]
    assert appmod._domain_candidates("a.b.example.com") == [
        "a.b.example.com", "b.example.com", "example.com"]


def test_analyze_spf():
    hard = appmod._analyze_spf("v=spf1 include:_spf.google.com a mx -all", "example.com", False)
    assert hard["all"] == "fail" and hard["lookups"] == 3 and not hard["tooManyLookups"]
    soft = appmod._analyze_spf("v=spf1 ~all", "example.com", False)
    assert soft["all"] == "softfail" and soft["lookups"] == 0
    weak = appmod._analyze_spf("v=spf1 +all", "example.com", False)
    assert weak["all"] == "pass"
    many = appmod._analyze_spf("v=spf1 " + " ".join(["include:x%d.test" % i for i in range(11)]) + " -all",
                               "example.com", False)
    assert many["tooManyLookups"] and many["lookups"] == 11


# ── WHOIS ──────────────────────────────────────────────────────────────────
# Every registry answers in its own layout, so the parser is exercised against
# the four shapes that cover most of them. No lookup here touches the network:
# subprocess.run is stubbed wherever get_whois is called.
WHOIS_ICANN = """\
   Domain Name: EXAMPLE.COM
   Registrar: MarkMonitor Inc.
   Registrar URL: http://www.markmonitor.com
   Updated Date: 2024-08-14T07:01:34Z
   Creation Date: 1995-08-14T04:00:00Z
   Registry Expiry Date: 2035-08-13T04:00:00Z
   Registrar Abuse Contact Email: abuse@markmonitor.com
   Domain Status: clientTransferProhibited https://icann.org/epp#clientTransferProhibited
   Domain Status: clientTransferProhibited (https://icann.org/epp#clientTransferProhibited)
   Name Server: A.IANA-SERVERS.NET
   Name Server: B.IANA-SERVERS.NET
   DNSSEC: signedDelegation
   Registrant Organization: REDACTED FOR PRIVACY
>>> Last update of whois database: 2025-01-02T10:00:00Z <<<
"""

WHOIS_NOMINET = """\
    Domain name:
        example.co.uk

    Registrar:
        Nominet UK [Tag = NOMINET]

    Registered on: 01-Aug-1996
    Expiry date:  01-Aug-2035
    Last updated:  05-Jul-2024

    Name servers:
        ns1.example.co.uk      198.51.100.7  2001:db8::1
        ns2.example.co.uk
"""

WHOIS_RIPE_STYLE = """\
domain:        EXAMPLE.RU
nserver:       ns1.example.ru. 93.158.134.1
nserver:       ns2.example.ru.
state:         REGISTERED, DELEGATED, VERIFIED
org:           Some Org LLC
registrar:     RU-CENTER-RU
created:       1997-09-30T10:48:56Z
paid-till:     2035-10-01T00:00:00Z
"""


def test_parse_whois_icann_format():
    w = appmod.parse_whois(WHOIS_ICANN)
    assert w["registrar"] == "MarkMonitor Inc."
    assert w["abuseEmail"] == "abuse@markmonitor.com"
    assert w["nameServers"] == ["A.IANA-SERVERS.NET", "B.IANA-SERVERS.NET"]
    # The registrar's parenthesised echo of a status is the same status.
    assert w["statuses"] == ["clientTransferProhibited"]
    assert w["dnssecSigned"]
    # Redaction is reported as such, not as an owner named "REDACTED FOR PRIVACY".
    assert w["registrant"] is None and w["redacted"]
    assert w["ageDays"] > 10000 and w["daysUntilExpiry"] > 0


def test_parse_whois_reads_indented_blocks():
    """`.uk` puts the registrar and the name servers under a bare key, and lists
    IPv6 glue on the name-server lines — colons that must not end the block."""
    w = appmod.parse_whois(WHOIS_NOMINET)
    assert w["registrar"] == "Nominet UK [Tag = NOMINET]"
    assert w["nameServers"] == ["ns1.example.co.uk", "ns2.example.co.uk"]
    assert w["created"] == "01-Aug-1996" and w["ageDays"] > 10000


def test_parse_whois_ripe_style_keys():
    w = appmod.parse_whois(WHOIS_RIPE_STYLE)
    assert w["registrar"] == "RU-CENTER-RU" and w["registrant"] == "Some Org LLC"
    # Glue addresses trail the name on the same line; they aren't name servers.
    assert w["nameServers"] == ["ns1.example.ru", "ns2.example.ru"]
    assert w["daysUntilExpiry"] > 0


def test_whois_date_formats():
    d = appmod._whois_date
    assert d("2024-08-14T07:01:34Z").year == 2024
    assert d("2024-08-14 07:01:34.123 +0000").hour == 7
    assert d("01-Aug-1996").month == 8      # not a "-19:96" UTC offset
    assert d("01.08.1996").day == 1         # not fractional seconds
    assert d("before Aug-1996") is None
    assert d("") is None


@pytest.fixture
def spy_whois(monkeypatch):
    """Stub `whois` with a per-domain answer table. Returns the domains asked."""
    asked = []

    def install(answers):
        class _Proc:
            def __init__(self, out):
                self.stdout, self.stderr, self.returncode = out, "", 0

        def fake_run(argv, **kwargs):
            domain = argv[-1]
            asked.append(domain)
            return _Proc(answers.get(domain, "No match for \"%s\"." % domain.upper()))

        monkeypatch.setattr(appmod.subprocess, "run", fake_run)
        return asked
    return install


def test_get_whois_walks_up_to_the_registrable_domain(spy_whois):
    asked = spy_whois({"example.com": WHOIS_ICANN})
    w = appmod.get_whois("www.example.com")
    assert w["found"] and w["queried"] == "example.com"
    assert asked == ["www.example.com", "example.com"]
    assert w["raw"].startswith("   Domain Name: EXAMPLE.COM")


def test_get_whois_handles_multi_label_suffixes(spy_whois):
    asked = spy_whois({"example.co.uk": WHOIS_NOMINET})
    w = appmod.get_whois("www.example.co.uk")
    assert w["found"] and w["queried"] == "example.co.uk"
    # Stops at the record; never falls through to the public suffix itself.
    assert "co.uk" not in asked


def test_get_whois_reports_no_record(spy_whois):
    spy_whois({})
    w = appmod.get_whois("nothing.example.com")
    assert not w["found"] and w["error"]


def test_get_whois_rejects_ip_targets(spy_whois):
    asked = spy_whois({})
    w = appmod.get_whois("8.8.8.8")
    assert not w["found"] and "IP address" in w["error"]
    assert asked == []


def test_analyze_skips_whois_unless_asked(client, monkeypatch):
    calls = []
    monkeypatch.setattr(appmod, "get_whois", lambda h: calls.append(h) or {"found": False})
    monkeypatch.setattr(appmod.socket, "gethostbyname", lambda h: "192.0.2.1")
    monkeypatch.setattr(appmod, "head_request", lambda u, a: (200, {}))
    monkeypatch.setattr(appmod, "get_dns_records", lambda h: {})
    monkeypatch.setattr(appmod, "get_cookies", lambda *a, **k: [])
    monkeypatch.setattr(appmod, "get_redirect_chain", lambda *a, **k: [])
    monkeypatch.setattr(appmod, "fetch_text_file", lambda *a, **k: {"found": False})
    monkeypatch.setattr(appmod, "fetch_page_html", lambda *a, **k: "")
    monkeypatch.setattr(appmod, "get_https_redirect", lambda h: {"tested": False})

    r = client.post("/api/analyze", json={"url": "http://x.test/"})
    assert r.status_code == 200 and r.get_json()["whois"] is None and calls == []

    r = client.post("/api/analyze", json={"url": "http://x.test/", "whois": True})
    assert r.status_code == 200 and r.get_json()["whois"] == {"found": False}
    assert calls == ["x.test"]


def test_analyze_csp():
    weak = appmod.analyze_csp("default-src 'self'; script-src 'self' 'unsafe-inline' *")
    assert weak["grade"] == "bad"
    texts = " ".join(i["text"] for i in weak["issues"])
    assert "unsafe-inline" in texts and "Wildcard" in texts
    # A nonce excuses unsafe-inline (browsers ignore it then) → no high finding
    nonce = appmod.analyze_csp("script-src 'self' 'unsafe-inline' 'nonce-abc123'; base-uri 'none'")
    assert all(i["severity"] != "high" for i in nonce["issues"])
    strong = appmod.analyze_csp("default-src 'none'; script-src 'self'; object-src 'none'; base-uri 'none'")
    assert strong["grade"] == "good" and strong["issues"] == []
    assert appmod.analyze_csp("Not found")["present"] is False


def test_analyze_hsts():
    ok = appmod.analyze_hsts("max-age=63072000; includeSubDomains; preload")
    assert ok["preloadEligible"] and ok["maxAge"] == 63072000
    short = appmod.analyze_hsts("max-age=600")
    assert not short["preloadEligible"] and not short["includeSubDomains"]
    assert appmod.analyze_hsts("Not found")["present"] is False


def test_grade_tls_deep_signals():
    base = {"url": "https://x.test", "certInfo": {
        "protocol": "TLSv1.3", "daysUntilExpiry": 90, "selfSigned": False,
        "chainTrusted": True, "deprecatedProtocols": [], "weakCipher": False}}
    assert appmod._grade_tls(base)[0] == "good"
    untrusted = {"url": "https://x.test", "certInfo": {**base["certInfo"], "chainTrusted": False,
                                                       "trustError": "hostname mismatch"}}
    assert appmod._grade_tls(untrusted)[0] == "bad"
    legacy = {"url": "https://x.test", "certInfo": {**base["certInfo"],
                                                    "deprecatedProtocols": ["TLS 1.0"]}}
    assert appmod._grade_tls(legacy)[0] == "warn"


def test_analyze_page_content_mixed_and_thirdparty():
    html = """
      <html><head>
        <script src="http://cdn.evil.com/a.js"></script>
        <link rel="stylesheet" href="https://fonts.example.com/f.css">
        <link rel="preconnect" href="http://hint.example.com">
      </head><body>
        <img src="http://img.example.com/p.png">
        <img src="/local.png">
        <a href="http://ignored-link.com">link</a>
        <iframe src="https://self.test/frame"></iframe>
      </body></html>"""
    pc = appmod.analyze_page_content(html, "https://self.test/")
    assert pc["analyzed"]
    # active mixed = the http script; passive mixed = the http img; preconnect hint excluded
    assert pc["mixedActiveCount"] == 1 and pc["mixedPassiveCount"] == 1
    hosts = {h["host"] for h in pc["thirdPartyHosts"]}
    assert "cdn.evil.com" in hosts and "fonts.example.com" in hosts
    assert "ignored-link.com" not in hosts          # <a> links are not resources
    assert "self.test" not in hosts                 # same-origin excluded


def test_analyze_page_content_http_page_has_no_mixed():
    pc = appmod.analyze_page_content('<img src="http://x.test/a.png">', "http://plain.test/")
    assert pc["mixedActiveCount"] == 0 and pc["mixedPassiveCount"] == 0


def test_analyze_redirects():
    loop = [{"url": "https://a.test/", "statusCode": 302},
            {"url": "https://a.test/", "statusCode": 302}]
    assert any("loop" in i.lower() for i in appmod.analyze_redirects(loop))
    downgrade = [{"url": "https://a.test/", "statusCode": 301},
                 {"url": "http://a.test/", "statusCode": 200}]
    assert any("downgrade" in i.lower() for i in appmod.analyze_redirects(downgrade))
    assert appmod.analyze_redirects([{"url": "https://a.test/", "statusCode": 200}]) == []


def test_grade_mixed_and_https_redirect():
    good = {"url": "https://x.test", "pageContent": {"analyzed": True, "resourceCount": 5,
            "mixedActiveCount": 0, "mixedPassiveCount": 0}}
    assert appmod._grade_mixed_content(good)[0] == "good"
    active = {"url": "https://x.test", "pageContent": {"analyzed": True,
              "mixedActiveCount": 2, "mixedPassiveCount": 0}}
    assert appmod._grade_mixed_content(active)[0] == "bad"
    assert appmod._grade_mixed_content({"url": "http://x.test"})[0] == "na"
    assert appmod._grade_https_redirect({"httpsRedirect": {"tested": True, "upgradesToHttps": True}})[0] == "good"
    assert appmod._grade_https_redirect({"httpsRedirect": {"tested": True, "upgradesToHttps": False}})[0] == "bad"
    assert appmod._grade_https_redirect({"httpsRedirect": {"tested": False}})[0] == "na"


def test_grade_analysis_weights_and_excludes_na():
    # HTTPS site, valid modern cert, full headers, enforced mail security → high score
    good = {
        "url": "https://example.com",
        "certInfo": {"protocol": "TLSv1.3", "daysUntilExpiry": 88, "selfSigned": False,
                     "chainTrusted": True, "deprecatedProtocols": [], "weakCipher": False},
        "cspAnalysis": {"present": True, "grade": "good", "issues": []},
        "securityHeaders": {k: "set" for k in appmod.SECURITY_HEADERS},
        "cookies": [{"name": "s", "secure": True, "httpOnly": True, "sameSite": "Strict"}],
        "dmarc": {"found": True, "policy": "reject"},
        "spf": {"found": True, "all": "fail", "lookups": 3, "tooManyLookups": False},
        "dnssec": {"signed": True, "ds": True, "zone": "example.com"},
        "dnsRecords": {"MX": [{"priority": 10, "exchange": "mx.example.com"}]},
        "mtaSts": {"found": True, "mode": "enforce"}, "tlsRpt": {"found": True},
        "securityTxt": {"found": True},
        "pageContent": {"analyzed": True, "resourceCount": 4,
                        "mixedActiveCount": 0, "mixedPassiveCount": 0},
        "httpsRedirect": {"tested": True, "upgradesToHttps": True},
    }
    sc = appmod.grade_analysis(good)
    assert sc["score"] == 100 and sc["rating"] == "good"

    # Plain HTTP with nothing set, DNS not checked → TLS is N/A (excluded), poor score
    bad = {
        "url": "http://example.com", "certInfo": None,
        "securityHeaders": {k: "Not found" for k in appmod.SECURITY_HEADERS},
        "cookies": [], "dmarc": None, "spf": None, "dnssec": None,
        "dnsRecords": {}, "mtaSts": None, "tlsRpt": None, "securityTxt": {"found": False},
    }
    sc = appmod.grade_analysis(bad)
    cats = {c["name"]: c["grade"] for c in sc["categories"]}
    assert cats["TLS/SSL"] == "na" and cats["DMARC"] == "na"      # excluded from score
    assert cats["Security Headers"] == "bad" and sc["rating"] == "bad"


# ── URL Analyzer as a saved scan ───────────────────────────────────────────
def _url_payload(score=70, grades=None, **opts):
    """A minimal /api/analyze-shaped payload."""
    grades = grades or {"TLS/SSL": "good", "Cookies": "warn"}
    return {
        "url": "https://example.test/", "ipAddress": "192.0.2.1", "statusCode": 200,
        "options": {"portScan": False, "dnsAuth": False, "whois": False, **opts},
        "scorecard": {"score": score, "rating": "warn",
                      "categories": [{"name": n, "grade": g, "detail": ""}
                                     for n, g in grades.items()]},
    }


def test_validate_url_target():
    assert appmod._validate_url_target("https://example.test/a") == ("https://example.test/a", None)
    assert appmod._validate_url_target("example.test")[1]        # no scheme
    assert appmod._validate_url_target("ftp://example.test")[1]  # wrong scheme
    assert appmod._validate_url_target("")[1]


def test_clean_url_result_keeps_options_and_drops_extras():
    data = _url_payload(whois=True)
    data["password"] = "hunter2"          # nothing outside the allowlist survives
    data["certInfo"] = {"subject": "CN=example.test"}
    clean = appmod._clean_url_result(data, "https://example.test/")
    assert "password" not in clean
    assert clean["certInfo"] == {"subject": "CN=example.test"}
    # Options ride along so a refresh re-runs the same checks.
    assert clean["options"] == {"portScan": False, "dnsAuth": False, "whois": True}
    assert [c["name"] for c in clean["scorecard"]["categories"]] == ["TLS/SSL", "Cookies"]


def test_url_grade_changes_reports_moves_only():
    prev = appmod._clean_url_result(_url_payload(70), "https://example.test/")
    now = appmod._clean_url_result(
        _url_payload(55, {"TLS/SSL": "good", "Cookies": "bad"}), "https://example.test/", prev)
    # An unchanged check is not a change; the scorecard's fixed category list is
    # why the generic new/gone diff can't carry this tool.
    assert now["changes"] == [{"name": "Cookies", "from": "warn", "to": "bad"}]
    assert now["previousScore"] == 70
    assert appmod._clean_url_result(_url_payload(), "https://example.test/")["changes"] == []


def test_saved_url_scan_refreshes_with_the_options_it_was_saved_with(client, monkeypatch):
    seen = []

    def fake_run(url, opts, auth=None):
        seen.append((url, dict(opts), auth))
        return _url_payload(60, whois=True), None, 200

    monkeypatch.setattr(appmod, "run_url_analysis", fake_run)

    created = client.post("/api/saved-scans", json={
        "tool": "url", "name": "Example", "data": _url_payload(70, whois=True)}).get_json()
    assert created["itemCount"] == 2      # the scorecard's checks are the items

    r = client.post("/api/saved-scans/%d/refresh" % created["id"])
    assert r.status_code == 200
    # Re-run with the saved options, and without any credentials: those are
    # deliberately never stored.
    assert seen == [("https://example.test/", {"portScan": False, "dnsAuth": False,
                                               "whois": True}, None)]
    assert r.get_json()["data"]["previousScore"] == 70


def test_note_on_a_scorecard_check_survives_a_slash(client, monkeypatch):
    monkeypatch.setattr(appmod, "run_url_analysis",
                        lambda url, opts, auth=None: (_url_payload(60), None, 200))
    sid = client.post("/api/saved-scans", json={
        "tool": "url", "name": "Example", "data": _url_payload()}).get_json()["id"]

    # "TLS/SSL" is a legitimate item key, which is why the notes route takes a path.
    r = client.put("/api/saved-scans/%d/notes/TLS/SSL" % sid, json={"note": "accepted"})
    assert r.status_code == 200 and r.get_json()["host"] == "TLS/SSL"
    assert client.get("/api/saved-scans/%d" % sid).get_json()["notes"]["TLS/SSL"]["note"] == "accepted"
    # The note outlives a refresh, which is the point of saving a scan.
    client.post("/api/saved-scans/%d/refresh" % sid)
    assert client.get("/api/saved-scans/%d" % sid).get_json()["notes"]["TLS/SSL"]["note"] == "accepted"


def test_saved_url_scan_rejects_junk(client):
    for data in ({}, {"url": "https://example.test/"}, {"scorecard": {}}):
        r = client.post("/api/saved-scans", json={"tool": "url", "name": "x", "data": data})
        assert r.status_code == 400


def test_resolve_history_file_guards_traversal():
    assert appmod._resolve_history_file("evil", "x.html") is None           # bad tool
    assert appmod._resolve_history_file("netscan", "../secanalysis.db") is None  # not .html
    assert appmod._resolve_history_file("netscan", "../../etc/passwd") is None
    assert appmod._resolve_history_file("netscan", ".hidden.html") is None   # dotfile
    assert appmod._resolve_history_file("netscan", "ok.html") is not None    # legit


# ── History CRUD ───────────────────────────────────────────────────────────
def test_history_lifecycle(client):
    r = client.post("/api/history",
                    json={"tool": "netscan", "target": "192.168.1.10",
                          "html": "<html><body>report</body></html>"})
    assert r.status_code == 200
    name = r.get_json()["filename"]

    items = client.get("/api/history").get_json()["items"]
    assert any(i["filename"] == name for i in items)

    g = client.get(f"/api/history/netscan/{name}")
    assert g.status_code == 200
    assert "default-src 'none'" in g.headers.get("Content-Security-Policy", "")

    p = client.patch(f"/api/history/netscan/{name}", json={"label": "Office NAS"})
    assert p.status_code == 200
    items = client.get("/api/history").get_json()["items"]
    assert any(i["label"] == "Office NAS" for i in items if i["filename"] == name)

    d = client.delete(f"/api/history/netscan/{name}")
    assert d.status_code == 200
    assert client.get(f"/api/history/netscan/{name}").status_code == 404


def test_history_rejects_unknown_tool(client):
    assert client.post("/api/history", json={"tool": "evil", "html": "x"}).status_code == 400


def test_history_rejects_empty_report(client):
    assert client.post("/api/history", json={"tool": "netscan", "html": ""}).status_code == 400


# ── Security guards ────────────────────────────────────────────────────────
def test_cross_origin_post_blocked(client):
    r = client.post("/api/history", json={"tool": "netscan", "html": "x"},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


def test_same_origin_post_allowed(client):
    r = client.post("/api/history", json={"tool": "netscan", "target": "t",
                                          "html": "<html></html>"},
                    headers={"Origin": "http://localhost"})
    assert r.status_code == 200


def test_subdomain_live_rejects_bad_hostname(client):
    assert client.post("/api/subdomain-live", json={"name": "not a host"}).status_code == 400
    assert client.post("/api/subdomain-live", json={"name": "169.254.169.254"}).status_code == 400


# ── Console ────────────────────────────────────────────────────────────────
# These never touch the network: subprocess.run is stubbed out so the tests can
# assert on the argv the endpoint *would* have executed.
@pytest.fixture
def spy_run(monkeypatch):
    """Capture the argv passed to subprocess.run and return canned output."""
    calls = []

    class _Proc:
        stdout, stderr, returncode = "output\n", "", 0

    def fake_run(argv, **kwargs):
        calls.append(argv)
        return _Proc()

    monkeypatch.setattr(appmod.subprocess, "run", fake_run)
    return calls


def test_console_tools_menu_matches_server(client):
    d = client.get("/api/console/tools").get_json()
    assert {t["id"] for t in d["tools"]} == set(appmod.CONSOLE_TOOLS)
    assert "A" in d["dnsTypes"]


def test_console_runs_allowlisted_tool(client, spy_run):
    r = client.post("/api/console", json={"tool": "ping", "target": "example.com"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["exitCode"] == 0
    assert d["output"] == "output\n"
    # Flags come from the server's table; only the target is appended.
    assert spy_run == [["ping", "-n", "-c", "4", "-W", "3", "example.com"]]
    assert d["command"] == "ping -n -c 4 -W 3 example.com"


def test_console_dig_appends_allowlisted_record_type(client, spy_run):
    r = client.post("/api/console", json={"tool": "dig", "target": "example.com",
                                          "recordType": "mx"})
    assert r.status_code == 200
    assert spy_run[0][-2:] == ["example.com", "MX"]


def test_console_rejects_unknown_record_type(client, spy_run):
    r = client.post("/api/console", json={"tool": "dig", "target": "example.com",
                                          "recordType": "-f/etc/passwd"})
    assert r.status_code == 400
    assert not spy_run          # nothing was executed


def test_console_rejects_unknown_tool(client, spy_run):
    assert client.post("/api/console", json={"tool": "bash", "target": "x"}).status_code == 400
    assert client.post("/api/console", json={"tool": "", "target": "x"}).status_code == 400
    assert not spy_run


def test_console_rejects_shell_metacharacters_in_target(client, spy_run):
    """The target is never parsed by a shell, but reject the payloads anyway so a
    typo'd or hostile target fails loudly instead of resolving to something odd."""
    for bad in ["example.com; id", "example.com && id", "$(id)", "`id`", "a|b",
                "a b", "a>b", "a\nid", ""]:
        r = client.post("/api/console", json={"tool": "ping", "target": bad})
        assert r.status_code == 400, bad
    assert not spy_run


def test_console_rejects_flag_like_target(client, spy_run):
    """A leading dash would otherwise let the caller smuggle in a flag."""
    for bad in ["-f", "--help", "-h", "-oN/tmp/x"]:
        assert client.post("/api/console", json={"tool": "ping", "target": bad}).status_code == 400, bad
    assert not spy_run


def test_console_truncates_huge_output(client, monkeypatch):
    class _Proc:
        stdout, stderr, returncode = "x" * (appmod.CONSOLE_MAX_OUTPUT + 5000), "", 0

    monkeypatch.setattr(appmod.subprocess, "run", lambda argv, **kw: _Proc())
    d = client.post("/api/console", json={"tool": "whois", "target": "example.com"}).get_json()
    assert len(d["output"]) < appmod.CONSOLE_MAX_OUTPUT + 100
    assert d["output"].endswith("output truncated")


def test_console_reports_timeout(client, monkeypatch):
    def fake_run(argv, **kw):
        raise appmod.subprocess.TimeoutExpired(argv, 25, output="partial\n")

    monkeypatch.setattr(appmod.subprocess, "run", fake_run)
    d = client.post("/api/console", json={"tool": "ping", "target": "example.com"}).get_json()
    assert d["timedOut"] is True
    assert d["exitCode"] is None
    assert "partial" in d["output"] and "timed out" in d["output"]


def test_console_cross_origin_blocked(client, spy_run):
    r = client.post("/api/console", json={"tool": "ping", "target": "example.com"},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403
    assert not spy_run


# ── Router detection ───────────────────────────────────────────────────────
# The whole point of detect_gateway is that our own default gateway is the wrong
# answer on Docker's bridge network, so these drive it from canned traceroute
# output rather than the network.
def _trace(*lines):
    return "traceroute to 1.1.1.1 (1.1.1.1), 5 hops max, 60 byte packets\n" + \
           "".join(" %d  %s\n" % (i + 1, l) for i, l in enumerate(lines))


@pytest.fixture
def fake_trace(monkeypatch):
    def install(output, own_gateway="172.21.0.1"):
        class _Proc:
            stdout, stderr, returncode = output, "", 0
        monkeypatch.setattr(appmod.shutil, "which", lambda x: "/usr/bin/" + x)
        monkeypatch.setattr(appmod.subprocess, "run", lambda argv, **kw: _Proc())
        monkeypatch.setattr(appmod, "_own_default_gateway", lambda: own_gateway)
    return install


def test_detect_gateway_skips_the_docker_bridge(fake_trace):
    # hop 1 is the bridge (i.e. the Docker host); the router is hop 2.
    fake_trace(_trace("172.21.0.1  0.070 ms", "192.168.2.254  1.968 ms",
                      "195.190.228.1  3.857 ms"))
    info, err = appmod.detect_gateway()
    assert err is None
    assert info["ip"] == "192.168.2.254"
    assert info["hop"] == 2
    assert info["ownGateway"] == "172.21.0.1"   # reported, but not chosen


def test_detect_gateway_on_host_networking(fake_trace):
    # No bridge in the way: the router is hop 1 and our own gateway, and the
    # same rule still picks it. This is why there's no "that's your own gateway,
    # it might be the bridge" warning — here that would be a false alarm.
    fake_trace(_trace("192.168.2.254  1.9 ms", "195.190.228.1  3.8 ms"),
               own_gateway="192.168.2.254")
    info, err = appmod.detect_gateway()
    assert err is None and info["ip"] == "192.168.2.254" and info["hop"] == 1


def test_detect_gateway_walks_past_silent_hops(fake_trace):
    fake_trace(_trace("* * *", "192.168.2.254  1.9 ms", "195.190.228.1  3.8 ms"))
    info, err = appmod.detect_gateway()
    assert err is None and info["ip"] == "192.168.2.254"


def test_detect_gateway_when_host_is_directly_public(fake_trace):
    fake_trace(_trace("195.190.228.1  3.8 ms", "1.1.1.1  9.0 ms"))
    info, err = appmod.detect_gateway()
    assert info is None and "no router in front" in err


def test_detect_gateway_reports_unusable_trace(fake_trace):
    fake_trace("traceroute to 1.1.1.1 (1.1.1.1), 5 hops max, 60 byte packets\n")
    info, err = appmod.detect_gateway()
    assert info is None and err


def test_router_endpoint_returns_gateway_and_dns(client, fake_trace, monkeypatch):
    fake_trace(_trace("172.21.0.1  0.07 ms", "192.168.2.254  1.9 ms",
                      "195.190.228.1  3.8 ms"))
    monkeypatch.setattr(appmod, "resolve",
                        lambda t: {"input": t, "ip": t, "hostname": "router.test",
                                   "aliases": []})
    d = client.get("/api/router").get_json()
    assert d["ip"] == "192.168.2.254"
    assert d["dns"]["hostname"] == "router.test"


def test_router_endpoint_reports_failure(client, fake_trace):
    fake_trace(_trace("195.190.228.1  3.8 ms"))
    r = client.get("/api/router")
    assert r.status_code == 502
    assert "error" in r.get_json()


def test_own_default_gateway_parses_proc_net_route(monkeypatch, tmp_path):
    # Gateway is a little-endian hex u32: 010015AC -> 172.21.0.1
    route = tmp_path / "route"
    route.write_text(
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\n"
        "eth0\t000015AC\t00000000\t0001\t0\t0\t0\t0000FFFF\n"
        "eth0\t00000000\t010015AC\t0003\t0\t0\t0\t00000000\n")
    real_open = open
    monkeypatch.setattr("builtins.open",
                        lambda p, *a, **k: real_open(route if p == "/proc/net/route" else p, *a, **k))
    assert appmod._own_default_gateway() == "172.21.0.1"


# ── Public IP ──────────────────────────────────────────────────────────────
# _fetch_public_ip is the only part that talks to the network, so stubbing it
# keeps these hermetic while still exercising the fallback/validation logic.
#
# The addresses below are globally routable ones (8.8.8.8 and friends) rather
# than the usual RFC 5737 documentation ranges: the endpoint accepts an answer
# only if ip_address().is_global, and 203.0.113.0/24 & 2001:db8::/32 are *not*
# global. Nothing is ever contacted — they are only ever compared as strings.
@pytest.fixture
def fake_sources(monkeypatch):
    """Drive get_public_ip from a {url: result} table. A result that is an
    Exception is raised, mimicking a source being down or rate-limiting."""
    def install(table, sources=None):
        if sources is not None:
            monkeypatch.setattr(appmod, "PUBLIC_IP_SOURCES", tuple(sources))
        def fake_fetch(url, timeout=6):
            got = table[url]
            if isinstance(got, Exception):
                raise got
            return got
        monkeypatch.setattr(appmod, "_fetch_public_ip", fake_fetch)
        # rDNS is a real DNS call; keep it off the network too.
        monkeypatch.setattr(appmod.socket, "gethostbyaddr",
                            lambda ip: ("host.example.net", [], [ip]))
    return install


def test_public_ip_returns_address_and_context(client, fake_sources):
    fake_sources({"u1": ("8.8.8.8", {"org": "Example ISP", "asn": "AS64496"})},
                 [("src1", "u1")])
    r = client.get("/api/public-ip")
    assert r.status_code == 200
    d = r.get_json()
    assert d["ip"] == "8.8.8.8"
    assert d["version"] == 4
    assert d["source"] == "src1"
    assert d["org"] == "Example ISP"
    assert d["reverseDns"] == "host.example.net"


def test_public_ip_falls_back_to_next_source(client, fake_sources):
    fake_sources({"u1": OSError("down"), "u2": ("9.9.9.9", {})},
                 [("src1", "u1"), ("src2", "u2")])
    d = client.get("/api/public-ip").get_json()
    assert d["ip"] == "9.9.9.9"
    assert d["source"] == "src2"
    assert d["failedSources"] == ["src1"]


def test_public_ip_skips_non_global_and_junk_answers(client, fake_sources):
    # A private address (proxy echoing an internal IP) and an HTML error page are
    # both wrong answers, not the public IP — neither should be returned.
    fake_sources({"u1": ("<html>rate limited</html>", {}),
                  "u2": ("192.168.1.1", {}),
                  "u3": ("1.1.1.1", {})},
                 [("src1", "u1"), ("src2", "u2"), ("src3", "u3")])
    d = client.get("/api/public-ip").get_json()
    assert d["ip"] == "1.1.1.1"
    assert d["failedSources"] == ["src1", "src2"]


def test_public_ip_reports_total_failure(client, fake_sources):
    fake_sources({"u1": OSError("down")}, [("src1", "u1")])
    r = client.get("/api/public-ip")
    assert r.status_code == 502
    assert "error" in r.get_json()


def test_public_ip_handles_ipv6(client, fake_sources):
    fake_sources({"u1": ("2606:4700::1111", {})}, [("src1", "u1")])
    d = client.get("/api/public-ip").get_json()
    assert d["version"] == 6


# ── Saved scans (shared engine: subnet + subdomains) ───────────────────────
def _subnet_result(*ips, subnet="192.168.1.0/24"):
    return {"subnet": subnet, "count": len(ips), "command": "nmap -sn " + subnet, "stderr": "",
            "hosts": [{"ip": ip, "hostname": None, "mac": None, "vendor": None,
                       "reason": "arp-response"} for ip in ips]}


def _subdomain_result(*names, domain="example.com"):
    return {"domain": domain, "sources": ["crt.sh"], "truncated": False, "count": len(names),
            "resolvingCount": len(names),
            "names": [{"name": n, "resolves": True, "addresses": ["1.2.3.4"]} for n in names]}


def _save(client, name="Home LAN", ips=("192.168.1.10",)):
    r = client.post("/api/saved-scans",
                    json={"tool": "subnet", "name": name, "data": _subnet_result(*ips)})
    assert r.status_code == 201, r.get_json()
    return r.get_json()["id"]


def _save_sub(client, name="Example", names=("www.example.com",)):
    r = client.post("/api/saved-scans",
                    json={"tool": "subdomains", "name": name, "data": _subdomain_result(*names)})
    assert r.status_code == 201, r.get_json()
    return r.get_json()["id"]


def test_diff_items():
    key = lambda i: i.get("ip")
    old = [{"ip": "10.0.0.1"}, {"ip": "10.0.0.2"}]
    new = [{"ip": "10.0.0.2"}, {"ip": "10.0.0.3"}]
    new_keys, gone = appmod._diff_items(old, new, key)
    assert new_keys == ["10.0.0.3"]
    assert [h["ip"] for h in gone] == ["10.0.0.1"]


def test_saved_scan_lifecycle(client):
    sid = _save(client, "Home LAN", ips=["192.168.1.10", "192.168.1.20"])

    listed = client.get("/api/saved-scans?tool=subnet").get_json()["scans"]
    assert any(s["id"] == sid and s["itemCount"] == 2 for s in listed)

    d = client.get(f"/api/saved-scans/{sid}").get_json()
    assert d["name"] == "Home LAN" and d["target"] == "192.168.1.0/24" and d["tool"] == "subnet"
    assert [h["ip"] for h in d["data"]["hosts"]] == ["192.168.1.10", "192.168.1.20"]
    assert d["notes"] == {}

    assert client.patch(f"/api/saved-scans/{sid}", json={"name": "Renamed"}).status_code == 200
    assert client.get(f"/api/saved-scans/{sid}").get_json()["name"] == "Renamed"

    assert client.delete(f"/api/saved-scans/{sid}").status_code == 200
    assert client.get(f"/api/saved-scans/{sid}").status_code == 404


def test_saved_scans_are_listed_per_tool(client):
    """The sidebar asks per tool; a subnet scan must never appear under Subdomains."""
    sid, sub = _save(client, "Net"), _save_sub(client, "Domains")
    subnet_ids = [s["id"] for s in client.get("/api/saved-scans?tool=subnet").get_json()["scans"]]
    sub_ids = [s["id"] for s in client.get("/api/saved-scans?tool=subdomains").get_json()["scans"]]
    assert sid in subnet_ids and sid not in sub_ids
    assert sub in sub_ids and sub not in subnet_ids
    assert client.get("/api/saved-scans?tool=nope").status_code == 400


def test_saved_scan_stores_replayable_payload(client):
    """The saved payload must keep the shape the live endpoint returns — the front
    end replays it through the same renderer, so a missing key would break the view."""
    sid = _save(client)
    data = client.get(f"/api/saved-scans/{sid}").get_json()["data"]
    assert set(data) == {"subnet", "hosts", "count", "command", "stderr"}
    assert set(data["hosts"][0]) == {"ip", "hostname", "mac", "vendor", "reason"}

    sub = _save_sub(client)
    sdata = client.get(f"/api/saved-scans/{sub}").get_json()["data"]
    assert set(sdata) == {"domain", "names", "count", "resolvingCount", "truncated", "sources"}
    assert set(sdata["names"][0]) == {"name", "resolves", "addresses"}


def test_saved_scan_ignores_unknown_client_fields(client):
    payload = _subnet_result("192.168.1.10")
    payload["evil"] = "x"
    payload["hosts"][0]["evil"] = "x"
    r = client.post("/api/saved-scans", json={"tool": "subnet", "name": "N", "data": payload})
    data = client.get(f"/api/saved-scans/{r.get_json()['id']}").get_json()["data"]
    assert "evil" not in data and "evil" not in data["hosts"][0]


def test_saved_scan_rejects_bad_input(client):
    bad = [
        {"tool": "subnet", "name": "", "data": _subnet_result("1.1.1.1")},   # no name
        {"tool": "subnet", "name": "N"},                                      # no data
        {"tool": "subnet", "name": "N", "data": {"hosts": []}},               # no subnet
        {"tool": "nope", "name": "N", "data": _subnet_result("1.1.1.1")},     # unknown tool
        {"name": "N", "data": _subnet_result("1.1.1.1")},                     # missing tool
        # Oversized prefix: the same cap the live scan enforces.
        {"tool": "subnet", "name": "N", "data": _subnet_result(subnet="10.0.0.0/8")},
        # A subdomains payload under the subnet tool has no `hosts` list.
        {"tool": "subnet", "name": "N", "data": _subdomain_result("www.example.com")},
        {"tool": "subdomains", "name": "N", "data": _subdomain_result(domain="not a domain")},
    ]
    for body in bad:
        assert client.post("/api/saved-scans", json=body).status_code == 400, body


def test_saved_scan_404s(client):
    assert client.get("/api/saved-scans/99999").status_code == 404
    assert client.patch("/api/saved-scans/99999", json={"name": "x"}).status_code == 404
    assert client.delete("/api/saved-scans/99999").status_code == 404
    assert client.put("/api/saved-scans/99999/notes/10.0.0.1", json={"note": "x"}).status_code == 404


def test_notes_set_update_and_clear(client):
    sid = _save(client)
    ip = "192.168.1.10"

    client.put(f"/api/saved-scans/{sid}/notes/{ip}", json={"note": "The NAS"})
    assert client.get(f"/api/saved-scans/{sid}").get_json()["notes"][ip]["note"] == "The NAS"

    client.put(f"/api/saved-scans/{sid}/notes/{ip}", json={"note": "The NAS (rack 2)"})
    notes = client.get(f"/api/saved-scans/{sid}").get_json()["notes"]
    assert notes[ip]["note"] == "The NAS (rack 2)"      # updated, not duplicated

    # Clearing the text removes the note rather than storing an empty one.
    client.put(f"/api/saved-scans/{sid}/notes/{ip}", json={"note": "   "})
    assert client.get(f"/api/saved-scans/{sid}").get_json()["notes"] == {}


def test_notes_work_for_subdomains(client):
    sid = _save_sub(client, names=["www.example.com", "mail.example.com"])
    client.put(f"/api/saved-scans/{sid}/notes/mail.example.com", json={"note": "MX host"})
    assert client.get(f"/api/saved-scans/{sid}").get_json()["notes"]["mail.example.com"]["note"] == "MX host"


def test_notes_are_scoped_to_their_scan(client):
    """The same IP in two saved scans is two different machines."""
    home, office = _save(client, "Home"), _save(client, "Office")
    client.put(f"/api/saved-scans/{home}/notes/192.168.1.10", json={"note": "my NAS"})
    client.put(f"/api/saved-scans/{office}/notes/192.168.1.10", json={"note": "the printer"})
    assert client.get(f"/api/saved-scans/{home}").get_json()["notes"]["192.168.1.10"]["note"] == "my NAS"
    assert client.get(f"/api/saved-scans/{office}").get_json()["notes"]["192.168.1.10"]["note"] == "the printer"


def test_notes_only_for_hosts_in_the_scan(client):
    """Notes are keyed to what the scan actually found, so the table can't be used
    to store arbitrary keys."""
    sid = _save(client, ips=["192.168.1.10"])
    assert client.put(f"/api/saved-scans/{sid}/notes/192.168.1.99",
                      json={"note": "x"}).status_code == 400
    assert client.put(f"/api/saved-scans/{sid}/notes/not an ip",
                      json={"note": "x"}).status_code == 400
    # A subdomain name is not a host of a subnet scan either.
    assert client.put(f"/api/saved-scans/{sid}/notes/www.example.com",
                      json={"note": "x"}).status_code == 400


def test_note_survives_on_a_host_that_went_away(client, monkeypatch):
    """A host that drops out of a refresh is still rendered (greyed), so its note
    must remain editable."""
    sid = _save(client, ips=["192.168.1.10", "192.168.1.20"])
    client.put(f"/api/saved-scans/{sid}/notes/192.168.1.20", json={"note": "the printer"})
    monkeypatch.setattr(appmod, "run_subnet_sweep",
                        lambda cidr: (_subnet_result("192.168.1.10"), None, 200))
    d = client.post(f"/api/saved-scans/{sid}/refresh").get_json()
    assert [h["ip"] for h in d["goneItems"]] == ["192.168.1.20"]
    assert d["notes"]["192.168.1.20"]["note"] == "the printer"
    assert client.put(f"/api/saved-scans/{sid}/notes/192.168.1.20",
                      json={"note": "the printer (unplugged)"}).status_code == 200


def test_deleting_scan_deletes_its_notes(client):
    """Notes are keyed on scan id, so orphans would be inherited by a later scan
    that reuses the id."""
    sid = _save(client)
    client.put(f"/api/saved-scans/{sid}/notes/192.168.1.10", json={"note": "secret"})
    client.delete(f"/api/saved-scans/{sid}")
    conn = appmod.get_db()
    try:
        left = conn.execute("SELECT COUNT(*) FROM host_notes WHERE scan_id=?", (sid,)).fetchone()[0]
    finally:
        conn.close()
    assert left == 0


def test_refresh_updates_result_keeps_notes_and_diffs(client, monkeypatch):
    sid = _save(client, ips=["192.168.1.10", "192.168.1.20"])
    client.put(f"/api/saved-scans/{sid}/notes/192.168.1.10", json={"note": "The NAS"})

    # .20 has gone away, .30 has appeared since the scan was saved.
    monkeypatch.setattr(appmod, "run_subnet_sweep",
                        lambda cidr: (_subnet_result("192.168.1.10", "192.168.1.30"), None, 200))
    d = client.post(f"/api/saved-scans/{sid}/refresh").get_json()

    assert [h["ip"] for h in d["data"]["hosts"]] == ["192.168.1.10", "192.168.1.30"]
    assert d["newKeys"] == ["192.168.1.30"]
    assert [h["ip"] for h in d["goneItems"]] == ["192.168.1.20"]
    assert d["lastRefreshed"]
    # The scan keeps its id across a refresh, which is what preserves notes.
    assert d["id"] == sid
    assert d["notes"]["192.168.1.10"]["note"] == "The NAS"


def test_refresh_uses_the_right_tool(client, monkeypatch):
    """A subdomains scan must refresh via the subdomain lookup, not the nmap sweep."""
    sid = _save_sub(client, names=["www.example.com"])
    monkeypatch.setattr(appmod, "run_subnet_sweep",
                        lambda t: pytest.fail("subnet sweep used for a subdomains scan"))
    monkeypatch.setattr(appmod, "run_subdomain_scan",
                        lambda domain: (_subdomain_result("www.example.com", "new.example.com"), None, 200))
    d = client.post(f"/api/saved-scans/{sid}/refresh").get_json()
    assert d["newKeys"] == ["new.example.com"]
    assert [n["name"] for n in d["data"]["names"]] == ["www.example.com", "new.example.com"]


def test_refresh_propagates_scan_failure(client, monkeypatch):
    sid = _save(client)
    monkeypatch.setattr(appmod, "run_subnet_sweep",
                        lambda cidr: (None, {"error": "nmap exploded"}, 500))
    r = client.post(f"/api/saved-scans/{sid}/refresh")
    assert r.status_code == 500
    assert r.get_json()["error"] == "nmap exploded"
    # A failed refresh must not clobber the stored result.
    assert client.get(f"/api/saved-scans/{sid}").get_json()["data"]["hosts"]


def test_saved_scans_cross_origin_blocked(client):
    r = client.post("/api/saved-scans",
                    json={"tool": "subnet", "name": "N", "data": _subnet_result("1.1.1.1")},
                    headers={"Origin": "http://evil.example"})
    assert r.status_code == 403


# ── Migration from the subnet-only schema ──────────────────────────────────
def test_migration_from_legacy_subnet_schema(tmp_path):
    """Saved scans shipped subnet-only first (cidr/ip/new_ips/gone_hosts). Existing
    scans and their notes must survive the rename to the generic shape."""
    import sqlite3
    db = tmp_path / "legacy.db"
    conn = sqlite3.connect(db)
    conn.executescript("""
      CREATE TABLE saved_scans (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, cidr TEXT NOT NULL,
        data TEXT NOT NULL, new_ips TEXT NOT NULL DEFAULT '[]',
        gone_hosts TEXT NOT NULL DEFAULT '[]', created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL, last_refreshed TEXT);
      CREATE TABLE host_notes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER NOT NULL, ip TEXT NOT NULL,
        note TEXT NOT NULL, updated_at TEXT NOT NULL, UNIQUE(scan_id, ip));
    """)
    conn.execute("INSERT INTO saved_scans (name, cidr, data, created_at, updated_at) "
                 "VALUES ('Home LAN', '192.168.2.0/24', ?, 't', 't')",
                 (json.dumps(_subnet_result("192.168.2.120")),))
    conn.execute("INSERT INTO host_notes (scan_id, ip, note, updated_at) "
                 "VALUES (1, '192.168.2.120', 'Unknown device', 't')")
    conn.commit()
    conn.close()

    old_path = appmod.DB_PATH
    appmod.DB_PATH = str(db)
    try:
        appmod.init_db()
        appmod.init_db()          # must be idempotent
        conn = appmod.get_db()
        cols = [r[1] for r in conn.execute("PRAGMA table_info(saved_scans)")]
        assert "target" in cols and "tool" in cols and "cidr" not in cols
        assert "host" in [r[1] for r in conn.execute("PRAGMA table_info(host_notes)")]
        row = conn.execute("SELECT tool, name, target FROM saved_scans WHERE id=1").fetchone()
        assert (row["tool"], row["name"], row["target"]) == ("subnet", "Home LAN", "192.168.2.0/24")
        note = conn.execute("SELECT host, note FROM host_notes WHERE scan_id=1").fetchone()
        assert (note["host"], note["note"]) == ("192.168.2.120", "Unknown device")
        conn.close()
    finally:
        appmod.DB_PATH = old_path
