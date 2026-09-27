import datetime as dt
import hashlib
import hmac
import json
import re
import socket
import ssl

import pytest

from siteguard import billing, checks, db, monitor, verify
from siteguard.app import create_app


# ---------- checks ----------

def fake_resolve(ip):
    return lambda host, port, proto=0: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]


def test_assert_public_blocks_private_addresses():
    for ip in ("127.0.0.1", "10.0.0.5", "169.254.169.254", "192.168.1.1"):
        with pytest.raises(checks.UnsafeTarget):
            checks.assert_public("evil.test", fake_resolve(ip))
    checks.assert_public("ok.test", fake_resolve("93.184.216.34"))


def cert_expiring_in(days):
    exp = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=days)
    return lambda host: {"notAfter": exp.strftime("%b %d %H:%M:%S %Y GMT")}


def test_tls_expiry_levels():
    assert checks.check_tls("x", get_cert=cert_expiring_in(90)) == []
    assert checks.check_tls("x", get_cert=cert_expiring_in(5))[0]["id"] == "tls_expiring"
    assert checks.check_tls("x", get_cert=cert_expiring_in(-2))[0]["id"] == "tls_expired"

    def bad(host):
        raise ssl.SSLCertVerificationError("bad")
    assert checks.check_tls("x", get_cert=bad)[0]["id"] == "tls_invalid"


GOOD_HEADERS = {
    "strict-transport-security": "max-age=31536000",
    "content-security-policy": "default-src 'self'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    "server": "nginx",
}


def make_get(https_headers, exposed=()):
    def get(url):
        if url.startswith("http://"):
            return 301, {"location": "https://x/"}, ""
        path = re.sub(r"^https://[^/]+", "", url)
        if path == "/":
            return 200, https_headers, "<html>"
        if path in exposed:
            return 200, {}, checks.SENSITIVE_PATHS[path] + " stuff"
        return 404, {}, "not found"
    return get


def test_hardened_site_has_no_http_findings():
    assert checks.check_http("x", get=make_get(GOOD_HEADERS)) == []


def test_missing_headers_and_exposed_files_are_reported():
    ids = {f["id"] for f in checks.check_http("x", get=make_get({"server": "Apache/2.4.1"}, exposed={"/.git/HEAD"}))}
    assert {"hsts_missing", "csp_missing", "nosniff_missing", "clickjacking", "referrer_missing",
            "version_leak", "exposed:/.git/HEAD"} <= ids


def test_catch_all_200_is_not_a_false_positive():
    def get(url):
        return 200, GOOD_HEADERS, "<html>welcome</html>"
    ids = {f["id"] for f in checks.check_http("x", get=get)}
    assert not any(i.startswith("exposed:") for i in ids)


def test_email_dns():
    records = {"x": ["v=spf1 include:_spf.google.com ~all"], "_dmarc.x": ["v=DMARC1; p=none"]}
    ids = {f["id"] for f in checks.check_email_dns("x", txt=lambda n: records.get(n, []))}
    assert ids == {"dmarc_weak"}
    ids = {f["id"] for f in checks.check_email_dns("x", txt=lambda n: [])}
    assert ids == {"spf_missing", "dmarc_missing"}


def test_score():
    assert checks.score([]) == 100
    assert checks.score([{"severity": "high"}] * 5) == 0


# ---------- verification ----------

def test_normalize():
    assert verify.normalize("https://www.Example.com/path") == "example.com"
    assert verify.normalize("localhost") is None
    assert verify.normalize("bad domain.com") is None


def test_is_verified():
    token = "abc"
    good = lambda name: [verify.record_value(token)] if name == "_siteguard.ex.com" else []
    assert verify.is_verified("ex.com", token, txt=good)
    assert not verify.is_verified("ex.com", "other", txt=good)


# ---------- billing ----------

def sign(payload, secret, ts):
    return f"t={ts},v1=" + hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()


def test_signature_verification():
    payload = b'{"type":"x"}'
    assert billing.verify_signature(payload, sign(payload, "s", 1000), "s", now=1000) == {"type": "x"}
    with pytest.raises(billing.BadSignature):
        billing.verify_signature(payload, sign(payload, "wrong", 1000), "s", now=1000)
    with pytest.raises(billing.BadSignature):
        billing.verify_signature(payload, sign(payload, "s", 1000), "s", now=5000)


# ---------- monitor ----------

@pytest.fixture
def dbpath(tmp_path):
    p = str(tmp_path / "t.db")
    db.init(p)
    return p


def test_monitor_alerts_only_on_new_findings(dbpath):
    with db.session(dbpath) as c:
        c.execute("INSERT INTO users (email, password_hash) VALUES ('a@b.c', 'x')")
        c.execute("INSERT INTO domains (user_id, name, token, verified_at) VALUES (1, 'ex.com', 't', datetime('now'))")
        c.execute("INSERT INTO domains (user_id, name, token) VALUES (1, 'unverified.com', 't')")

    sent, scanned = [], []
    f1 = checks.finding("hsts_missing", "medium", "t", "f")

    def run(name):
        scanned.append(name)
        return 90, [f1]

    monitor.run_once(dbpath, run=run, send=lambda *a: sent.append(a))
    assert scanned == ["ex.com"]  # never scans unverified domains
    assert len(sent) == 1

    with db.session(dbpath) as c:
        c.execute("UPDATE domains SET last_checked_at = datetime('now', '-2 days')")
    monitor.run_once(dbpath, run=run, send=lambda *a: sent.append(a))
    assert len(sent) == 1  # same finding, no repeat alert


# ---------- web app ----------

@pytest.fixture
def client(dbpath):
    records = {}
    app = create_app(dbpath, txt=lambda n: records.get(n, []), run_checks=lambda d: (75, []))
    app.config["TESTING"] = True
    c = app.test_client()
    c.records = records
    return c


def csrf(client):
    client.get("/")
    with client.session_transaction() as s:
        return s["csrf"]


def test_full_flow(client, dbpath):
    tok = csrf(client)
    assert client.post("/signup", data={"email": "o@ex.com", "password": "short", "csrf": tok}).status_code == 200
    r = client.post("/signup", data={"email": "o@ex.com", "password": "longpassword", "csrf": tok})
    assert r.headers["Location"].endswith("/dashboard")
    tok = csrf(client)  # session (and CSRF token) is rotated on login

    r = client.post("/domains", data={"domain": "https://www.shop.com/", "csrf": tok})
    assert r.headers["Location"].endswith("/domains/1")
    page = client.get("/domains/1").get_data(as_text=True)
    assert "_siteguard.shop.com" in page

    # Scan refused before verification.
    assert client.post("/domains/1/scan", data={"csrf": tok}).status_code == 403

    token = re.search(r"siteguard-verify=([\w-]+)", page).group(1)
    client.records["_siteguard.shop.com"] = [f"siteguard-verify={token}"]
    client.post("/domains/1/verify", data={"csrf": tok})
    assert "75/100" in client.get("/domains/1").get_data(as_text=True)

    # Free plan allows one domain.
    client.post("/domains", data={"domain": "second.com", "csrf": tok})
    with db.session(dbpath) as c:
        assert c.execute("SELECT COUNT(*) FROM domains").fetchone()[0] == 1


def test_csrf_required(client):
    csrf(client)
    assert client.post("/signup", data={"email": "a@b.com", "password": "longpassword"}).status_code == 400


def test_other_users_domains_are_private(client, dbpath):
    with db.session(dbpath) as c:
        c.execute("INSERT INTO users (email, password_hash) VALUES ('x@y.z', 'x')")
        c.execute("INSERT INTO domains (user_id, name, token) VALUES (1, 'secret.com', 't')")
    tok = csrf(client)
    client.post("/signup", data={"email": "me@me.com", "password": "longpassword", "csrf": tok})
    csrf(client)
    assert client.get("/domains/1").status_code == 404


def test_stripe_webhook_upgrades_plan(client, dbpath, monkeypatch):
    monkeypatch.setattr("siteguard.config.STRIPE_WEBHOOK_SECRET", "whsec")
    with db.session(dbpath) as c:
        c.execute("INSERT INTO users (email, password_hash) VALUES ('p@p.com', 'x')")
    event = {"type": "checkout.session.completed",
             "data": {"object": {"amount_total": 900, "client_reference_id": "1", "customer": "cus_1"}}}
    payload = json.dumps(event).encode()
    import time
    ts = int(time.time())
    assert client.post("/stripe/webhook", data=payload, headers={"Stripe-Signature": "t=1,v1=bad"}).status_code == 400
    assert client.post("/stripe/webhook", data=payload, headers={"Stripe-Signature": sign(payload, "whsec", ts)}).status_code == 200
    with db.session(dbpath) as c:
        assert c.execute("SELECT plan FROM users").fetchone()[0] == "pro"

    cancel = json.dumps({"type": "customer.subscription.deleted", "data": {"object": {"customer": "cus_1"}}}).encode()
    client.post("/stripe/webhook", data=cancel, headers={"Stripe-Signature": sign(cancel, "whsec", ts)})
    with db.session(dbpath) as c:
        assert c.execute("SELECT plan FROM users").fetchone()[0] == "free"


def test_dns_failure_is_not_a_finding():
    def broken(name):
        raise OSError("resolver down")
    assert checks.check_email_dns("x", txt=broken) == []
    assert not verify.is_verified("x.com", "t", txt=broken)
