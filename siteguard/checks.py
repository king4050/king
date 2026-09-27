"""Passive, non-intrusive security checks for a domain whose owner has verified it.

Every check makes ordinary requests a browser or mail server would make
(one TLS handshake, a handful of GETs, public DNS lookups). Nothing here
attempts exploitation, brute force, or load.
"""
import datetime as dt
import ipaddress
import socket
import ssl
import urllib.error
import urllib.request

import dns.exception
import dns.resolver

USER_AGENT = "SiteGuard-Monitor/1.0 (+owner-verified security health check)"
TIMEOUT = 10

SEVERITY_PENALTY = {"high": 25, "medium": 10, "low": 4, "info": 0}

# Paths that should never be publicly readable, with a signature that
# distinguishes a real leak from a catch-all 200 page.
SENSITIVE_PATHS = {
    "/.git/HEAD": "ref:",
    "/.env": "=",
    "/.DS_Store": "Bud1",
    "/backup.sql": "INSERT INTO",
}


class UnsafeTarget(Exception):
    pass


def finding(fid, severity, title, fix):
    return {"id": fid, "severity": severity, "title": title, "fix": fix}


def assert_public(host, resolve=socket.getaddrinfo):
    """Refuse hosts that resolve to private/internal addresses (SSRF guard)."""
    try:
        infos = resolve(host, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as e:
        raise UnsafeTarget(f"cannot resolve {host}") from e
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise UnsafeTarget(f"{host} resolves to non-public address {ip}")


# ---------- network primitives (replaceable in tests) ----------

def fetch_cert(host):
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


_opener = urllib.request.build_opener(_NoRedirect)


def http_get(url):
    """Return (status, headers-dict-lowercased, first 2KB of body)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        resp = _opener.open(req, timeout=TIMEOUT)
    except urllib.error.HTTPError as e:
        resp = e
    headers = {k.lower(): v for k, v in resp.headers.items()}
    body = resp.read(2048).decode("utf-8", "replace")
    return resp.status, headers, body


def txt_records(name):
    try:
        answers = dns.resolver.resolve(name, "TXT", lifetime=TIMEOUT)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return []
    except dns.exception.DNSException as e:
        # Resolver trouble is not evidence of a missing record; don't report a false finding.
        raise OSError(f"DNS lookup failed for {name}") from e
    return [b"".join(r.strings).decode("utf-8", "replace") for r in answers]


# ---------- individual checks ----------

def check_tls(host, now=None, get_cert=fetch_cert):
    now = now or dt.datetime.now(dt.timezone.utc)
    try:
        cert = get_cert(host)
    except ssl.SSLCertVerificationError:
        return [finding("tls_invalid", "high", "شهادة SSL غير صالحة أو غير موثوقة",
                        "جدد الشهادة من جهة موثوقة (مثل Let's Encrypt المجانية).")]
    except OSError:
        return [finding("tls_unreachable", "high", "الموقع لا يعمل عبر HTTPS",
                        "فعّل HTTPS على الاستضافة وثبّت شهادة SSL.")]
    expires = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
    days = (expires - now).days
    if days < 0:
        return [finding("tls_expired", "high", "شهادة SSL منتهية", "جدد الشهادة فورًا.")]
    if days <= 14:
        return [finding("tls_expiring", "medium", f"شهادة SSL تنتهي خلال {days} يوم",
                        "جدد الشهادة أو فعّل التجديد التلقائي.")]
    return []


def check_http(host, get=http_get):
    out = []
    try:
        status, headers, _ = get(f"http://{host}/")
        if not (300 <= status < 400 and headers.get("location", "").startswith("https://")):
            out.append(finding("no_https_redirect", "medium", "الموقع لا يحوّل الزوار تلقائيًا إلى HTTPS",
                               "أضف تحويل 301 من http إلى https."))
    except OSError:
        pass

    try:
        status, headers, _ = get(f"https://{host}/")
    except OSError:
        return out

    if "strict-transport-security" not in headers:
        out.append(finding("hsts_missing", "medium", "ترويسة HSTS غير موجودة",
                           "أضف: Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    csp = headers.get("content-security-policy", "")
    if not csp:
        out.append(finding("csp_missing", "low", "لا توجد سياسة Content-Security-Policy",
                           "أضف سياسة CSP تحدد مصادر السكربتات المسموح بها."))
    if headers.get("x-content-type-options", "").lower() != "nosniff":
        out.append(finding("nosniff_missing", "low", "ترويسة X-Content-Type-Options غير مضبوطة",
                           "أضف: X-Content-Type-Options: nosniff"))
    if "x-frame-options" not in headers and "frame-ancestors" not in csp:
        out.append(finding("clickjacking", "low", "الموقع غير محمي من Clickjacking",
                           "أضف: X-Frame-Options: DENY أو frame-ancestors في CSP"))
    if "referrer-policy" not in headers:
        out.append(finding("referrer_missing", "low", "لا توجد Referrer-Policy",
                           "أضف: Referrer-Policy: strict-origin-when-cross-origin"))
    server = headers.get("server", "") + headers.get("x-powered-by", "")
    if any(ch.isdigit() for ch in server):
        out.append(finding("version_leak", "low", "السيرفر يكشف رقم إصدار البرمجيات",
                           "أخفِ رقم الإصدار من ترويستي Server و X-Powered-By."))

    for path, signature in SENSITIVE_PATHS.items():
        try:
            status, _, body = get(f"https://{host}{path}")
        except OSError:
            continue
        if status == 200 and signature in body:
            out.append(finding(f"exposed:{path}", "high", f"ملف حساس مكشوف للعامة: {path}",
                               "احذف الملف من مجلد الموقع أو امنع الوصول إليه من إعدادات السيرفر."))
    return out


def check_email_dns(domain, txt=txt_records):
    try:
        root, dmarc_txt = txt(domain), txt(f"_dmarc.{domain}")
    except OSError:
        return []
    out = []
    if not any(r.lower().startswith("v=spf1") for r in root):
        out.append(finding("spf_missing", "medium", "لا يوجد سجل SPF (يمكن انتحال بريدك)",
                           "أضف سجل TXT يبدأ بـ v=spf1 يحدد خوادم البريد المسموحة."))
    dmarc = [r for r in dmarc_txt if r.lower().startswith("v=dmarc1")]
    if not dmarc:
        out.append(finding("dmarc_missing", "medium", "لا يوجد سجل DMARC",
                           "أضف سجل TXT على _dmarc بقيمة: v=DMARC1; p=quarantine; rua=mailto:you@domain"))
    elif "p=none" in dmarc[0].lower().replace(" ", ""):
        out.append(finding("dmarc_weak", "low", "سياسة DMARC في وضع المراقبة فقط (p=none)",
                           "بعد التأكد من سلامة البريد، غيّرها إلى p=quarantine أو p=reject."))
    return out


def score(findings):
    return max(0, 100 - sum(SEVERITY_PENALTY[f["severity"]] for f in findings))


def run_all(domain, *, resolve=socket.getaddrinfo, get_cert=fetch_cert, get=http_get, txt=txt_records):
    assert_public(domain, resolve)
    findings = check_tls(domain, get_cert=get_cert) + check_http(domain, get=get) + check_email_dns(domain, txt=txt)
    return score(findings), findings
