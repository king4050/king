"""Domain ownership verification via a DNS TXT record.

The owner proves control by publishing:
    _siteguard.<domain>  TXT  "siteguard-verify=<token>"
Scans never run against a domain until this succeeds.
"""
import re
import secrets

from . import checks

DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


def normalize(domain):
    d = domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    d = d.removeprefix("www.")
    return d if DOMAIN_RE.match(d) else None


def new_token():
    return secrets.token_urlsafe(24)


def record_name(domain):
    return f"_siteguard.{domain}"


def record_value(token):
    return f"siteguard-verify={token}"


def is_verified(domain, token, txt=checks.txt_records):
    try:
        return record_value(token) in txt(record_name(domain))
    except OSError:
        return False
