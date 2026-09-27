"""Stripe webhook handling without the Stripe SDK (signature check per Stripe docs)."""
import hashlib
import hmac
import json
import time

from . import config

AMOUNT_TO_PLAN = {config.PLANS["pro"]["price"] * 100: "pro",
                  config.PLANS["business"]["price"] * 100: "business"}


class BadSignature(Exception):
    pass


def verify_signature(payload: bytes, header: str, secret: str, tolerance=300, now=None):
    parts = dict(p.split("=", 1) for p in header.split(",") if "=" in p)
    ts, sig = parts.get("t"), parts.get("v1")
    if not ts or not sig or not secret:
        raise BadSignature("missing signature")
    expected = hmac.new(secret.encode(), f"{ts}.".encode() + payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, sig):
        raise BadSignature("signature mismatch")
    if abs((now or time.time()) - int(ts)) > tolerance:
        raise BadSignature("timestamp outside tolerance")
    return json.loads(payload)


def apply_event(conn, event):
    """Update a user's plan from a Stripe event. Returns True if something changed."""
    obj = event.get("data", {}).get("object", {})
    kind = event.get("type")
    if kind == "checkout.session.completed":
        plan = AMOUNT_TO_PLAN.get(obj.get("amount_total"))
        user_id = obj.get("client_reference_id")
        if plan and user_id and str(user_id).isdigit():
            cur = conn.execute("UPDATE users SET plan = ?, stripe_customer = ? WHERE id = ?",
                               (plan, obj.get("customer"), int(user_id)))
            return cur.rowcount > 0
    elif kind == "customer.subscription.deleted":
        cur = conn.execute("UPDATE users SET plan = 'free' WHERE stripe_customer = ?", (obj.get("customer"),))
        return cur.rowcount > 0
    return False
