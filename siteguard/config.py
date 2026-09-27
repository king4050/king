import os

DATABASE = os.environ.get("SITEGUARD_DB", "siteguard.db")
SECRET_KEY = os.environ.get("SITEGUARD_SECRET_KEY", "dev-only-change-me")
BASE_URL = os.environ.get("SITEGUARD_BASE_URL", "http://localhost:8000")

SMTP_HOST = os.environ.get("SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("SMTP_PORT", "587"))
SMTP_USER = os.environ.get("SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SMTP_PASSWORD", "")
MAIL_FROM = os.environ.get("MAIL_FROM", "alerts@example.com")

# Stripe Payment Links (created in the Stripe dashboard) and webhook signing secret.
STRIPE_LINK_PRO = os.environ.get("STRIPE_LINK_PRO", "")
STRIPE_LINK_BUSINESS = os.environ.get("STRIPE_LINK_BUSINESS", "")
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "")

CHECK_INTERVAL_HOURS = int(os.environ.get("CHECK_INTERVAL_HOURS", "24"))

PLANS = {
    "free": {"name": "مجاني", "price": 0, "domains": 1},
    "pro": {"name": "احترافي", "price": 9, "domains": 5},
    "business": {"name": "أعمال", "price": 29, "domains": 25},
}
