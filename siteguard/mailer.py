import logging
import smtplib
from email.message import EmailMessage

from . import config

log = logging.getLogger(__name__)


def send(to, subject, body):
    if not config.SMTP_HOST:
        log.info("SMTP not configured; would email %s: %s\n%s", to, subject, body)
        return False
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = config.MAIL_FROM, to, subject
    msg.set_content(body)
    with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=30) as s:
        s.starttls()
        if config.SMTP_USER:
            s.login(config.SMTP_USER, config.SMTP_PASSWORD)
        s.send_message(msg)
    return True
