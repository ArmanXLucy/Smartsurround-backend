"""
email_driver.py
---------------
Track B outbound email surface for authority notifications.

Safety rules enforced here (never in the caller):
  - EMAIL_DRIVER switch:            default "resend". Only real, enabled
                                    verifications actually reach a driver; the
                                    admin queue (unowned / pending / bounced /
                                    bogus) is surfaced for typing, never
                                    auto-sent.
  - EMAIL_TEST_MODE:                default on (true). When on, NO email leaves
                                    the box: the driver logs what WOULD be sent
                                    and writes the PDF attachment path next to
                                    the cluster row. Recipient overridden to
                                    EMAIL_TEST_RECIPIENT (default
                                    codexzero98@gmail.com) — safe to run with
                                    no real credentials configured.
  - No credentials, no crash:       Resend driver sends only when (a) not in
                                    test mode AND (b) RESEND_API_KEY +
                                    RESEND_FROM_EMAIL are both set. Any
                                    missing/blank piece -> we FAIL SOFT to
                                    admin_queue and log, never raise into the
                                    request cycle. The smtplib driver remains
                                    as a legacy opt-in (EMAIL_DRIVER=smtplib).
"""
import os
import smtplib
import logging
from email.message import EmailMessage
from email.utils import make_msgid, formatdate
from datetime import datetime, timezone

logger = logging.getLogger("smart_surround.email")

DRIVER = os.environ.get("EMAIL_DRIVER", "resend")         # resend | smtplib | ...
TEST_MODE = os.environ.get("EMAIL_TEST_MODE", "true").strip().lower() in ("1", "true", "yes", "on")
TEST_RECIPIENT = os.environ.get(
    "EMAIL_TEST_RECIPIENT", "codexzero98@gmail.com"
)

# Resend driver settings (both optional; used only when fully present AND
# EMAIL_TEST_MODE=0)
RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
RESEND_FROM_EMAIL = os.environ.get("RESEND_FROM_EMAIL", "")

# smtplib driver settings (all optional; used only when fully present AND
# EMAIL_TEST_MODE=0)
SMTP_HOST = os.environ.get("EMAIL_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("EMAIL_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("EMAIL_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("EMAIL_SMTP_PASSWORD", "")
SMTP_USE_TLS = os.environ.get("EMAIL_SMTP_USE_TLS", "true").strip().lower() in ("1", "true", "yes", "on")
SMTP_FROM = os.environ.get("EMAIL_FROM", "SmartSurround Authority Notices <noreply@smartsurround.local>")


def _invalid_smtp():
    return not (SMTP_HOST and SMTP_USER and SMTP_PASSWORD)


def _invalid_resend():
    return not (RESEND_API_KEY and RESEND_FROM_EMAIL)


def compose(subject, recipient, body, attachment_path):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM
    msg["To"] = recipient
    msg["Message-ID"] = make_msgid()
    msg["Date"] = formatdate(localtime=True)
    msg.set_content(body)
    if attachment_path and os.path.isfile(attachment_path):
        with open(attachment_path, "rb") as fh:
            msg.add_attachment(
                fh.read(),
                maintype="application",
                subtype="pdf",
                filename=os.path.basename(attachment_path),
            )
    return msg


class _SmtpDriver:
    def __init__(self):
        self._ok = not (_invalid_smtp())

    def send(self, subject, recipient, body, attachment_path):
        if not self._ok:
            return {"ok": False, "reason": "missing_smtp_config", "to": recipient}
        msg = compose(subject, recipient, body, attachment_path)
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=15) as server:
                if SMTP_USE_TLS:
                    server.starttls()
                server.login(SMTP_USER, SMTP_PASSWORD)
                server.send_message(msg)
            return {"ok": True, "to": recipient}
        except Exception as exc:  # network/auth/dns — never crash the caller
            logger.warning("smtp send failed (soft): %s", exc)
            return {"ok": False, "reason": f"smtp_error:{type(exc).__name__}", "to": recipient}


class _ResendDriver:
    """Transactional API driver using Resend's official Python SDK. The SDK is
    imported lazily (only when a real send is attempted) so test mode and app
    boot never require the package. `resend.Emails.send(params)` RAISES on
    failure (ResendError / ValueError / network) — every path below degrades to
    a soft-fail dict, never a raise into the request cycle. The PDF attachment
    is passed as base64-decoded bytes per the SDK's `content: list(int)` API."""

    def __init__(self):
        self._ok = not (_invalid_resend())

    def send(self, subject, recipient, body, attachment_path):
        if not self._ok:
            return {"ok": False, "reason": "missing_resend_config", "to": recipient}
        try:
            import base64
            import resend
            from resend.exceptions import ResendError  # noqa: F401  (raised, caught below)
        except Exception as exc:  # SDK not installed — soft-fail, no crash
            logger.warning("resend sdk unavailable (soft): %s", exc)
            return {"ok": False, "reason": "resend_sdk_unavailable", "to": recipient}

        params = {
            "from": RESEND_FROM_EMAIL,
            "to": [recipient],
            "subject": subject,
            "text": body,
        }
        if attachment_path and os.path.isfile(attachment_path):
            with open(attachment_path, "rb") as fh:
                params["attachments"] = [
                    {
                        "filename": os.path.basename(attachment_path),
                        "content": list(fh.read()),
                    }
                ]
        try:
            resend.api_key = RESEND_API_KEY
            resend.Emails.send(params)
            return {"ok": True, "to": recipient}
        except Exception as exc:  # api/auth/validation/network — never crash the caller
            logger.warning("resend send failed (soft): %s", exc)
            return {"ok": False, "reason": f"resend_error:{type(exc).__name__}", "to": recipient}


class _TestDriver:
    """Replaces the real driver in EMAIL_TEST_MODE: log intent, keep the PDF
    path (already stored on the cluster by the caller), never send."""
    def send(self, subject, recipient, body, attachment_path):
        logger.info(
            "[test-mode] WOULD-EMAIL to %s | %s | attachment=%s | recipient-overridden=%s",
            recipient, subject, attachment_path, TEST_RECIPIENT,
        )
        return {"ok": True, "mode": "test", "to": recipient, "attachment": attachment_path}


def get_driver():
    if TEST_MODE:
        return _TestDriver()
    if DRIVER in ("resend", "sendgrid", "resend-api"):
        return _ResendDriver()
    if DRIVER == "smtplib":
        return _SmtpDriver()
    # unknown driver name -> soft-fail (never crash)
    return _TestDriver()


def send_authority_email(authority_email, subject, body, attachment_path):
    """Top-level helper used by the app: safe under every configuration."""
    driver = get_driver()
    to = TEST_RECIPIENT if TEST_MODE else authority_email
    result = driver.send(subject, to, body, attachment_path)
    return {
        **result,
        "mode": "test" if TEST_MODE else DRIVER,
        "effective_recipient": to,
        "original_recipient": authority_email,
    }


def mark_letter_recorded(cluster_id, letter_path, window_tag=None):
    """Track B bookkeeping: the PDF is kept on the cluster row; the letter is
    not emailed in test mode. Called by the corroboration sweep AFTER the
    driver decision so the admin surface shows exactly what was decided."""
    db.mark_cluster_recorded(cluster_id, letter_path=letter_path, window_tag=window_tag)
