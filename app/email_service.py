"""Email delivery via Resend's HTTPS API (compatible with Render's free service)."""
import json
import os
import urllib.error
import urllib.request
from html import escape


class EmailDeliveryError(RuntimeError):
    """Raised when the configured email provider rejects a message."""


def send_password_reset_email(to_email: str, reset_url: str) -> None:
    """Send a reset message through Resend; no secrets are written to logs."""
    api_key = os.getenv("RESEND_API_KEY", "").strip()
    if not api_key:
        raise EmailDeliveryError("RESEND_API_KEY is not configured")

    sender = os.getenv("RESEND_FROM_EMAIL", "CloudAuth <onboarding@resend.dev>").strip()
    safe_url = escape(reset_url, quote=True)
    message = {
        "from": sender,
        "to": [to_email],
        "subject": "Reset your CloudAuth password",
        "html": (
            "<div style=\"font-family:Arial,sans-serif;max-width:600px;margin:auto;color:#182338\">"
            "<h2>Reset your CloudAuth password</h2>"
            "<p>We received a request to reset the password for your CloudAuth account.</p>"
            f"<p><a href=\"{safe_url}\" style=\"display:inline-block;padding:12px 18px;background:#176e68;color:white;"
            "border-radius:8px;text-decoration:none\">Reset password</a></p>"
            "<p>This link expires in 20 minutes and can be used only once. If you did not request this, "
            "you can ignore this email.</p><p>For your security, do not share this link.</p></div>"
        ),
        "text": (
            "We received a request to reset your CloudAuth password.\n\n"
            f"Use this one-time link within 20 minutes: {reset_url}\n\n"
            "If you did not request this, ignore this email. Do not share the link."
        ),
    }
    request = urllib.request.Request(
        "https://api.resend.com/emails",
        data=json.dumps(message).encode("utf-8"),
        headers={"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            if not 200 <= response.status < 300:
                raise EmailDeliveryError(f"Email provider returned HTTP {response.status}")
    except urllib.error.HTTPError as exc:
        # Never relay provider response text: it may contain account or request metadata.
        raise EmailDeliveryError(f"Email provider returned HTTP {exc.code}") from None
    except (urllib.error.URLError, TimeoutError) as exc:
        raise EmailDeliveryError("Email provider could not be reached") from None
