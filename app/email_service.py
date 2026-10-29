"""Email delivery via Resend's HTTPS API with safe diagnostic errors."""
import json
import os
import re
import urllib.error
import urllib.request
from html import escape


class EmailDeliveryError(RuntimeError):
    """Raised when the configured email provider rejects a message."""


def _provider_error_message(raw: bytes, *, api_key: str, sender: str, recipient: str) -> str:
    """Extract a short provider error without logging credentials or reset links."""
    try:
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError):
        return "provider returned a non-JSON error response"

    if not isinstance(data, dict):
        return "provider returned an unexpected error response"

    error_name = data.get("name") or data.get("type") or "provider_error"
    message = data.get("message") or data.get("error") or "request rejected"
    message = str(message)
    for secret in (api_key, recipient, sender):
        if secret:
            message = message.replace(secret, "[redacted]")
    message = re.sub(r"re_[A-Za-z0-9_-]+", "[redacted-api-key]", message)
    message = " ".join(message.split())[:240]
    return f"{error_name}: {message}"


def send_password_reset_email(to_email: str, reset_url: str) -> None:
    """Send a reset message through Resend; never log message content or secrets."""
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
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
            # Resend is fronted by edge security; identify this service rather than
            # urllib's default generic User-Agent, which can be rejected upstream.
            "User-Agent": "CloudAuth/1.0 (+https://cloudauth-demo.onrender.com)",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            if not 200 <= response.status < 300:
                raise EmailDeliveryError(f"Resend rejected email request (HTTP {response.status})")
            # Do not log the response body, recipient, or reset URL.
            import logging
            logging.getLogger(__name__).info("Resend accepted password-reset email request (HTTP %s)", response.status)
    except urllib.error.HTTPError as exc:
        # Capture only non-secret edge diagnostics. A Cloudflare-generated 403
        # may never reach Resend, so the Ray ID is useful for provider support.
        raw_body = exc.read(4096)
        details = _provider_error_message(
            raw_body, api_key=api_key, sender=sender, recipient=to_email
        )
        content_type = str(exc.headers.get("Content-Type", "unknown"))[:100]
        server = str(exc.headers.get("Server", "unknown"))[:100]
        ray_id = str(exc.headers.get("CF-Ray", exc.headers.get("cf-ray", "")))[:100]
        diagnostics = f"content-type={content_type}; server={server}"
        if ray_id:
            diagnostics += f"; cf-ray={ray_id}"
        raise EmailDeliveryError(
            f"Resend rejected email request (HTTP {exc.code}; {details}; {diagnostics})"
        ) from None
    except urllib.error.URLError as exc:
        reason = exc.reason
        reason_type = type(reason).__name__
        # Include only a coarse diagnostic category; no request or credential details.
        raise EmailDeliveryError(f"Could not reach Resend API (network error: {reason_type})") from None
    except TimeoutError:
        raise EmailDeliveryError("Resend API request timed out") from None
