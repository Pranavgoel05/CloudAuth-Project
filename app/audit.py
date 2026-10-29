"""Centralized audit event recording; secrets and credentials are intentionally excluded."""
from sqlalchemy.orm import Session
from app.models import AuditLog
from app.cloud_services import emit_cloud_audit


def record_event(db: Session, *, event: str, email: str = "unknown", ip: str = "unknown",
                 success: bool, details: str = "") -> None:
    # Details must be an explanatory label, never a password, token, TOTP code, or secret.
    safe_email = str(email or "unknown")[:255]
    safe_ip = str(ip or "unknown")[:45]
    safe_details = str(details or "")[:300]
    row = AuditLog(event=event[:80], email=safe_email, ip=safe_ip, success=success, details=safe_details)
    db.add(row)
    db.commit()
    emit_cloud_audit({"event": event[:80], "email": safe_email, "ip": safe_ip,
                      "success": bool(success), "details": safe_details})
