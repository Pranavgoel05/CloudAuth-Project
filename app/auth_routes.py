"""Registration, login, refresh/logout, MFA, profile, admin, and audit endpoints."""
from datetime import datetime, timedelta, timezone
import base64
import io
import logging
import os
import secrets
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
import jwt
from app import totp as pyotp
from app.audit import record_event
from app.cloud_services import decrypt_sensitive_value, encrypt_sensitive_value, get_cloud_status
from app.database import get_db
from app.email_service import send_password_reset_email
from app.models import AuditLog, PasswordResetToken, RefreshToken, User, utcnow_naive
from app.rbac import get_current_user, require_roles
from app.rate_limit import limiter
from app.schemas import (ForgotPasswordRequest, LoginRequest, MFACodeRequest,
                         RefreshRequest, RegisterRequest, ResetPasswordRequest)
from app.security import (ACCESS_TOKEN_MINUTES, create_jwt, decode_jwt, hash_password,
                          hash_token, validate_password, verify_password)

router = APIRouter()
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 5
PASSWORD_RESET_MINUTES = 20
logger = logging.getLogger(__name__)


def _request_ip(request: Request) -> str:
    # Avoid trusting X-Forwarded-For unless a trusted reverse proxy is explicitly configured.
    return request.client.host if request.client else "unknown"


def _token_pair(db: Session, user: User) -> dict:
    access = create_jwt(str(user.id), "access", role=user.role)
    refresh = create_jwt(str(user.id), "refresh")
    now = utcnow_naive()
    db.add(RefreshToken(user_id=user.id, token_hash=hash_token(refresh),
                        expires_at=now + timedelta(days=7)))
    db.commit()
    return {"access_token": access, "refresh_token": refresh, "token_type": "bearer",
            "expires_in": ACCESS_TOKEN_MINUTES * 60,
            "user": {"id": user.id, "email": user.email, "role": user.role}}


@router.post("/auth/register", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/minute")
def register(payload: RegisterRequest, request: Request, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    try:
        validate_password(payload.password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    if db.scalar(select(User).where(User.email == email)):
        record_event(db, event="registration_rejected_duplicate", email=email, ip=_request_ip(request), success=False)
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    try:
        user = User(email=email, password_hash=hash_password(payload.password), role="user")
        db.add(user)
        db.commit()
        db.refresh(user)
    except IntegrityError:
        db.rollback()
        record_event(db, event="registration_rejected_duplicate", email=email, ip=_request_ip(request), success=False)
        raise HTTPException(status_code=409, detail="An account with this email already exists")
    record_event(db, event="registration_success", email=email, ip=_request_ip(request), success=True)
    return {"message": "Account created", "user": {"id": user.id, "email": user.email, "role": user.role}}


@router.post("/auth/password/forgot", status_code=status.HTTP_202_ACCEPTED)
@limiter.limit("5/minute")
def forgot_password(payload: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Request a password reset without disclosing whether an account exists."""
    generic = {"message": "If an account matches that email, password-reset instructions will be sent."}
    email = str(payload.email).lower().strip()

    # In production, fail uniformly until email delivery is configured; never create
    # a reset token that cannot reach the account owner.
    is_production = os.getenv("APP_ENV", "development").lower() == "production"
    if is_production and not os.getenv("RESEND_API_KEY", "").strip():
        logger.error("Password reset unavailable: RESEND_API_KEY is not configured")
        raise HTTPException(status_code=503, detail="Password-reset email service is temporarily unavailable")

    user = db.scalar(select(User).where(User.email == email, User.is_active.is_(True)))
    now = utcnow_naive()
    reset_url = None
    if user is not None:
        # Only the hash is persisted; a new request invalidates previous links.
        prior_tokens = db.scalars(select(PasswordResetToken).where(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.used_at.is_(None),
        )).all()
        for prior in prior_tokens:
            prior.used_at = now
        raw_token = secrets.token_urlsafe(32)
        db.add(PasswordResetToken(
            user_id=user.id,
            token_hash=hash_token(raw_token),
            expires_at=now + timedelta(minutes=PASSWORD_RESET_MINUTES),
        ))
        db.commit()
        base_url = os.getenv("PUBLIC_BASE_URL", "http://127.0.0.1:8000").rstrip("/")
        # URL fragment is read by the browser and is not sent in the HTTP request line.
        reset_url = f"{base_url}/#reset_token={raw_token}"
        if os.getenv("RESEND_API_KEY", "").strip():
            try:
                send_password_reset_email(email, reset_url)
                record_event(db, event="password_reset_email_sent", email=email,
                             ip=_request_ip(request), success=True)
            except Exception:
                logger.warning("Password reset email delivery failed; check Resend configuration.")
                record_event(db, event="password_reset_email_failed", email=email,
                             ip=_request_ip(request), success=False)
        elif not is_production:
            # Local-only convenience for tests/development. Never return reset tokens
            # from the public production API response.
            generic["reset_url"] = reset_url

    # Use the same status and message for known and unknown addresses.
    record_event(db, event="password_reset_requested", email=email,
                 ip=_request_ip(request), success=True)
    return generic


@router.post("/auth/password/reset")
@limiter.limit("10/minute")
def reset_password(payload: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Consume an unexpired reset token, change the password, and revoke refresh sessions."""
    try:
        validate_password(payload.new_password)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))

    now = utcnow_naive()
    token_hash = hash_token(payload.token)
    # Atomically consume the token before changing the password so parallel submissions
    # cannot both reuse the same reset link. The transaction commits with the password.
    claimed = db.execute(
        update(PasswordResetToken)
        .where(
            PasswordResetToken.token_hash == token_hash,
            PasswordResetToken.used_at.is_(None),
            PasswordResetToken.expires_at > now,
        )
        .values(used_at=now)
        .returning(PasswordResetToken.id, PasswordResetToken.user_id)
    ).one_or_none()
    if claimed is None:
        record_event(db, event="password_reset_rejected", ip=_request_ip(request), success=False)
        raise HTTPException(status_code=400, detail="Invalid or expired password-reset link")

    reset_record_id, reset_user_id = claimed
    user = db.get(User, reset_user_id)
    if user is None or not user.is_active:
        db.commit()  # Consume the token even if its account is no longer active.
        record_event(db, event="password_reset_rejected", ip=_request_ip(request), success=False)
        raise HTTPException(status_code=400, detail="Invalid or expired password-reset link")

    user.password_hash = hash_password(payload.new_password)
    user.failed_attempts = 0
    user.locked_until = None
    # Consume all other outstanding reset links and revoke refresh sessions.
    other_resets = db.scalars(select(PasswordResetToken).where(
        PasswordResetToken.user_id == user.id,
        PasswordResetToken.used_at.is_(None),
        PasswordResetToken.id != reset_record_id,
    )).all()
    for other in other_resets:
        other.used_at = now
    active_refresh_tokens = db.scalars(select(RefreshToken).where(
        RefreshToken.user_id == user.id,
        RefreshToken.revoked_at.is_(None),
    )).all()
    for refresh_token in active_refresh_tokens:
        refresh_token.revoked_at = now
    db.commit()
    record_event(db, event="password_reset_success", email=user.email,
                 ip=_request_ip(request), success=True)
    return {"message": "Password reset successful. Sign in with your new password."}


@router.post("/auth/login")
@limiter.limit("10/minute")
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)):
    email = str(payload.email).lower().strip()
    user = db.scalar(select(User).where(User.email == email))
    now = utcnow_naive()
    if user and user.locked_until and user.locked_until > now:
        record_event(
            db, event="login_blocked_locked_account", email=email, ip=_request_ip(request),
            success=False, details="Login attempt denied while the account is temporarily locked.",
        )
        raise HTTPException(status_code=423, detail="Account temporarily locked after repeated failed attempts")
    if user is None or not verify_password(payload.password, user.password_hash):
        lockout_started = False
        if user is not None:
            user.failed_attempts += 1
            if user.failed_attempts >= LOCKOUT_THRESHOLD:
                user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                lockout_started = True
            db.commit()
        record_event(db, event="login_failed", email=email, ip=_request_ip(request), success=False,
                     details="Access denied: invalid credentials.")
        if lockout_started:
            record_event(
                db, event="account_temporarily_blocked", email=email, ip=_request_ip(request),
                success=False,
                details=f"Account temporarily blocked for {LOCKOUT_MINUTES} minutes after "
                        f"{LOCKOUT_THRESHOLD} failed login attempts.",
            )
        raise HTTPException(status_code=401, detail="Invalid email or password")
    if not user.is_active:
        record_event(db, event="login_inactive_account", email=email, ip=_request_ip(request), success=False)
        raise HTTPException(status_code=403, detail="Account is disabled")
    if user.mfa_enabled:
        if not payload.totp_code or not user.mfa_secret:
            record_event(db, event="login_mfa_required", email=email, ip=_request_ip(request), success=False)
            raise HTTPException(status_code=401, detail="MFA code required")
        try:
            secret = decrypt_sensitive_value(user.mfa_secret)
            valid = pyotp.TOTP(secret).verify(payload.totp_code, valid_window=1)
        except Exception:
            valid = False
        if not valid:
            user.failed_attempts += 1
            lockout_started = False
            if user.failed_attempts >= LOCKOUT_THRESHOLD:
                user.locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)
                lockout_started = True
            db.commit()
            record_event(db, event="login_mfa_failed", email=email, ip=_request_ip(request),
                         success=False, details="Access denied: invalid MFA verification.")
            if lockout_started:
                record_event(
                    db, event="account_temporarily_blocked", email=email, ip=_request_ip(request),
                    success=False,
                    details=f"Account temporarily blocked for {LOCKOUT_MINUTES} minutes after "
                            f"{LOCKOUT_THRESHOLD} failed authentication attempts.",
                )
            raise HTTPException(status_code=401, detail="Invalid email, password, or MFA code")
    user.failed_attempts = 0
    user.locked_until = None
    db.commit()
    tokens = _token_pair(db, user)
    record_event(db, event="login_success", email=email, ip=_request_ip(request), success=True)
    return tokens


@router.get("/auth/me")
def get_profile(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "role": user.role,
            "mfa_enabled": user.mfa_enabled, "created_at": user.created_at}


@router.post("/auth/refresh")
@limiter.limit("20/minute")
def refresh_tokens(payload: RefreshRequest, request: Request, db: Session = Depends(get_db)):
    try:
        claims = decode_jwt(payload.refresh_token, expected_type="refresh")
        user_id = int(claims["sub"])
    except (jwt.PyJWTError, ValueError, KeyError, TypeError):
        record_event(db, event="refresh_rejected", ip=_request_ip(request), success=False)
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")
    stored = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(payload.refresh_token)))
    now = utcnow_naive()
    if stored is None or stored.revoked_at is not None or stored.expires_at <= now or stored.user_id != user_id:
        record_event(db, event="refresh_rejected", ip=_request_ip(request), success=False)
        raise HTTPException(status_code=401, detail="Invalid, expired, or revoked refresh token")
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=401, detail="Account unavailable")
    stored.revoked_at = now
    db.commit()
    tokens = _token_pair(db, user)
    record_event(db, event="refresh_success", email=user.email, ip=_request_ip(request), success=True)
    return tokens


@router.post("/auth/logout")
def logout(payload: RefreshRequest, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    stored = db.scalar(select(RefreshToken).where(RefreshToken.token_hash == hash_token(payload.refresh_token),
                                                RefreshToken.user_id == user.id))
    if stored and stored.revoked_at is None:
        stored.revoked_at = utcnow_naive()
        db.commit()
    record_event(db, event="logout", email=user.email, ip=_request_ip(request), success=True)
    return {"message": "Logged out; the submitted refresh token has been revoked"}


@router.post("/auth/mfa/setup")
@limiter.limit("10/minute")
def mfa_setup(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if user.mfa_enabled:
        raise HTTPException(status_code=409, detail="MFA is already enabled")
    secret = pyotp.random_base32()
    user.mfa_secret = encrypt_sensitive_value(secret)
    db.commit()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name="Cloud Auth Service")
    record_event(db, event="mfa_setup_started", email=user.email, ip=_request_ip(request), success=True)
    # Return the secret/URI only to the already authenticated account for enrollment in an authenticator app.
    response = {"secret": secret, "provisioning_uri": uri,
                "message": "Add this account to an authenticator app, then verify the current code at /auth/mfa/enable"}
    # QR support is an enhancement for the browser demo; manual secret entry remains available.
    try:
        import qrcode
        image = qrcode.make(uri)
        buffer = io.BytesIO()
        image.save(buffer, format="PNG")
        response["qr_code_data_uri"] = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode("ascii")
    except Exception:
        pass
    return response


@router.post("/auth/mfa/enable")
@limiter.limit("10/minute")
def mfa_enable(payload: MFACodeRequest, request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if not user.mfa_secret:
        raise HTTPException(status_code=400, detail="Run MFA setup first")
    try:
        secret = decrypt_sensitive_value(user.mfa_secret)
        valid = pyotp.TOTP(secret).verify(payload.code, valid_window=1)
    except Exception:
        valid = False
    if not valid:
        record_event(db, event="mfa_enable_failed", email=user.email, ip=_request_ip(request), success=False)
        raise HTTPException(status_code=400, detail="Invalid MFA code")
    user.mfa_enabled = True
    db.commit()
    record_event(db, event="mfa_enabled", email=user.email, ip=_request_ip(request), success=True)
    return {"message": "MFA enabled", "mfa_enabled": True}


@router.get("/admin/users")
def list_users(user: User = Depends(require_roles("admin")), db: Session = Depends(get_db)):
    users = db.scalars(select(User).order_by(User.id)).all()
    return [{"id": row.id, "email": row.email, "role": row.role, "is_active": row.is_active,
             "mfa_enabled": row.mfa_enabled, "created_at": row.created_at} for row in users]


@router.get("/audit/events")
def list_audit_events(limit: int = Query(default=50, ge=1, le=100),
                      user: User = Depends(require_roles("admin", "auditor")), db: Session = Depends(get_db)):
    events = db.scalars(select(AuditLog).order_by(AuditLog.at.desc(), AuditLog.id.desc()).limit(limit)).all()
    return [{"id": row.id, "event": row.event, "email": row.email, "ip": row.ip,
             "success": row.success, "details": row.details, "at": row.at} for row in events]


@router.get("/admin/cloud-status")
def cloud_status(user: User = Depends(require_roles("admin"))):
    return get_cloud_status()
