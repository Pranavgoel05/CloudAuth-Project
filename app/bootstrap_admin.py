"""Create the single deployment administrator from private environment variables."""
import os
from sqlalchemy import select
from app.database import Base, SessionLocal, engine
from app.models import User
from app.schemas import RegisterRequest
from app.security import hash_password, validate_password


def bootstrap_admin_from_env() -> None:
    """Create the admin on first deployment; never overwrite an existing password/role."""
    email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
    password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
    if not email and not password:
        return
    if not email or not password:
        raise RuntimeError("Set both BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD, or leave both blank.")
    try:
        validated = RegisterRequest(email=email, password=password)
    except Exception as exc:
        raise RuntimeError("BOOTSTRAP_ADMIN_EMAIL or BOOTSTRAP_ADMIN_PASSWORD is invalid.") from exc
    email = str(validated.email).lower().strip()
    try:
        validate_password(password)
    except ValueError as exc:
        raise RuntimeError(f"Bootstrap administrator password does not meet the password policy: {exc}") from exc

    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        existing_admin = db.scalar(select(User).where(User.role == "admin").limit(1))
        existing_email = db.scalar(select(User).where(User.email == email))
        if existing_admin is not None:
            if existing_admin.email == email:
                # Existing credentials and MFA state are intentionally not reset on restarts.
                return
            raise RuntimeError("An administrator already exists with a different email. Refusing to create another admin.")
        if existing_email is not None:
            raise RuntimeError("Bootstrap email already belongs to a non-admin account. Refusing to promote it automatically.")
        db.add(User(email=email, password_hash=hash_password(password), role="admin"))
        db.commit()
        print("Created the initial administrator from private deployment settings.")
