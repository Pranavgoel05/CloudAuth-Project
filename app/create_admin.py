"""Create the one local demo administrator interactively; never resets existing credentials."""
import getpass
import os
from dotenv import load_dotenv

load_dotenv()  # Load DATABASE_URL and other local settings before app modules are imported.

from sqlalchemy import select
from app.database import Base, SessionLocal, engine
from app.models import User
from app.schemas import RegisterRequest
from app.security import hash_password, validate_password


def main() -> None:
    Base.metadata.create_all(bind=engine)
    with SessionLocal() as db:
        existing_admin = db.scalar(select(User).where(User.role == "admin").limit(1))
        if existing_admin is not None:
            print(f"Administrator already exists ({existing_admin.email}); no credentials were changed.")
            return

        env_email = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip()
        env_password = os.getenv("BOOTSTRAP_ADMIN_PASSWORD", "")
        if bool(env_email) != bool(env_password):
            raise SystemExit("Set both BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD, or leave both blank to enter them securely.")
        email = env_email or input("Private administrator email: ").strip().lower()
        password = env_password or getpass.getpass("Create a strong administrator password (not displayed): ")
        confirm = env_password or getpass.getpass("Confirm administrator password: ")
        if password != confirm:
            raise SystemExit("Passwords did not match. No administrator was created.")
        try:
            validated = RegisterRequest(email=email, password=password)
            email = str(validated.email).lower().strip()
            validate_password(password)
        except Exception as exc:
            raise SystemExit(f"Invalid administrator details: {exc}") from exc
        existing_user = db.scalar(select(User).where(User.email == email))
        if existing_user is not None:
            raise SystemExit("That email already belongs to an account. No role was changed; use a different email.")
        db.add(User(email=email, password_hash=hash_password(password), role="admin"))
        db.commit()
        print(f"Created administrator: {email}. Store your password privately and enable MFA after signing in.")


if __name__ == "__main__":
    main()
