"""Milestone 3 functional and security regression tests."""
from app.totp import TOTP
from sqlalchemy import select
from app.database import SessionLocal
from app.models import AuditLog, RefreshToken, User
from app.security import verify_password

PASSWORD = "CloudSecure!Pass2026"


def register(client, email="student@example.com", password=PASSWORD):
    return client.post("/auth/register", json={"email": email, "password": password})


def login(client, email="student@example.com", password=PASSWORD, totp_code=None):
    payload = {"email": email, "password": password}
    if totp_code is not None:
        payload["totp_code"] = totp_code
    return client.post("/auth/login", json=payload)


def auth_header(access):
    return {"Authorization": f"Bearer {access}"}


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"




def test_login_rate_limit_blocks_excessive_requests(client):
    responses = [client.post("/auth/login", json={"email": "nobody@example.com", "password": PASSWORD}) for _ in range(11)]
    assert any(response.status_code == 429 for response in responses)


def test_registration_hashes_password_and_blocks_weak_and_duplicate(client):
    weak = register(client, "weak@example.com", "password")
    assert weak.status_code == 422
    created = register(client)
    assert created.status_code == 201
    assert created.json()["user"]["role"] == "user"
    with SessionLocal() as db:
        user = db.scalar(select(User).where(User.email == "student@example.com"))
        assert user is not None and user.password_hash != PASSWORD
        assert user.password_hash.startswith("$argon2")
        assert verify_password(PASSWORD, user.password_hash)
    duplicate = register(client)
    assert duplicate.status_code == 409
    # Supplying a role is rejected, so public registration cannot self-assign admin.
    role_override = client.post("/auth/register", json={"email": "role@example.com", "password": PASSWORD, "role": "admin"})
    assert role_override.status_code == 422


def test_login_protected_profile_refresh_rotation_and_logout(client):
    assert register(client).status_code == 201
    assert login(client, password="DefinitelyWrong!999").status_code == 401
    logged_in = login(client)
    assert logged_in.status_code == 200, logged_in.text
    first = logged_in.json()
    profile = client.get("/auth/me", headers=auth_header(first["access_token"]))
    assert profile.status_code == 200 and profile.json()["email"] == "student@example.com"
    assert client.get("/auth/me").status_code == 401

    refreshed = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert refreshed.status_code == 200, refreshed.text
    second = refreshed.json()
    assert second["refresh_token"] != first["refresh_token"]
    replay = client.post("/auth/refresh", json={"refresh_token": first["refresh_token"]})
    assert replay.status_code == 401

    logout = client.post("/auth/logout", json={"refresh_token": second["refresh_token"]},
                         headers=auth_header(second["access_token"]))
    assert logout.status_code == 200
    after_logout = client.post("/auth/refresh", json={"refresh_token": second["refresh_token"]})
    assert after_logout.status_code == 401


def test_tampered_access_token_is_rejected(client):
    register(client)
    access = login(client).json()["access_token"]
    tampered = access[:-2] + ("aa" if not access.endswith("aa") else "bb")
    response = client.get("/auth/me", headers=auth_header(tampered))
    assert response.status_code == 401


def test_rbac_denies_user_and_allows_admin_and_auditor(client):
    register(client, "user@example.com")
    register(client, "admin@example.com")
    register(client, "auditor@example.com")
    with SessionLocal() as db:
        db.scalar(select(User).where(User.email == "admin@example.com")).role = "admin"
        db.scalar(select(User).where(User.email == "auditor@example.com")).role = "auditor"
        db.commit()
    user_token = login(client, "user@example.com").json()["access_token"]
    admin_token = login(client, "admin@example.com").json()["access_token"]
    auditor_token = login(client, "auditor@example.com").json()["access_token"]
    assert client.get("/admin/users", headers=auth_header(user_token)).status_code == 403
    assert client.get("/admin/users", headers=auth_header(admin_token)).status_code == 200
    assert client.get("/audit/events", headers=auth_header(auditor_token)).status_code == 200
    assert client.get("/admin/cloud-status", headers=auth_header(user_token)).status_code == 403


def test_account_lockout_after_five_failed_password_attempts(client):
    register(client)
    for _ in range(5):
        response = login(client, password="WrongPassword!2026")
        assert response.status_code == 401
    locked = login(client)
    assert locked.status_code == 423


def test_totp_mfa_enrollment_and_enforced_login(client):
    register(client)
    access = login(client).json()["access_token"]
    headers = auth_header(access)
    setup = client.post("/auth/mfa/setup", headers=headers)
    assert setup.status_code == 200, setup.text
    secret = setup.json()["secret"]
    code = TOTP(secret).now()
    enabled = client.post("/auth/mfa/enable", headers=headers, json={"code": code})
    assert enabled.status_code == 200, enabled.text
    assert login(client).status_code == 401
    good_login = login(client, totp_code=TOTP(secret).now())
    assert good_login.status_code == 200, good_login.text


def test_audit_records_are_created_without_credentials(client):
    register(client)
    login(client, password="WrongPassword!2026")
    with SessionLocal() as db:
        events = db.scalars(select(AuditLog)).all()
        labels = {event.event for event in events}
        assert "registration_success" in labels and "login_failed" in labels
        assert all(PASSWORD not in event.details for event in events)


def test_sensitive_value_encryption_round_trip(monkeypatch):
    # This unit test deliberately uses local Fernet mode; Moto is started only by the app lifespan.
    monkeypatch.setenv("CLOUD_SIMULATION", "false")
    from app.cloud_services import decrypt_sensitive_value, encrypt_sensitive_value
    encrypted = encrypt_sensitive_value("totp-sensitive-value")
    assert encrypted != "totp-sensitive-value"
    assert decrypt_sensitive_value(encrypted) == "totp-sensitive-value"


def test_refresh_token_is_stored_as_hash_not_raw_value(client):
    register(client)
    tokens = login(client).json()
    with SessionLocal() as db:
        record = db.scalar(select(RefreshToken))
        assert record is not None
        assert record.token_hash != tokens["refresh_token"]
        assert len(record.token_hash) == 64


def test_browser_dashboard_and_static_assets(client):
    page = client.get("/")
    assert page.status_code == 200
    assert "CloudAuth" in page.text
    assert client.get("/static/styles.css").status_code == 200
    assert client.get("/static/app.js").status_code == 200


def test_dashboard_does_not_publish_demo_admin_credentials(client):
    page = client.get("/").text
    script = client.get("/static/app.js").text
    assert "admin@demo.example.com" not in page + script
    assert "AdminDemo!2026Secure" not in page + script
    assert "QUICK DEMO ACCESS" not in page


def test_private_admin_bootstrap_creates_once_without_resetting_password(client, monkeypatch):
    from app.bootstrap_admin import bootstrap_admin_from_env
    from app.models import User
    monkeypatch.setenv("BOOTSTRAP_ADMIN_EMAIL", "owner@example.com")
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", "PrivateAdmin!Pass2026")
    bootstrap_admin_from_env()
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.email == "owner@example.com"))
        assert admin is not None and admin.role == "admin"
        original_hash = admin.password_hash
    monkeypatch.setenv("BOOTSTRAP_ADMIN_PASSWORD", "DifferentAdmin!Pass2026")
    bootstrap_admin_from_env()
    with SessionLocal() as db:
        admin = db.scalar(select(User).where(User.email == "owner@example.com"))
        assert admin.password_hash == original_hash
