"""Milestone 3 functional and security regression tests."""
from app.totp import TOTP
from sqlalchemy import select
from app.database import SessionLocal
from urllib.parse import parse_qs, urlsplit
from app.models import AuditLog, PasswordResetToken, RefreshToken, User
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
    with SessionLocal() as db:
        labels = [row.event for row in db.scalars(select(AuditLog).order_by(AuditLog.id)).all()]
        assert labels.count("login_failed") == 5
        assert "account_temporarily_blocked" in labels
    locked = login(client)
    assert locked.status_code == 423
    with SessionLocal() as db:
        labels = [row.event for row in db.scalars(select(AuditLog).order_by(AuditLog.id)).all()]
        assert "login_blocked_locked_account" in labels


def test_admin_audit_api_records_failed_and_temporarily_blocked_logins(client):
    register(client, "student@example.com")
    register(client, "admin@example.com")
    with SessionLocal() as db:
        db.scalar(select(User).where(User.email == "admin@example.com")).role = "admin"
        db.commit()

    for _ in range(5):
        login(client, "student@example.com", "WrongPassword!2026")
    login(client, "student@example.com")  # attempt while the account is locked

    admin_token = login(client, "admin@example.com").json()["access_token"]
    response = client.get("/audit/events?limit=50", headers=auth_header(admin_token))
    assert response.status_code == 200
    labels = {row["event"] for row in response.json()}
    assert {"login_failed", "account_temporarily_blocked", "login_blocked_locked_account"}.issubset(labels)

    # The dashboard translates these stable backend event codes into the requested labels.
    script = client.get("/static/app.js").text
    assert "login_failed: 'Access Denied'" in script
    assert "login_blocked_locked_account: 'Temporary Blocked'" in script


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


def test_password_reset_is_hashed_single_use_and_revokes_refresh_sessions(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    assert register(client).status_code == 201
    initial_login = login(client)
    assert initial_login.status_code == 200

    requested = client.post("/auth/password/forgot", json={"email": "student@example.com"})
    assert requested.status_code == 202, requested.text
    payload = requested.json()
    assert "If an account matches" in payload["message"]
    reset_token = parse_qs(urlsplit(payload["reset_url"]).fragment)["reset_token"][0]

    with SessionLocal() as db:
        row = db.scalar(select(PasswordResetToken))
        assert row is not None
        assert row.token_hash != reset_token
        assert len(row.token_hash) == 64

    new_password = "NewCloudAuth!Pass2026"
    reset = client.post("/auth/password/reset", json={"token": reset_token, "new_password": new_password})
    assert reset.status_code == 200, reset.text
    assert login(client, password=PASSWORD).status_code == 401
    assert login(client, password=new_password).status_code == 200
    # A one-time reset token cannot be replayed.
    assert client.post("/auth/password/reset", json={"token": reset_token, "new_password": "AnotherNew!Pass2026"}).status_code == 400
    # The session created before the reset cannot use its old refresh token again.
    assert client.post("/auth/refresh", json={"refresh_token": initial_login.json()["refresh_token"]}).status_code == 401


def test_forgot_password_does_not_disclose_unknown_email(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "development")
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    register(client)
    known = client.post("/auth/password/forgot", json={"email": "student@example.com"})
    unknown = client.post("/auth/password/forgot", json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 202
    assert known.json()["message"] == unknown.json()["message"]
    assert "reset_url" not in unknown.json()


def test_production_password_reset_requires_email_provider_for_every_address(client, monkeypatch):
    monkeypatch.setenv("APP_ENV", "production")
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    known = client.post("/auth/password/forgot", json={"email": "admin@example.com"})
    unknown = client.post("/auth/password/forgot", json={"email": "nobody@example.com"})
    assert known.status_code == unknown.status_code == 503
    assert known.json()["detail"] == unknown.json()["detail"]


def test_resend_email_adapter_uses_https_and_does_not_require_smtp(monkeypatch):
    import json
    import urllib.request
    from app.email_service import send_password_reset_email

    monkeypatch.setenv("RESEND_API_KEY", "re_test_key_only")
    monkeypatch.setenv("RESEND_FROM_EMAIL", "CloudAuth <onboarding@resend.dev>")
    captured = {}

    class FakeResponse:
        status = 200
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            return False

    def fake_urlopen(request, timeout):
        captured["url"] = request.full_url
        captured["method"] = request.get_method()
        captured["payload"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    send_password_reset_email("student@example.com", "https://example.test/#reset_token=one-time-token")
    assert captured["url"] == "https://api.resend.com/emails"
    assert captured["method"] == "POST"
    assert captured["payload"]["to"] == ["student@example.com"]
    assert "one-time-token" in captured["payload"]["text"]
    assert captured["timeout"] == 12


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
