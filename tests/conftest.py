import os
# Tests use an isolated database and local key mode; never touch the demo DB or live AWS.
os.environ["DATABASE_URL"] = "sqlite:///./cloud_auth_test.db"
os.environ["CLOUD_SIMULATION"] = "false"

import pytest
from sqlalchemy import delete
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app.models import AuditLog, RefreshToken, User
from app.rate_limit import limiter

@pytest.fixture(autouse=True)
def clean_database():
    with SessionLocal() as db:
        db.execute(delete(RefreshToken))
        db.execute(delete(AuditLog))
        db.execute(delete(User))
        db.commit()
    try:
        limiter.reset()
    except Exception:
        pass
    yield

@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client
