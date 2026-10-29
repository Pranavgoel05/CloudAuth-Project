"""FastAPI application and browser dashboard entry point."""
from contextlib import asynccontextmanager
from pathlib import Path
import os

from dotenv import load_dotenv
load_dotenv()

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.auth_routes import router
from app.bootstrap_admin import bootstrap_admin_from_env
from app.cloud_services import _simulation_enabled, initialize_simulated_cloud
from app.database import Base, engine
from app.rate_limit import limiter
import app.models  # noqa: F401 - ensure SQLAlchemy metadata is registered

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
Base.metadata.create_all(bind=engine)


def validate_deployment_configuration() -> None:
    """Fail closed when public deployment settings are incomplete."""
    if os.getenv("APP_ENV", "development").lower() != "production":
        return
    if len(os.getenv("AUTH_JWT_SECRET", "")) < 32:
        raise RuntimeError("Production requires AUTH_JWT_SECRET with at least 32 characters.")
    if not os.getenv("AUTH_ENCRYPTION_KEY", "").strip():
        raise RuntimeError("Production requires a stable AUTH_ENCRYPTION_KEY in private environment settings.")
    database_url = os.getenv("DATABASE_URL", "sqlite:///./cloud_auth.db")
    if database_url.startswith("sqlite"):
        raise RuntimeError("Production requires a persistent PostgreSQL DATABASE_URL; SQLite is local-demo only.")
    if not os.getenv("BOOTSTRAP_ADMIN_EMAIL", "").strip() or not os.getenv("BOOTSTRAP_ADMIN_PASSWORD", ""):
        raise RuntimeError("Production requires private BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD settings.")


@asynccontextmanager
async def lifespan(app: FastAPI):
    validate_deployment_configuration()
    moto_context = None
    if _simulation_enabled():
        try:
            from moto import mock_aws
        except ImportError as exc:
            raise RuntimeError(
                "CLOUD_SIMULATION=true but Moto is not installed. Run `pip install -r requirements.txt`."
            ) from exc
        moto_context = mock_aws()
        moto_context.start()
        try:
            initialize_simulated_cloud()
        except Exception:
            moto_context.stop()
            raise
    try:
        # Cloud-hosted deployments bootstrap an admin from private env settings.
        # Local startup uses the interactive `python -m app.create_admin` command.
        bootstrap_admin_from_env()
        yield
    finally:
        if moto_context is not None:
            moto_context.stop()


app = FastAPI(
    title="Cloud User Authentication System",
    version="1.1.0",
    description=("Final-year demo: secure registration, Argon2 password hashing, JWT sessions, "
                 "RBAC, TOTP MFA, rate limiting, lockout, audit logging and optional simulated AWS."),
    lifespan=lifespan,
)
app.include_router(router)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def home():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health", tags=["system"])
@limiter.limit("60/minute")
def health(request: Request):
    return {"status": "ok", "service": "cloud-auth", "version": app.version,
            "cloud_simulation": _simulation_enabled()}
