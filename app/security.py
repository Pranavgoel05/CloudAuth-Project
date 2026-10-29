"""Password hashing, policy enforcement, token creation, and token verification."""
import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
import jwt
from app.cloud_services import get_jwt_signing_key

_password_hasher = PasswordHasher()
COMMON_PASSWORDS = {
    "password", "password123", "123456", "123456789", "12345678", "qwerty",
    "admin", "letmein", "welcome", "iloveyou", "abc123", "111111", "changeme"
}
ACCESS_TOKEN_MINUTES = 15
REFRESH_TOKEN_DAYS = 7


def validate_password(password: str) -> None:
    if len(password) < 12 or len(password) > 128:
        raise ValueError("Password must be between 12 and 128 characters")
    if password.lower() in COMMON_PASSWORDS:
        raise ValueError("Choose a less common password")
    if not any(ch.islower() for ch in password) or not any(ch.isupper() for ch in password):
        raise ValueError("Password must include uppercase and lowercase letters")
    if not any(ch.isdigit() for ch in password) or not any(not ch.isalnum() for ch in password):
        raise ValueError("Password must include a number and a special character")


def hash_password(password: str) -> str:
    validate_password(password)
    return _password_hasher.hash(password)


def verify_password(password: str, encoded_hash: str) -> bool:
    try:
        return _password_hasher.verify(encoded_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, TypeError):
        return False


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def create_jwt(subject: str, token_type: str, *, role: str | None = None, lifetime: timedelta | None = None) -> str:
    now = datetime.now(timezone.utc)
    expires = now + (lifetime or (timedelta(minutes=ACCESS_TOKEN_MINUTES) if token_type == "access" else timedelta(days=REFRESH_TOKEN_DAYS)))
    payload = {"sub": str(subject), "type": token_type, "iat": now, "nbf": now, "exp": expires, "jti": secrets.token_urlsafe(12)}
    if role:
        payload["role"] = role
    return jwt.encode(payload, get_jwt_signing_key(), algorithm="HS256")


def decode_jwt(token: str, expected_type: str | None = None) -> dict:
    payload = jwt.decode(token, get_jwt_signing_key(), algorithms=["HS256"], options={"require": ["sub", "iat", "exp", "type"]})
    if expected_type and payload.get("type") != expected_type:
        raise jwt.InvalidTokenError("Wrong token type")
    return payload
