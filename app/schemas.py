"""Validated request schemas. Extra request fields are rejected by default."""
from typing import Annotated
from pydantic import BaseModel, ConfigDict, EmailStr, Field

PasswordInput = Annotated[str, Field(min_length=1, max_length=128)]

class RegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: PasswordInput

class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    email: EmailStr
    password: PasswordInput
    totp_code: str | None = Field(default=None, pattern=r"^\d{6}$")

class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    refresh_token: str = Field(min_length=20, max_length=4096)

class MFACodeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: str = Field(pattern=r"^\d{6}$")
