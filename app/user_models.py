"""
Pydantic models for user management, authentication, and client DB config.
"""
from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr


class RegisterRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=255)
    password: str = Field(..., min_length=6, max_length=128)
    full_name: Optional[str] = Field(default=None, max_length=255)
    company_name: Optional[str] = Field(default=None, max_length=255)


class LoginRequest(BaseModel):
    email: str
    password: str


class UserResponse(BaseModel):
    id: int
    email: str
    full_name: Optional[str] = None
    company_name: Optional[str] = None
    is_active: bool = True
    is_admin: bool = False
    created_at: Optional[datetime] = None


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse


class ApiTokenCreateRequest(BaseModel):
    name: str = Field(default="Default", max_length=128)


class ApiTokenResponse(BaseModel):
    id: int
    token_prefix: str
    name: str
    is_active: bool
    last_used_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class ApiTokenCreatedResponse(BaseModel):
    """Returned only once when token is created. Contains the raw token."""
    id: int
    token: str  # raw token, shown ONCE
    token_prefix: str
    name: str


class ClientDbConfigRequest(BaseModel):
    db_host: str = Field(..., max_length=255)
    db_port: int = Field(default=5432, ge=1, le=65535)
    db_name: str = Field(..., max_length=128)
    db_user: str = Field(..., max_length=128)
    db_password: str = Field(..., max_length=255)
    ssl_mode: str = Field(default="prefer", max_length=32)


class ClientDbConfigResponse(BaseModel):
    id: int
    db_host: str
    db_port: int
    db_name: str
    db_user: str
    ssl_mode: str
    is_verified: bool
    last_sync_at: Optional[datetime] = None
    created_at: Optional[datetime] = None


class DataFilterParams(BaseModel):
    pii_type: Optional[str] = None
    search: Optional[str] = None
    date_from: Optional[str] = None
    date_to: Optional[str] = None
    page: int = 1
    per_page: int = 25


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str = Field(..., min_length=6, max_length=128)
