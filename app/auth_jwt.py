"""
JWT and API token authentication utilities.
"""
import os
import logging
import secrets
import hashlib
from datetime import datetime, timedelta
from typing import Optional, Tuple

import bcrypt
from jose import jwt, JWTError

JWT_SECRET = os.getenv("PII_JWT_SECRET", "")
JWT_ALGORITHM = "HS256"

if not JWT_SECRET:
    # Falling back to a source-readable constant would let anyone forge a token,
    # so generate a throwaway one instead: tokens die with the process, which
    # makes a missing PII_JWT_SECRET obvious rather than silently insecure.
    JWT_SECRET = secrets.token_hex(32)
    logging.getLogger(__name__).error(
        "PII_JWT_SECRET is not set — using an ephemeral secret. "
        "All issued tokens become invalid on restart. Set it in the environment."
    )
JWT_ACCESS_EXPIRE_MINUTES = int(os.getenv("PII_JWT_ACCESS_EXPIRE_MINUTES", "60"))
JWT_REFRESH_EXPIRE_DAYS = int(os.getenv("PII_JWT_REFRESH_EXPIRE_DAYS", "7"))


def hash_password(password: str) -> str:
    pwd_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(password: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))
    except Exception:
        return False


def create_access_token(user_id: int, email: str) -> str:
    expire = datetime.utcnow() + timedelta(minutes=JWT_ACCESS_EXPIRE_MINUTES)
    payload = {
        "sub": str(user_id),
        "email": email,
        "exp": expire,
        "type": "access",
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def decode_access_token(token: str) -> Optional[dict]:
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            return None
        return payload
    except JWTError:
        return None


def generate_api_token() -> Tuple[str, str]:
    """Generate a new API token. Returns (raw_token, sha256_hash)."""
    raw = "pii_sk_live_" + secrets.token_hex(24)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed


def hash_api_token(raw_token: str) -> str:
    return hashlib.sha256(raw_token.encode()).hexdigest()


def generate_refresh_token() -> Tuple[str, str]:
    """Generate refresh token. Returns (raw_token, sha256_hash)."""
    raw = secrets.token_hex(32)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed
