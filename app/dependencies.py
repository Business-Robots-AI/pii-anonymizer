"""
FastAPI dependency injection for authentication.
"""
import os
import secrets
import logging
from typing import Optional
from datetime import datetime

from fastapi import Request, HTTPException, status
from psycopg2.extras import RealDictCursor

from .auth_jwt import decode_access_token, hash_api_token
from .database import get_connection

logger = logging.getLogger(__name__)

# Legacy auth (backward compat). The shared key must come from the environment —
# without PII_API_KEY the legacy path stays off, so an unconfigured deployment
# cannot hand out admin access via a key that is readable in the source.
LEGACY_API_KEY = os.getenv("PII_API_KEY", "")
LEGACY_AUTH_ENABLED = (
    os.getenv("PII_LEGACY_AUTH_ENABLED", "true").lower() == "true" and bool(LEGACY_API_KEY)
)


def _get_user_by_id(user_id: int) -> Optional[dict]:
    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM users WHERE id = %s AND is_active = TRUE", (user_id,))
                return cur.fetchone()
    except Exception:
        return None


def _get_user_by_token_hash(token_hash: str) -> Optional[dict]:
    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT u.* FROM users u
                    JOIN api_tokens t ON t.user_id = u.id
                    WHERE t.token_hash = %s AND t.is_active = TRUE AND u.is_active = TRUE
                """, (token_hash,))
                user = cur.fetchone()
                if user:
                    # Update last_used_at
                    cur.execute(
                        "UPDATE api_tokens SET last_used_at = CURRENT_TIMESTAMP WHERE token_hash = %s",
                        (token_hash,)
                    )
                return user
    except Exception as e:
        logger.warning(f"Token lookup failed: {e}")
        return None


async def get_current_user(request: Request) -> dict:
    """Extract user from JWT access token in Authorization header."""
    auth_header = request.headers.get("Authorization", "")

    if auth_header.startswith("Bearer "):
        token = auth_header[7:]

        # Try JWT first
        payload = decode_access_token(token)
        if payload:
            user_id = int(payload["sub"])
            user = _get_user_by_id(user_id)
            if user:
                return dict(user)

        # Try API token
        token_hash = hash_api_token(token)
        user = _get_user_by_token_hash(token_hash)
        if user:
            return dict(user)

    # Legacy: check X-API-Key header
    api_key = request.headers.get("X-API-Key", "")
    if api_key:
        token_hash = hash_api_token(api_key)
        user = _get_user_by_token_hash(token_hash)
        if user:
            return dict(user)

    # Legacy fallback
    if LEGACY_AUTH_ENABLED:
        if api_key and secrets.compare_digest(api_key, LEGACY_API_KEY):
            return {"id": None, "email": "legacy", "is_admin": True, "is_active": True}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing authentication",
    )


async def get_current_user_optional(request: Request) -> Optional[dict]:
    """Same as get_current_user but returns None instead of 401."""
    try:
        return await get_current_user(request)
    except HTTPException:
        return None


async def require_admin(request: Request) -> dict:
    """Require authenticated user with is_admin=True."""
    user = await get_current_user(request)
    if not user.get("is_admin"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return user
