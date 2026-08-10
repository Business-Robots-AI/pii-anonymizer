"""
Authentication router: register, login, refresh, logout.
"""
import logging
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Response, Request, status
from psycopg2.extras import RealDictCursor

from ..auth_jwt import (
    hash_password, verify_password,
    create_access_token, generate_api_token,
    generate_refresh_token, hash_api_token,
    JWT_REFRESH_EXPIRE_DAYS,
)
from ..user_models import RegisterRequest, LoginRequest, TokenResponse, UserResponse
from ..database import get_connection, DB_CONFIG
from ..client_db import client_db_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=TokenResponse, status_code=201)
async def register(req: RegisterRequest):
    """Register a new user account."""
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check email uniqueness
            cur.execute("SELECT id FROM users WHERE email = %s", (req.email.lower(),))
            if cur.fetchone():
                raise HTTPException(status_code=409, detail="Email already registered")

            # Create user
            pw_hash = hash_password(req.password)
            cur.execute("""
                INSERT INTO users (email, password_hash, full_name, company_name)
                VALUES (%s, %s, %s, %s) RETURNING *
            """, (req.email.lower(), pw_hash, req.full_name, req.company_name))
            user = dict(cur.fetchone())

            # Create default API token
            raw_token, token_hash = generate_api_token()
            cur.execute("""
                INSERT INTO api_tokens (user_id, token_hash, token_prefix, name)
                VALUES (%s, %s, %s, 'Default')
            """, (user["id"], token_hash, raw_token[:16]))

    # Auto-connect new user to platform DB
    try:
        config_id = client_db_manager.save_config(
            user_id=user["id"],
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"],
            db_name=DB_CONFIG["database"],
            db_user=DB_CONFIG["user"],
            db_password=DB_CONFIG["password"],
            ssl_mode="prefer",
        )
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE client_db_configs SET is_verified = TRUE WHERE id = %s",
                    (config_id,),
                )
        logger.info(f"Auto-configured platform DB for user {user['id']}")
    except Exception as e:
        logger.warning(f"Failed to auto-configure platform DB for user {user['id']}: {e}")

    access_token = create_access_token(user["id"], user["email"])
    return TokenResponse(
        access_token=access_token,
        user=UserResponse(**user),
    )


@router.post("/login", response_model=TokenResponse)
async def login(req: LoginRequest, response: Response):
    """Login with email and password."""
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM users WHERE email = %s AND is_active = TRUE", (req.email.lower(),))
            user = cur.fetchone()

    if not user or not verify_password(req.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")

    user = dict(user)
    access_token = create_access_token(user["id"], user["email"])

    # Create refresh token
    raw_refresh, refresh_hash = generate_refresh_token()
    expires_at = datetime.utcnow() + timedelta(days=JWT_REFRESH_EXPIRE_DAYS)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
                VALUES (%s, %s, %s)
            """, (user["id"], refresh_hash, expires_at))

    response.set_cookie(
        key="refresh_token",
        value=raw_refresh,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=JWT_REFRESH_EXPIRE_DAYS * 86400,
    )

    return TokenResponse(
        access_token=access_token,
        user=UserResponse(**user),
    )


@router.post("/refresh")
async def refresh_token(request: Request):
    """Refresh access token using refresh cookie."""
    raw_refresh = request.cookies.get("refresh_token")
    if not raw_refresh:
        raise HTTPException(status_code=401, detail="No refresh token")

    import hashlib
    refresh_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()

    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT rt.*, u.email, u.is_active FROM refresh_tokens rt
                JOIN users u ON u.id = rt.user_id
                WHERE rt.token_hash = %s AND rt.expires_at > CURRENT_TIMESTAMP AND u.is_active = TRUE
            """, (refresh_hash,))
            row = cur.fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    access_token = create_access_token(row["user_id"], row["email"])
    return {"access_token": access_token, "token_type": "bearer"}


@router.post("/logout")
async def logout(request: Request, response: Response):
    """Logout — delete refresh token."""
    raw_refresh = request.cookies.get("refresh_token")
    if raw_refresh:
        import hashlib
        refresh_hash = hashlib.sha256(raw_refresh.encode()).hexdigest()
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute("DELETE FROM refresh_tokens WHERE token_hash = %s", (refresh_hash,))
        except Exception:
            pass

    response.delete_cookie("refresh_token")
    return {"message": "Logged out"}
