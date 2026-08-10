"""
User management router: profile, API tokens, database config.
"""
import logging
from typing import List

from fastapi import APIRouter, HTTPException, Depends, Request
from psycopg2.extras import RealDictCursor

from ..dependencies import get_current_user
from ..auth_jwt import hash_password, verify_password, generate_api_token
from ..user_models import (
    UserResponse, ApiTokenCreateRequest, ApiTokenResponse,
    ApiTokenCreatedResponse, ClientDbConfigRequest, ClientDbConfigResponse,
    ChangePasswordRequest,
)
from ..database import get_connection, DB_CONFIG
from ..client_db import client_db_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v2/me", tags=["User Management"])


# === Profile ===

@router.get("", response_model=UserResponse)
async def get_profile(user: dict = Depends(get_current_user)):
    return UserResponse(**user)


@router.put("", response_model=UserResponse)
async def update_profile(
    full_name: str = None,
    company_name: str = None,
    user: dict = Depends(get_current_user),
):
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth cannot update profile")
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                UPDATE users SET
                    full_name = COALESCE(%s, full_name),
                    company_name = COALESCE(%s, company_name),
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s RETURNING *
            """, (full_name, company_name, user["id"]))
            updated = cur.fetchone()
    return UserResponse(**dict(updated))


@router.put("/password")
async def change_password(
    req: ChangePasswordRequest,
    user: dict = Depends(get_current_user),
):
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth cannot change password")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT password_hash FROM users WHERE id = %s", (user["id"],))
            row = cur.fetchone()
            if not row or not verify_password(req.current_password, row[0]):
                raise HTTPException(400, "Current password is incorrect")
            new_hash = hash_password(req.new_password)
            cur.execute("UPDATE users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s",
                        (new_hash, user["id"]))
    return {"message": "Password updated"}


# === API Tokens ===

@router.get("/tokens", response_model=List[ApiTokenResponse])
async def list_tokens(user: dict = Depends(get_current_user)):
    if user.get("id") is None:
        return []
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT id, token_prefix, name, is_active, last_used_at, created_at
                FROM api_tokens WHERE user_id = %s ORDER BY created_at DESC
            """, (user["id"],))
            return [ApiTokenResponse(**dict(r)) for r in cur.fetchall()]


@router.post("/tokens", response_model=ApiTokenCreatedResponse, status_code=201)
async def create_token(
    req: ApiTokenCreateRequest,
    user: dict = Depends(get_current_user),
):
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth cannot create tokens")
    raw_token, token_hash = generate_api_token()
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO api_tokens (user_id, token_hash, token_prefix, name)
                VALUES (%s, %s, %s, %s) RETURNING id
            """, (user["id"], token_hash, raw_token[:16], req.name))
            token_id = cur.fetchone()[0]
    return ApiTokenCreatedResponse(
        id=token_id,
        token=raw_token,
        token_prefix=raw_token[:16],
        name=req.name,
    )


@router.delete("/tokens/{token_id}")
async def delete_token(token_id: int, user: dict = Depends(get_current_user)):
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth cannot delete tokens")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM api_tokens WHERE id = %s AND user_id = %s", (token_id, user["id"]))
            if cur.rowcount == 0:
                raise HTTPException(404, "Token not found")
    return {"message": "Token deleted"}


# === Client Database Config ===

@router.get("/database", response_model=ClientDbConfigResponse)
async def get_db_config(user: dict = Depends(get_current_user)):
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth has no DB config")
    config = client_db_manager.get_config(user["id"])
    if not config:
        raise HTTPException(404, "No database configured")
    return ClientDbConfigResponse(**config)


@router.post("/database", response_model=ClientDbConfigResponse)
async def save_db_config(
    req: ClientDbConfigRequest,
    user: dict = Depends(get_current_user),
):
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth cannot configure DB")
    client_db_manager.save_config(
        user_id=user["id"],
        host=req.db_host, port=req.db_port,
        db_name=req.db_name, db_user=req.db_user,
        db_password=req.db_password, ssl_mode=req.ssl_mode,
    )
    config = client_db_manager.get_config(user["id"])
    return ClientDbConfigResponse(**config)


@router.post("/database/test")
async def test_db_connection(user: dict = Depends(get_current_user)):
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth cannot test DB")
    ok = client_db_manager.test_connection(user["id"])
    if ok:
        schema = client_db_manager.verify_schema(user["id"])
        return {"connected": True, "schema": schema}
    return {"connected": False, "error": "Connection failed"}


@router.post("/database/restore-default")
async def restore_default_db(user: dict = Depends(get_current_user)):
    """Restore connection to platform default database."""
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth cannot configure DB")
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
    return {"message": "Default database restored"}


@router.delete("/database")
async def delete_db_config(user: dict = Depends(get_current_user)):
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth cannot delete DB config")
    deleted = client_db_manager.delete_config(user["id"])
    if not deleted:
        raise HTTPException(404, "No database configured")
    return {"message": "Database config removed"}


# === Custom Words ===

@router.get("/custom-words")
async def get_custom_words(user: dict = Depends(get_current_user)):
    """Get custom stop-words and names."""
    from ..database import pii_db
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth not supported")
    words = pii_db.get_custom_words(user["id"])
    return {"words": words}


@router.post("/custom-words")
async def add_custom_word(
    request: Request,
    user: dict = Depends(get_current_user),
):
    """Add a custom stop-word or name."""
    from ..database import pii_db
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth not supported")
    body = await request.json()
    word = body.get("word", "").strip()
    word_type = body.get("word_type", "")
    if not word or word_type not in ("stop_word", "name"):
        raise HTTPException(400, "Invalid word or word_type")
    word_id = pii_db.add_custom_word(user["id"], word, word_type)
    return {"id": word_id, "word": word, "word_type": word_type}


@router.delete("/custom-words/{word_id}")
async def delete_custom_word(word_id: int, user: dict = Depends(get_current_user)):
    """Delete a custom word."""
    from ..database import pii_db
    if user.get("id") is None:
        raise HTTPException(400, "Legacy auth not supported")
    deleted = pii_db.delete_custom_word(user["id"], word_id)
    if not deleted:
        raise HTTPException(404, "Word not found")
    return {"message": "Deleted"}
