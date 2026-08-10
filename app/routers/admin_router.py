"""
Admin API endpoints — user management, system stats, audit.
All endpoints require is_admin=True.
"""
import logging
import secrets
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from psycopg2.extras import RealDictCursor

from ..dependencies import require_admin
from ..database import get_connection
from ..auth_jwt import hash_password

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v2/admin", tags=["Admin"])


# ── System-wide statistics ──────────────────────────────────────────

@router.get("/stats")
async def admin_system_stats(admin: dict = Depends(require_admin)):
    """Global platform statistics."""
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT COUNT(*) as total FROM users")
            total_users = cur.fetchone()["total"]

            cur.execute("SELECT COUNT(*) as total FROM users WHERE is_active = TRUE")
            active_users = cur.fetchone()["total"]

            cur.execute("SELECT COUNT(*) as total FROM users WHERE is_admin = TRUE")
            admin_count = cur.fetchone()["total"]

            cur.execute("SELECT COUNT(*) as total FROM api_tokens WHERE is_active = TRUE")
            active_tokens = cur.fetchone()["total"]

            sessions_count = 0
            mappings_count = 0
            try:
                cur.execute("SELECT COUNT(*) as total FROM pii_sessions")
                sessions_count = cur.fetchone()["total"]
                cur.execute("SELECT COUNT(*) as total FROM pii_mappings")
                mappings_count = cur.fetchone()["total"]
            except Exception:
                pass

            cur.execute("SELECT COUNT(*) as total FROM client_db_configs WHERE is_verified = TRUE")
            verified_dbs = cur.fetchone()["total"]

            return {
                "total_users": total_users,
                "active_users": active_users,
                "admin_count": admin_count,
                "active_tokens": active_tokens,
                "sessions_count": sessions_count,
                "mappings_count": mappings_count,
                "verified_databases": verified_dbs,
            }


# ── User management ─────────────────────────────────────────────────

@router.get("/users")
async def admin_list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    search: Optional[str] = None,
    admin: dict = Depends(require_admin),
):
    """List all users with pagination and search."""
    offset = (page - 1) * per_page
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where = ""
            params = []
            if search:
                where = "WHERE email ILIKE %s OR full_name ILIKE %s OR company_name ILIKE %s"
                like = f"%{search}%"
                params = [like, like, like]

            cur.execute(f"SELECT COUNT(*) as total FROM users {where}", params)
            total = cur.fetchone()["total"]

            cur.execute(f"""
                SELECT u.id, u.email, u.full_name, u.company_name,
                       u.is_active, u.is_admin, u.created_at, u.updated_at,
                       (SELECT COUNT(*) FROM api_tokens t WHERE t.user_id = u.id AND t.is_active = TRUE) as token_count,
                       (SELECT COUNT(*) FROM client_db_configs c WHERE c.user_id = u.id) as has_db
                FROM users u {where}
                ORDER BY u.created_at DESC
                LIMIT %s OFFSET %s
            """, params + [per_page, offset])
            users = [dict(u) for u in cur.fetchall()]

            return {
                "total": total,
                "page": page,
                "per_page": per_page,
                "pages": (total + per_page - 1) // per_page,
                "users": users,
            }


@router.get("/users/{user_id}")
async def admin_get_user(user_id: int, admin: dict = Depends(require_admin)):
    """Get single user details with stats."""
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT id, email, full_name, company_name, is_active, is_admin, created_at, updated_at FROM users WHERE id = %s", (user_id,))
            user = cur.fetchone()
            if not user:
                raise HTTPException(status_code=404, detail="User not found")

            cur.execute("SELECT id, token_prefix, name, is_active, last_used_at, created_at FROM api_tokens WHERE user_id = %s ORDER BY created_at DESC", (user_id,))
            tokens = [dict(t) for t in cur.fetchall()]

            cur.execute("SELECT id, db_host, db_port, db_name, db_user, ssl_mode, is_verified, last_sync_at, created_at FROM client_db_configs WHERE user_id = %s", (user_id,))
            db_config = cur.fetchone()

            session_count = 0
            mapping_count = 0
            try:
                cur.execute("SELECT COUNT(*) as total FROM pii_sessions WHERE user_id = %s", (user_id,))
                session_count = cur.fetchone()["total"]
                cur.execute("SELECT COUNT(*) as total FROM pii_mappings WHERE user_id = %s", (user_id,))
                mapping_count = cur.fetchone()["total"]
            except Exception:
                pass

            return {
                "user": dict(user),
                "tokens": tokens,
                "db_config": dict(db_config) if db_config else None,
                "session_count": session_count,
                "mapping_count": mapping_count,
            }


@router.put("/users/{user_id}/toggle-admin")
async def admin_toggle_admin(user_id: int, admin: dict = Depends(require_admin)):
    """Toggle admin status for a user."""
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot change your own admin status")
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("UPDATE users SET is_admin = NOT is_admin, updated_at = CURRENT_TIMESTAMP WHERE id = %s RETURNING id, email, is_admin", (user_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            return {"ok": True, "user_id": row["id"], "email": row["email"], "is_admin": row["is_admin"]}


@router.put("/users/{user_id}/toggle-active")
async def admin_toggle_active(user_id: int, admin: dict = Depends(require_admin)):
    """Toggle active status (block/unblock user)."""
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot deactivate yourself")
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("UPDATE users SET is_active = NOT is_active, updated_at = CURRENT_TIMESTAMP WHERE id = %s RETURNING id, email, is_active", (user_id,))
            row = cur.fetchone()
            if not row:
                raise HTTPException(status_code=404, detail="User not found")
            return {"ok": True, "user_id": row["id"], "email": row["email"], "is_active": row["is_active"]}


@router.delete("/users/{user_id}")
async def admin_delete_user(user_id: int, admin: dict = Depends(require_admin)):
    """Permanently delete a user and all associated data."""
    if user_id == admin["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete yourself")
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM users WHERE id = %s", (user_id,))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
            return {"ok": True, "deleted_user_id": user_id}


@router.put("/users/{user_id}/reset-password")
async def admin_reset_password(user_id: int, admin: dict = Depends(require_admin)):
    """Reset user password to a temporary one."""
    # Random per reset — a fixed string would make every reset account guessable.
    temp_password = secrets.token_urlsafe(12)
    hashed = hash_password(temp_password)
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("UPDATE users SET password_hash = %s, updated_at = CURRENT_TIMESTAMP WHERE id = %s", (hashed, user_id))
            if cur.rowcount == 0:
                raise HTTPException(status_code=404, detail="User not found")
            return {"ok": True, "temporary_password": temp_password}


# ── Audit log (global) ──────────────────────────────────────────────

@router.get("/audit")
async def admin_audit_log(
    limit: int = Query(100, ge=1, le=500),
    admin: dict = Depends(require_admin),
):
    """View global audit log."""
    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT a.*, u.email as user_email
                    FROM pii_audit_log a
                    LEFT JOIN users u ON u.id = a.user_id
                    ORDER BY a.created_at DESC LIMIT %s
                """, (limit,))
                logs = [dict(l) for l in cur.fetchall()]
                return {"count": len(logs), "logs": logs}
    except Exception as e:
        return {"count": 0, "logs": [], "error": str(e)}


# ── All sessions (global) ───────────────────────────────────────────

@router.get("/sessions")
async def admin_all_sessions(
    limit: int = Query(100, ge=1, le=500),
    admin: dict = Depends(require_admin),
):
    """View all PII sessions across all users."""
    try:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT s.session_id, s.contact_id, s.page_id, s.channel,
                           s.created_at, s.user_id, u.email as user_email,
                           COUNT(m.id) as mapping_count
                    FROM pii_sessions s
                    LEFT JOIN pii_mappings m ON s.session_id = m.session_id
                    LEFT JOIN users u ON u.id = s.user_id
                    GROUP BY s.id, u.email
                    ORDER BY s.created_at DESC LIMIT %s
                """, (limit,))
                sessions = [dict(s) for s in cur.fetchall()]
                return {"count": len(sessions), "sessions": sessions}
    except Exception as e:
        return {"count": 0, "sessions": [], "error": str(e)}
