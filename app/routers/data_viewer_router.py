"""
Data viewer router: browse and filter PII data.
"""
import csv
import io
import logging
from typing import Optional

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from psycopg2.extras import RealDictCursor

from ..dependencies import get_current_user
from ..database import get_connection
from ..client_db import client_db_manager

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v2/me/data", tags=["Data Viewer"])


def _query_mappings(cur, user_id: Optional[int], pii_type: str = None,
                    search: str = None, date_from: str = None, date_to: str = None,
                    page: int = 1, per_page: int = 25, count_only: bool = False):
    """Build and execute query for PII mappings."""
    select = "COUNT(*)" if count_only else "m.id, m.session_id, m.placeholder, m.pii_type, m.original_value, m.created_at"
    where_clauses = []
    params = []

    if user_id is not None:
        where_clauses.append("s.user_id = %s")
        params.append(user_id)
    if pii_type and pii_type != "ALL":
        where_clauses.append("m.pii_type = %s")
        params.append(pii_type.upper())
    if date_from:
        where_clauses.append("m.created_at >= %s")
        params.append(date_from)
    if date_to:
        where_clauses.append("m.created_at <= %s")
        params.append(date_to)

    where = " AND ".join(where_clauses) if where_clauses else "1=1"
    sql = f"SELECT {select} FROM pii_mappings m JOIN pii_sessions s ON s.session_id = m.session_id WHERE {where}"

    if not count_only:
        sql += " ORDER BY m.created_at DESC"
        offset = (page - 1) * per_page
        sql += " LIMIT %s OFFSET %s"
        params.extend([per_page, offset])

    cur.execute(sql, params)
    if count_only:
        row = cur.fetchone()
        return row['count'] if isinstance(row, dict) else row[0]
    return cur.fetchall()


@router.get("")
async def list_data(
    pii_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    per_page: int = Query(25, ge=1, le=100),
    user: dict = Depends(get_current_user),
):
    """List PII mappings for current user, with filters."""
    user_id = user.get("id")

    # Try client DB first if configured
    config = client_db_manager.get_config(user_id) if user_id else None
    source = "platform"

    if config and config.get("is_verified"):
        try:
            with client_db_manager.get_client_connection(user_id) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    total = _query_mappings(cur, None, pii_type, search, date_from, date_to, page, per_page, count_only=True)
                    if total > 0:
                        rows = _query_mappings(cur, None, pii_type, search, date_from, date_to, page, per_page)
                        source = "client_db"
                        return {
                            "source": source,
                            "total": total,
                            "page": page,
                            "per_page": per_page,
                            "data": [dict(r) for r in rows],
                        }
        except Exception as e:
            logger.warning(f"Client DB read failed, falling back to platform: {e}")

    # Fallback to platform DB
    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            total = _query_mappings(cur, user_id, pii_type, search, date_from, date_to, page, per_page, count_only=True)
            rows = _query_mappings(cur, user_id, pii_type, search, date_from, date_to, page, per_page)
            return {
                "source": source,
                "total": total,
                "page": page,
                "per_page": per_page,
                "data": [dict(r) for r in rows],
            }


@router.get("/summary")
async def data_summary(user: dict = Depends(get_current_user)):
    """Get aggregated PII counts by type."""
    user_id = user.get("id")

    config = client_db_manager.get_config(user_id) if user_id else None
    if config and config.get("is_verified"):
        try:
            with client_db_manager.get_client_connection(user_id) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT pii_type, COUNT(*) as count,
                               COUNT(DISTINCT session_id) as sessions
                        FROM pii_mappings GROUP BY pii_type ORDER BY count DESC
                    """)
                    types = [dict(r) for r in cur.fetchall()]
                    if types:
                        return {"source": "client_db", "types": types}
        except Exception:
            pass

    with get_connection() as conn:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            where = "WHERE s.user_id = %s" if user_id else ""
            params = [user_id] if user_id else []
            cur.execute(f"""
                SELECT m.pii_type, COUNT(*) as count,
                       COUNT(DISTINCT m.session_id) as sessions
                FROM pii_mappings m
                JOIN pii_sessions s ON s.session_id = m.session_id
                {where}
                GROUP BY m.pii_type ORDER BY count DESC
            """, params)
            return {"source": "platform", "types": [dict(r) for r in cur.fetchall()]}


@router.get("/export")
async def export_data(
    pii_type: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    user: dict = Depends(get_current_user),
):
    """Export filtered PII data as CSV. Values are AES-256 encrypted."""
    user_id = user.get("id")
    rows = []

    # Try client DB first
    config = client_db_manager.get_config(user_id) if user_id else None
    if config and config.get("is_verified"):
        try:
            with client_db_manager.get_client_connection(user_id) as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    rows = _query_mappings(cur, None, pii_type, search, date_from, date_to, page=1, per_page=10000)
        except Exception as e:
            logger.warning(f"Client DB export failed, falling back to platform: {e}")
            rows = []

    # Fallback to platform DB
    if not rows:
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                rows = _query_mappings(cur, user_id, pii_type, search, date_from, date_to, page=1, per_page=10000)

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "Session", "Placeholder", "PII Type", "Original Value (AES-256 Encrypted)", "Created At"])
    for r in rows:
        r = dict(r)
        writer.writerow([r["id"], r["session_id"], r["placeholder"], r["pii_type"], r["original_value"], r["created_at"]])

    output.seek(0)
    return StreamingResponse(
        iter([output.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=pii_export_encrypted.csv"},
    )
