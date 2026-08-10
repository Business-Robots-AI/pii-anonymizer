"""
Background sync service: moves PII data from platform DB to client DB, then deletes from platform.
"""
import asyncio
import json
import logging
from datetime import datetime
from typing import Optional

from psycopg2.extras import RealDictCursor

from .database import get_connection
from .client_db import client_db_manager

logger = logging.getLogger(__name__)

SYNC_INTERVAL = 30  # seconds
MAX_RETRIES = 3


class SyncService:
    def __init__(self):
        self._running = False
        self._task: Optional[asyncio.Task] = None

    async def start(self):
        self._running = True
        self._task = asyncio.create_task(self._sync_loop())
        logger.info("Sync service started")

    async def stop(self):
        self._running = False
        if self._task:
            self._task.cancel()
        logger.info("Sync service stopped")

    async def _sync_loop(self):
        while self._running:
            try:
                await asyncio.sleep(SYNC_INTERVAL)
                await self._do_sync()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Sync error: {e}")

    async def _do_sync(self):
        """Find unsynced sessions and push them to client DBs."""
        try:
            with get_connection() as conn:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT DISTINCT s.session_id, s.user_id, s.page_id,
                               s.created_at, s.expires_at
                        FROM pii_sessions s
                        WHERE s.synced = FALSE AND s.user_id IS NOT NULL
                          AND s.sync_status != 'failed'
                        ORDER BY s.created_at ASC
                        LIMIT 50
                    """)
                    sessions = cur.fetchall()
        except Exception as e:
            logger.warning(f"Could not query unsynced sessions: {e}")
            return

        for session in sessions:
            user_id = session["user_id"]
            session_id = session["session_id"]

            # Check if user has client DB configured
            config = client_db_manager.get_config(user_id)
            if not config or not config.get("is_verified"):
                continue

            try:
                await self._sync_session(user_id, session)
            except Exception as e:
                logger.warning(f"Sync failed for session {session_id}: {e}")
                self._mark_sync_status(session_id, "retry")

    async def _sync_session(self, user_id: int, session: dict):
        """Sync a single session to client DB."""
        session_id = session["session_id"]

        # Get mappings and audit log from platform
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("SELECT * FROM pii_mappings WHERE session_id = %s", (session_id,))
                mappings = cur.fetchall()

                cur.execute("SELECT * FROM pii_audit_log WHERE session_id = %s", (session_id,))
                audit_logs = cur.fetchall()

        # Write to client DB
        with client_db_manager.get_client_connection(user_id) as client_conn:
            with client_conn.cursor() as cur:
                # Insert session
                cur.execute("""
                    INSERT INTO pii_sessions (session_id, page_id, created_at, expires_at)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (session_id) DO NOTHING
                """, (session_id, session.get("page_id"),
                      session.get("created_at"), session.get("expires_at")))

                # Insert mappings
                for m in mappings:
                    cur.execute("""
                        INSERT INTO pii_mappings (session_id, placeholder, pii_type, original_value, created_at)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (session_id, placeholder) DO UPDATE SET original_value = EXCLUDED.original_value
                    """, (m["session_id"], m["placeholder"], m["pii_type"],
                          m["original_value"], m["created_at"]))

                # Insert audit logs
                for a in audit_logs:
                    cur.execute("""
                        INSERT INTO pii_audit_log (session_id, action, details, ip_address, created_at)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (a["session_id"], a["action"],
                          json.dumps(a["details"]) if a.get("details") else None,
                          a.get("ip_address"), a["created_at"]))

        # Mark synced on platform
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    UPDATE pii_sessions SET synced = TRUE, sync_status = 'synced' WHERE session_id = %s
                """, (session_id,))
                # Delete mappings from platform (data now lives in client DB)
                cur.execute("DELETE FROM pii_mappings WHERE session_id = %s", (session_id,))
                cur.execute("DELETE FROM pii_audit_log WHERE session_id = %s", (session_id,))

        logger.info(f"Synced session {session_id} to client DB (user {user_id})")

    def _mark_sync_status(self, session_id: str, status: str):
        try:
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE pii_sessions SET sync_status = %s WHERE session_id = %s",
                        (status, session_id)
                    )
        except Exception:
            pass


sync_service = SyncService()
