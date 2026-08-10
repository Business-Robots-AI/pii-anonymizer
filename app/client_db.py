"""
Client database connection management.
Handles connecting to client's own PostgreSQL databases.
"""
import logging
import socket
from typing import Optional, Dict
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor

from .crypto import encrypt_value, safe_decrypt
from .database import get_connection

logger = logging.getLogger(__name__)


class ClientDBManager:
    """Manages connections to client-owned PostgreSQL databases."""

    def save_config(self, user_id: int, host: str, port: int, db_name: str,
                    db_user: str, db_password: str, ssl_mode: str = "prefer") -> int:
        """Save or update client DB config. Returns config id."""
        encrypted_pw = encrypt_value(db_password)
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO client_db_configs (user_id, db_host, db_port, db_name, db_user, db_password_encrypted, ssl_mode)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (user_id) DO UPDATE SET
                        db_host = EXCLUDED.db_host,
                        db_port = EXCLUDED.db_port,
                        db_name = EXCLUDED.db_name,
                        db_user = EXCLUDED.db_user,
                        db_password_encrypted = EXCLUDED.db_password_encrypted,
                        ssl_mode = EXCLUDED.ssl_mode,
                        is_verified = FALSE,
                        updated_at = CURRENT_TIMESTAMP
                    RETURNING id
                """, (user_id, host, port, db_name, db_user, encrypted_pw, ssl_mode))
                return cur.fetchone()[0]

    def get_config(self, user_id: int) -> Optional[Dict]:
        """Get client DB config (without decrypted password)."""
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, user_id, db_host, db_port, db_name, db_user, ssl_mode,
                           is_verified, last_sync_at, created_at, updated_at
                    FROM client_db_configs WHERE user_id = %s
                """, (user_id,))
                row = cur.fetchone()
                return dict(row) if row else None

    def _get_connection_params(self, user_id: int) -> Optional[Dict]:
        """Get full connection params including decrypted password."""
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT db_host, db_port, db_name, db_user, db_password_encrypted, ssl_mode
                    FROM client_db_configs WHERE user_id = %s
                """, (user_id,))
                row = cur.fetchone()
                if not row:
                    return None
                return {
                    "host": row["db_host"],
                    "port": row["db_port"],
                    "database": row["db_name"],
                    "user": row["db_user"],
                    "password": safe_decrypt(row["db_password_encrypted"]),
                    "sslmode": row["ssl_mode"],
                }

    @contextmanager
    def get_client_connection(self, user_id: int):
        """Context manager yielding a connection to the client's DB."""
        params = self._get_connection_params(user_id)
        if not params:
            raise ValueError(f"No DB config for user {user_id}")
        # Force IPv4 for external hosts (Docker may lack IPv6)
        host = params.get("host", "")
        if host and not host.replace(".", "").isdigit():
            try:
                ipv4 = socket.getaddrinfo(host, params.get("port", 5432), socket.AF_INET)[0][4][0]
                params["hostaddr"] = ipv4
            except Exception:
                pass
        conn = psycopg2.connect(**params, connect_timeout=10)
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def test_connection(self, user_id: int) -> bool:
        """Test connection to client DB. Updates is_verified."""
        try:
            with self.get_client_connection(user_id) as conn:
                with conn.cursor() as cur:
                    cur.execute("SELECT 1")
            with get_connection() as conn:
                with conn.cursor() as cur:
                    cur.execute(
                        "UPDATE client_db_configs SET is_verified = TRUE WHERE user_id = %s",
                        (user_id,)
                    )
            return True
        except Exception as e:
            logger.warning(f"Client DB test failed for user {user_id}: {e}")
            with get_connection() as pconn:
                with pconn.cursor() as cur:
                    cur.execute(
                        "UPDATE client_db_configs SET is_verified = FALSE WHERE user_id = %s",
                        (user_id,)
                    )
            return False

    def verify_schema(self, user_id: int) -> Dict:
        """Check if required tables exist in client DB."""
        required = ["pii_sessions", "pii_mappings", "pii_audit_log"]
        result = {}
        try:
            with self.get_client_connection(user_id) as conn:
                with conn.cursor() as cur:
                    for table in required:
                        cur.execute("""
                            SELECT EXISTS (
                                SELECT 1 FROM information_schema.tables WHERE table_name = %s
                            )
                        """, (table,))
                        result[table] = cur.fetchone()[0]
        except Exception as e:
            for t in required:
                result[t] = False
            result["error"] = str(e)
        return result

    def delete_config(self, user_id: int) -> bool:
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("DELETE FROM client_db_configs WHERE user_id = %s", (user_id,))
                return cur.rowcount > 0


client_db_manager = ClientDBManager()
