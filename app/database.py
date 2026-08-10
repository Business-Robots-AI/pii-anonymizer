"""
Database module for persistent PII storage.
Uses PostgreSQL for storing contact PII mappings.
"""
import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Optional, List
from contextlib import contextmanager

import psycopg2
from psycopg2.extras import RealDictCursor
from psycopg2.pool import ThreadedConnectionPool

from .crypto import encrypt_value, safe_decrypt

logger = logging.getLogger(__name__)

# Database configuration
DB_CONFIG = {
    "host": os.getenv("PII_DB_HOST", "localhost"),
    "port": int(os.getenv("PII_DB_PORT", 5432)),
    "database": os.getenv("PII_DB_NAME", "pii_anonymizer"),
    "user": os.getenv("PII_DB_USER", "pii_user"),
    "password": os.getenv("PII_DB_PASSWORD", ""),
}

# Connection pool
_pool: Optional[ThreadedConnectionPool] = None


def get_pool() -> ThreadedConnectionPool:
    """Get or create connection pool."""
    global _pool
    if _pool is None:
        _pool = ThreadedConnectionPool(
            minconn=2,
            maxconn=10,
            **DB_CONFIG
        )
    return _pool


@contextmanager
def get_connection():
    """Context manager for database connections."""
    pool = get_pool()
    conn = pool.getconn()
    try:
        yield conn
        conn.commit()
    except Exception as e:
        conn.rollback()
        raise e
    finally:
        pool.putconn(conn)


def init_database():
    """Initialize database tables."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            # Create sessions table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pii_sessions (
                    id SERIAL PRIMARY KEY,
                    session_id VARCHAR(64) UNIQUE NOT NULL,
                    page_id VARCHAR(64),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON pii_sessions(session_id);
            """)

            # Create PII mappings table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pii_mappings (
                    id SERIAL PRIMARY KEY,
                    session_id VARCHAR(64) NOT NULL REFERENCES pii_sessions(session_id) ON DELETE CASCADE,
                    placeholder VARCHAR(128) NOT NULL,
                    pii_type VARCHAR(32) NOT NULL,
                    original_value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(session_id, placeholder)
                );

                CREATE INDEX IF NOT EXISTS idx_mappings_session_id ON pii_mappings(session_id);
            """)

            # Create audit log table
            cur.execute("""
                CREATE TABLE IF NOT EXISTS pii_audit_log (
                    id SERIAL PRIMARY KEY,
                    session_id VARCHAR(64),
                    action VARCHAR(32) NOT NULL,
                    details JSONB,
                    ip_address VARCHAR(45),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );

                CREATE INDEX IF NOT EXISTS idx_audit_created ON pii_audit_log(created_at);
            """)

            # Add confidence column if not exists
            cur.execute("""
                DO $$ BEGIN
                    ALTER TABLE pii_mappings ADD COLUMN IF NOT EXISTS confidence VARCHAR(16) DEFAULT 'high';
                    ALTER TABLE pii_mappings ADD COLUMN IF NOT EXISTS detection_method VARCHAR(32);
                EXCEPTION WHEN others THEN NULL;
                END $$;
            """)

            # Custom words table (stop-words and extra names per client)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS client_custom_words (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    word VARCHAR(128) NOT NULL,
                    word_type VARCHAR(16) NOT NULL CHECK (word_type IN ('stop_word', 'name')),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, word)
                );
                CREATE INDEX IF NOT EXISTS idx_custom_words_user ON client_custom_words(user_id);
            """)

            logger.info("Database tables initialized successfully")


class PIIDatabase:
    """Database interface for PII storage."""

    def create_session(
        self,
        session_id: str,
        page_id: Optional[str] = None,
        ttl_hours: int = 24,
        user_id: Optional[int] = None,
        **kwargs,
    ) -> str:
        """Create a new PII session."""
        with get_connection() as conn:
            with conn.cursor() as cur:
                expires_at = datetime.utcnow() + timedelta(hours=ttl_hours)
                cur.execute("""
                    INSERT INTO pii_sessions (session_id, page_id, expires_at, user_id)
                    VALUES (%s, %s, %s, %s)
                    ON CONFLICT (session_id) DO UPDATE SET
                        page_id = EXCLUDED.page_id,
                        user_id = COALESCE(EXCLUDED.user_id, pii_sessions.user_id),
                        updated_at = CURRENT_TIMESTAMP
                    RETURNING session_id
                """, (session_id, page_id, expires_at, user_id))
                return cur.fetchone()[0]

    def store_mapping(
        self,
        session_id: str,
        mapping: Dict[str, str],
        pii_types: Dict[str, str],
        user_id: Optional[int] = None,
        confidence_map: Optional[Dict] = None,
    ) -> bool:
        """Store PII mapping for a session with optional confidence data."""
        with get_connection() as conn:
            with conn.cursor() as cur:
                for placeholder, original_value in mapping.items():
                    pii_type = pii_types.get(placeholder, "UNKNOWN")
                    conf = "high"
                    method = "regex"
                    if confidence_map and placeholder in confidence_map:
                        conf = confidence_map[placeholder].get("confidence", "high")
                        method = confidence_map[placeholder].get("method", "regex")
                    encrypted_value = encrypt_value(original_value)
                    cur.execute("""
                        INSERT INTO pii_mappings (session_id, placeholder, pii_type, original_value, user_id, confidence, detection_method)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        ON CONFLICT (session_id, placeholder) DO UPDATE SET
                            original_value = EXCLUDED.original_value,
                            user_id = COALESCE(EXCLUDED.user_id, pii_mappings.user_id),
                            confidence = EXCLUDED.confidence,
                            detection_method = EXCLUDED.detection_method
                    """, (session_id, placeholder, pii_type, encrypted_value, user_id, conf, method))
                return True

    def get_mapping(self, session_id: str) -> Optional[Dict[str, str]]:
        """Retrieve PII mapping for a session."""
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT placeholder, original_value
                    FROM pii_mappings
                    WHERE session_id = %s
                """, (session_id,))
                rows = cur.fetchall()
                if not rows:
                    return None
                return {row['placeholder']: safe_decrypt(row['original_value']) for row in rows}

    def get_session(self, session_id: str) -> Optional[Dict]:
        """Get session details."""
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT * FROM pii_sessions WHERE session_id = %s
                """, (session_id,))
                return cur.fetchone()

    def log_action(
        self,
        action: str,
        session_id: Optional[str] = None,
        details: Optional[Dict] = None,
        ip_address: Optional[str] = None,
        user_id: Optional[int] = None,
    ):
        """Log an action to audit log."""
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO pii_audit_log (session_id, action, details, ip_address)
                    VALUES (%s, %s, %s, %s)
                """, (session_id, action, json.dumps(details) if details else None, ip_address))

    def cleanup_expired(self) -> int:
        """Remove expired sessions and their mappings."""
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM pii_sessions
                    WHERE expires_at < CURRENT_TIMESTAMP
                    RETURNING session_id
                """)
                deleted = cur.rowcount
                logger.info(f"Cleaned up {deleted} expired sessions")
                return deleted

    def get_stats(self, user_id: Optional[int] = None) -> Dict:
        """Get database statistics, filtered by user_id if provided."""
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                if user_id:
                    cur.execute("""
                        SELECT
                            (SELECT COUNT(*) FROM pii_sessions WHERE user_id = %s) as total_sessions,
                            (SELECT COUNT(*) FROM pii_sessions WHERE user_id = %s AND expires_at > CURRENT_TIMESTAMP) as active_sessions,
                            (SELECT COUNT(*) FROM pii_mappings WHERE session_id IN (SELECT session_id FROM pii_sessions WHERE user_id = %s)) as total_mappings,
                            (SELECT COUNT(DISTINCT pii_type) FROM pii_mappings WHERE session_id IN (SELECT session_id FROM pii_sessions WHERE user_id = %s)) as pii_types_count
                    """, (user_id, user_id, user_id, user_id))
                else:
                    cur.execute("""
                        SELECT
                            (SELECT COUNT(*) FROM pii_sessions) as total_sessions,
                            (SELECT COUNT(*) FROM pii_sessions WHERE expires_at > CURRENT_TIMESTAMP) as active_sessions,
                            (SELECT COUNT(*) FROM pii_mappings) as total_mappings,
                            (SELECT COUNT(DISTINCT pii_type) FROM pii_mappings) as pii_types_count
                    """)
                return dict(cur.fetchone())

    # ======== CUSTOM WORDS ========

    def get_custom_words(self, user_id: int) -> List[Dict]:
        """Get custom stop-words and names for a user."""
        with get_connection() as conn:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT id, word, word_type, created_at
                    FROM client_custom_words
                    WHERE user_id = %s
                    ORDER BY word_type, word
                """, (user_id,))
                return [dict(r) for r in cur.fetchall()]

    def add_custom_word(self, user_id: int, word: str, word_type: str) -> int:
        """Add a custom stop-word or name. word_type: 'stop_word' or 'name'."""
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO client_custom_words (user_id, word, word_type)
                    VALUES (%s, %s, %s)
                    ON CONFLICT (user_id, word) DO NOTHING
                    RETURNING id
                """, (user_id, word.strip(), word_type))
                row = cur.fetchone()
                return row[0] if row else 0

    def delete_custom_word(self, user_id: int, word_id: int) -> bool:
        """Delete a custom word."""
        with get_connection() as conn:
            with conn.cursor() as cur:
                cur.execute("""
                    DELETE FROM client_custom_words
                    WHERE id = %s AND user_id = %s
                """, (word_id, user_id))
                return cur.rowcount > 0


# Global instance
pii_db = PIIDatabase()
