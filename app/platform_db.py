"""
Platform database initialization — creates tables for multi-tenant auth.
"""
import logging
from .database import get_connection

logger = logging.getLogger(__name__)


def init_platform_tables():
    """Create multi-tenant tables (users, api_tokens, client_db_configs, refresh_tokens).
    Also adds user_id columns to existing tables if missing."""
    with get_connection() as conn:
        with conn.cursor() as cur:
            cur.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id SERIAL PRIMARY KEY,
                    email VARCHAR(255) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    full_name VARCHAR(255),
                    company_name VARCHAR(255),
                    is_active BOOLEAN DEFAULT TRUE,
                    is_admin BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS api_tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash VARCHAR(255) UNIQUE NOT NULL,
                    token_prefix VARCHAR(16) NOT NULL,
                    name VARCHAR(128) DEFAULT 'Default',
                    is_active BOOLEAN DEFAULT TRUE,
                    last_used_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
                CREATE INDEX IF NOT EXISTS idx_api_tokens_user ON api_tokens(user_id);
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS client_db_configs (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    db_host VARCHAR(255) NOT NULL,
                    db_port INTEGER DEFAULT 5432,
                    db_name VARCHAR(128) NOT NULL,
                    db_user VARCHAR(128) NOT NULL,
                    db_password_encrypted BYTEA NOT NULL,
                    ssl_mode VARCHAR(32) DEFAULT 'prefer',
                    is_verified BOOLEAN DEFAULT FALSE,
                    last_sync_at TIMESTAMP,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_client_db_user ON client_db_configs(user_id);
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS refresh_tokens (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    token_hash VARCHAR(255) UNIQUE NOT NULL,
                    expires_at TIMESTAMP NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                CREATE INDEX IF NOT EXISTS idx_refresh_hash ON refresh_tokens(token_hash);
                CREATE INDEX IF NOT EXISTS idx_refresh_user ON refresh_tokens(user_id);
            """)

            # Add user_id to existing tables if missing
            for table in ("pii_sessions", "pii_mappings", "pii_audit_log"):
                cur.execute(f"""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (
                            SELECT 1 FROM information_schema.columns
                            WHERE table_name = '{table}' AND column_name = 'user_id'
                        ) THEN
                            ALTER TABLE {table} ADD COLUMN user_id INTEGER REFERENCES users(id) ON DELETE SET NULL;
                        END IF;
                    END $$;
                """)

            # Add sync columns to pii_sessions if missing
            cur.execute("""
                DO $$
                BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM information_schema.columns
                        WHERE table_name = 'pii_sessions' AND column_name = 'synced'
                    ) THEN
                        ALTER TABLE pii_sessions ADD COLUMN synced BOOLEAN DEFAULT FALSE;
                        ALTER TABLE pii_sessions ADD COLUMN sync_status VARCHAR(32) DEFAULT 'pending';
                    END IF;
                END $$;
            """)

            logger.info("Platform multi-tenant tables initialized")
