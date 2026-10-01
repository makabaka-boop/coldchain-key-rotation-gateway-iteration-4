"""PostgreSQL connection pool and schema bootstrap."""
import asyncio

import asyncpg

from .config import DATABASE_URL, DEFAULT_POP_CHALLENGE_TTL_SECONDS

SCHEMA = """
CREATE TABLE IF NOT EXISTS tenant_keys (
    tenant_id   TEXT        NOT NULL,
    key_id      TEXT        NOT NULL,
    role        TEXT        NOT NULL CHECK (role IN ('current', 'candidate', 'retiring', 'retired')),
    public_key  BYTEA       NOT NULL CHECK (octet_length(public_key) = 32),
    revoked_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, key_id),
    CONSTRAINT tenant_keys_candidate_not_revoked
        CHECK (role <> 'candidate' OR revoked_at IS NULL)
);

-- Migration for existing deployments: revocation is orthogonal to the role
-- state machine, recorded as a timestamp on the key row itself. Adding the
-- column preserves every existing key and receipt; NULL means "not revoked".
ALTER TABLE tenant_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- Storage-layer backstop for the seat-release rule: a revoked candidate is
-- moved out of the candidate role in the same transaction, so a row can never
-- be both 'candidate' and revoked. (ADD CONSTRAINT has no IF NOT EXISTS.)
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint
        WHERE conname = 'tenant_keys_candidate_not_revoked'
          AND conrelid = 'tenant_keys'::regclass
    ) THEN
        ALTER TABLE tenant_keys ADD CONSTRAINT tenant_keys_candidate_not_revoked
            CHECK (role <> 'candidate' OR revoked_at IS NULL);
    END IF;
END $$;

-- Invariants, enforced at the storage layer: per tenant at most one key per
-- in-use role. 'retired' is unbounded.
CREATE UNIQUE INDEX IF NOT EXISTS tenant_keys_one_current
    ON tenant_keys (tenant_id) WHERE role = 'current';
CREATE UNIQUE INDEX IF NOT EXISTS tenant_keys_one_candidate
    ON tenant_keys (tenant_id) WHERE role = 'candidate';
CREATE UNIQUE INDEX IF NOT EXISTS tenant_keys_one_retiring
    ON tenant_keys (tenant_id) WHERE role = 'retiring';

CREATE TABLE IF NOT EXISTS receipts (
    receipt_id  UUID        PRIMARY KEY,
    tenant_id   TEXT        NOT NULL,
    key_id      TEXT        NOT NULL,
    body_sha256 BYTEA       NOT NULL,
    body_size   BIGINT      NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS receipts_by_tenant ON receipts (tenant_id, created_at);

-- v2 verification receipts: one immutable receipt per (tenant, message id).
-- The unique constraint is the cross-instance arbiter: two instances accepting
-- the same request concurrently can only produce one row. The tenant column is
-- part of the key, so message ids never collide across tenants. The bound
-- key_id and body_sha256 let an exact retry be answered with the original
-- receipt while any reuse of the id with another key or content is a conflict.
CREATE TABLE IF NOT EXISTS v2_receipts (
    receipt_id    UUID        PRIMARY KEY,
    tenant_id     TEXT        NOT NULL,
    message_id    TEXT        NOT NULL,
    key_id        TEXT        NOT NULL,
    body_sha256   BYTEA       NOT NULL,
    body_size     BIGINT      NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now(),
    CONSTRAINT v2_receipts_one_per_message UNIQUE (tenant_id, message_id)
);
CREATE INDEX IF NOT EXISTS v2_receipts_by_tenant ON v2_receipts (tenant_id, created_at);

-- Per-tenant key generation. Only present once a tenant gains a key; the
-- generation advances whenever the current key changes, binding a
-- proof-of-possession to the exact current/candidate pair it was made for.
CREATE TABLE IF NOT EXISTS tenant_state (
    tenant_id        TEXT PRIMARY KEY,
    key_generation   BIGINT NOT NULL DEFAULT 0
);

-- Tenant-level, opt-in pre-promotion proof-of-possession policy. Absence of a
-- row means the legacy behaviour: register/promote/verify stay unchanged.
CREATE TABLE IF NOT EXISTS tenant_policies (
    tenant_id        TEXT PRIMARY KEY,
    pop_required     BOOLEAN NOT NULL DEFAULT FALSE,
    challenge_ttl    INTEGER NOT NULL CHECK (challenge_ttl BETWEEN 1 AND 86400),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time challenges / proofs. Each row moves
--   issued -> answered -> consumed (by the single successful promote)
-- and may be short-circuited to 'expired'. Only 'answered' rows whose context
-- still matches can drive a promotion.
CREATE TABLE IF NOT EXISTS pop_challenges (
    challenge_id        UUID        PRIMARY KEY,
    tenant_id           TEXT        NOT NULL,
    candidate_key_id    TEXT        NOT NULL,
    current_key_id      TEXT        NOT NULL,
    current_generation  BIGINT      NOT NULL,
    nonce               BYTEA       NOT NULL,
    status              TEXT        NOT NULL CHECK (status IN
                            ('issued', 'answered', 'consumed', 'expired')),
    ttl_seconds         INTEGER     NOT NULL CHECK (ttl_seconds BETWEEN 1 AND 86400),
    issued_at           TIMESTAMPTZ NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    answered_at         TIMESTAMPTZ,
    consumed_at         TIMESTAMPTZ,
    FOREIGN KEY (tenant_id, candidate_key_id)
        REFERENCES tenant_keys (tenant_id, key_id),
    FOREIGN KEY (tenant_id, current_key_id)
        REFERENCES tenant_keys (tenant_id, key_id)
);
-- Backstop: at most one live (issued/answered) challenge per tenant+candidate.
CREATE UNIQUE INDEX IF NOT EXISTS pop_challenges_one_open
    ON pop_challenges (tenant_id, candidate_key_id)
    WHERE status IN ('issued', 'answered');

-- Shared virtual clock: now() plus one offset row. Every API instance reads
-- the same virtual time, so acceptance runs can advance expiry deterministically.
CREATE TABLE IF NOT EXISTS service_clock (
    id         INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    offset_sec BIGINT NOT NULL DEFAULT 0
);
INSERT INTO service_clock (id, offset_sec)
VALUES (1, 0) ON CONFLICT (id) DO NOTHING;
"""

# Virtual now() used for every challenge/proof timing decision. STABLE within
# the transaction and identical on every API instance because the offset lives
# in the database.
VIRTUAL_NOW_SQL = "(now() + (SELECT offset_sec * interval '1 second' FROM service_clock WHERE id = 1))"

pool: asyncpg.Pool | None = None


async def init() -> None:
    """Create the pool and apply the schema, waiting for Postgres to come up."""
    global pool
    last_error: Exception | None = None
    for _ in range(30):
        candidate: asyncpg.Pool | None = None
        try:
            candidate = await asyncpg.create_pool(dsn=DATABASE_URL, min_size=1, max_size=10)
            async with candidate.acquire() as conn:
                await conn.execute(SCHEMA)
            pool = candidate
            return
        except Exception as exc:  # Postgres not ready yet; retry.
            if candidate is not None:
                await candidate.close()
            last_error = exc
            await asyncio.sleep(1)
    raise RuntimeError(f"database did not become ready: {last_error}")


async def close() -> None:
    global pool
    if pool is not None:
        await pool.close()
        pool = None


def default_challenge_ttl() -> int:
    return DEFAULT_POP_CHALLENGE_TTL_SECONDS
