"""Tenant key lifecycle: register, promote, retire, inspect."""
import re

import asyncpg
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from . import db
from .auth import require
from .errors import ApiError
from .pop import consume_proof
from .util import b64url_decode_unpadded

router = APIRouter(tags=["keys"])

_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_ACTIVE_ROLES = ("current", "candidate", "retiring")


class RegisterKeyRequest(BaseModel):
    keyId: str
    publicKey: str


def _roles_from_rows(rows):
    """Split a role snapshot into active roles, retired (unrevoked) and revoked.

    Revocation is orthogonal to roles. A revoked candidate has already been
    moved to the 'retired' role by revoke_key and surfaces in `revoked`; a
    revoked current/retiring key keeps its role (so rotation keeps working)
    and appears in both `roles` and `revoked`.
    """
    roles = {role: None for role in _ACTIVE_ROLES}
    retired = []
    revoked = []
    for row in rows:
        revoked_at = row["revoked_at"]
        if revoked_at is not None:
            revoked.append({"keyId": row["key_id"], "revokedAt": revoked_at.isoformat()})
        if row["role"] == "retired":
            if revoked_at is None:
                retired.append(row["key_id"])
        else:
            roles[row["role"]] = row["key_id"]
    revoked.sort(key=lambda item: (item["revokedAt"], item["keyId"]))
    return roles, retired, revoked


async def _fetch_roles(conn, tenant_id: str):
    rows = await conn.fetch(
        "SELECT k.key_id, k.role, r.revoked_at"
        " FROM tenant_keys k"
        " LEFT JOIN key_revocations r"
        "   ON r.tenant_id = k.tenant_id AND r.key_id = k.key_id"
        " WHERE k.tenant_id = $1"
        " ORDER BY k.created_at, k.key_id",
        tenant_id,
    )
    return _roles_from_rows(rows)


async def _lock_tenant(conn, tenant_id: str) -> None:
    # Serialize every key-state transition for this tenant within the
    # transaction; the partial unique indexes are the backstop.
    await conn.execute(
        "SELECT pg_advisory_xact_lock(hashtext('tenant_keys'), hashtext($1))",
        tenant_id,
    )


def _check_ids(tenant_id: str, key_id: str | None = None) -> None:
    if not _ID_RE.fullmatch(tenant_id):
        raise ApiError(400, "BAD_REQUEST", field="tenantId")
    if key_id is not None and not _ID_RE.fullmatch(key_id):
        raise ApiError(400, "BAD_REQUEST", field="keyId")


@router.post("/tenants/{tenant_id}/keys", status_code=201)
async def register_key(
    tenant_id: str,
    body: RegisterKeyRequest,
    _: None = Depends(require("keys:manage")),
):
    """First key becomes current; a second becomes candidate; anything else
    while a candidate or retiring key exists is an illegal transition."""
    _check_ids(tenant_id, body.keyId)
    public_key = b64url_decode_unpadded(body.publicKey, error_code="BAD_PUBLIC_KEY")
    if len(public_key) != 32:
        raise ApiError(400, "BAD_PUBLIC_KEY", detail="Ed25519 public keys must be 32 bytes")

    try:
        async with db.pool.acquire() as conn:
            async with conn.transaction():
                await _lock_tenant(conn, tenant_id)
                rows = await conn.fetch(
                    "SELECT k.key_id, k.role, r.revoked_at"
                    " FROM tenant_keys k"
                    " LEFT JOIN key_revocations r"
                    "   ON r.tenant_id = k.tenant_id AND r.key_id = k.key_id"
                    " WHERE k.tenant_id = $1 FOR UPDATE OF k",
                    tenant_id,
                )
                roles, _, _ = _roles_from_rows(rows)
                if any(row["key_id"] == body.keyId for row in rows):
                    raise ApiError(409, "KEY_ALREADY_EXISTS", roles=roles)
                if not rows:
                    role = "current"
                elif roles["candidate"] is None and roles["retiring"] is None:
                    role = "candidate"
                else:
                    raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)
                await conn.execute(
                    "INSERT INTO tenant_keys (tenant_id, key_id, role, public_key)"
                    " VALUES ($1, $2, $3, $4)",
                    tenant_id, body.keyId, role, public_key,
                )
                if role == "current":
                    # A tenant with a first key starts at key generation 0;
                    # every successful promote advances it.
                    await conn.execute(
                        "INSERT INTO tenant_state (tenant_id, key_generation)"
                        " VALUES ($1, 0) ON CONFLICT (tenant_id) DO NOTHING",
                        tenant_id,
                    )
                roles[role] = body.keyId
                return {"tenantId": tenant_id, "keyId": body.keyId, "role": role, "roles": roles}
    except asyncpg.UniqueViolationError:
        # Lost a race against a concurrent transition; answer with the
        # authoritative roles so the caller can resync.
        async with db.pool.acquire() as conn:
            roles, _, _ = await _fetch_roles(conn, tenant_id)
        raise ApiError(409, "KEY_ALREADY_EXISTS", roles=roles) from None


@router.post("/tenants/{tenant_id}/keys/promote")
async def promote_key(tenant_id: str, _: None = Depends(require("keys:manage"))):
    """Atomically: candidate -> current, old current -> retiring.

    Tenants with the pre-promotion proof-of-possession policy enabled must
    hold a valid, unconsumed proof for the current candidate; the proof is
    consumed within this same transaction, immediately before the role swap.
    """
    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            roles, _, revoked = await _fetch_roles(conn, tenant_id)
            if roles["candidate"] is None or roles["retiring"] is not None:
                raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)
            # Defense in depth: a revoked candidate is moved out of the seat by
            # revoke_key, so it cannot be selected; refuse any stale candidate
            # row carrying a revocation record as well.
            revoked_ids = {item["keyId"] for item in revoked}
            if roles["candidate"] in revoked_ids:
                raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)

            # Raises with authoritative roles and a precise code when the
            # tenant requires a proof that is missing/expired/consumed/stale;
            # on success the proof is consumed by this transaction.
            await consume_proof(conn, tenant_id, roles)

            # Order matters: the partial unique indexes admit only one row per
            # role, so the old current must move out first.
            await conn.execute(
                "UPDATE tenant_keys SET role = 'retiring', updated_at = now()"
                " WHERE tenant_id = $1 AND role = 'current'",
                tenant_id,
            )
            await conn.execute(
                "UPDATE tenant_keys SET role = 'current', updated_at = now()"
                " WHERE tenant_id = $1 AND role = 'candidate'",
                tenant_id,
            )
            generation = await conn.fetchval(
                "UPDATE tenant_state SET key_generation = key_generation + 1"
                " WHERE tenant_id = $1 RETURNING key_generation",
                tenant_id,
            )
            roles["retiring"] = roles["current"]
            roles["current"] = roles["candidate"]
            roles["candidate"] = None
            return {
                "tenantId": tenant_id,
                "roles": roles,
                "keyGeneration": generation,
            }


@router.post("/tenants/{tenant_id}/keys/retire")
async def retire_key(tenant_id: str, _: None = Depends(require("keys:manage"))):
    """Retiring -> retired (irreversible).

    Works unchanged when the retiring key was revoked: retirement only releases
    the retiring seat; the key already answers as KEY_REVOKED while in it.
    """
    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            roles, _, _ = await _fetch_roles(conn, tenant_id)
            if roles["retiring"] is None:
                raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)
            await conn.execute(
                "UPDATE tenant_keys SET role = 'retired', updated_at = now()"
                " WHERE tenant_id = $1 AND role = 'retiring'",
                tenant_id,
            )
            roles, retired, revoked = await _fetch_roles(conn, tenant_id)
            return {
                "tenantId": tenant_id,
                "roles": roles,
                "retired": retired,
                "revoked": revoked,
            }


@router.post("/tenants/{tenant_id}/keys/{key_id}/revoke", status_code=200)
async def revoke_key(
    tenant_id: str,
    key_id: str,
    _: None = Depends(require("keys:manage")),
):
    """Irreversibly revoke one tenant key and persist the revocation time.

    Revocation is independent of the current/candidate/retiring/retired roles:
    it is recorded as a key_revocations row that nothing ever deletes. A
    revoked candidate is immediately moved to 'retired' to release the
    candidate seat for a replacement registration. A revoked current or
    retiring key keeps its role, so the ordinary promote/retire rotation still
    replaces it. Repeated revocation of the same key is idempotent: the first
    revocation timestamp is the durable one.
    """
    _check_ids(tenant_id, key_id)
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            key_row = await conn.fetchrow(
                "SELECT role FROM tenant_keys WHERE tenant_id = $1 AND key_id = $2 FOR UPDATE",
                tenant_id,
                key_id,
            )
            if key_row is None:
                # Unknown key ids and other tenants' keys are indistinguishable.
                raise ApiError(404, "KEY_UNKNOWN")

            await conn.execute(
                "INSERT INTO key_revocations (tenant_id, key_id, revoked_at)"
                " VALUES ($1, $2, clock_timestamp())"
                " ON CONFLICT (tenant_id, key_id) DO NOTHING",
                tenant_id,
                key_id,
            )
            if key_row["role"] == "candidate":
                # Release the candidate seat so a replacement can be registered;
                # the key itself stays (now 'retired') with its revocation row.
                await conn.execute(
                    "UPDATE tenant_keys SET role = 'retired', updated_at = now()"
                    " WHERE tenant_id = $1 AND key_id = $2 AND role = 'candidate'",
                    tenant_id,
                    key_id,
                )
            roles, retired, revoked = await _fetch_roles(conn, tenant_id)
            return {
                "tenantId": tenant_id,
                "keyId": key_id,
                "revoked": True,
                "roles": roles,
                "retired": retired,
                "revocations": revoked,
            }


@router.get("/tenants/{tenant_id}/keys")
async def list_keys(tenant_id: str, _: None = Depends(require("keys:manage"))):
    """Authoritative role view for a tenant."""
    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        roles, retired, revoked = await _fetch_roles(conn, tenant_id)
    return {
        "tenantId": tenant_id,
        "roles": roles,
        "retired": retired,
        "revoked": revoked,
    }


@router.get("/tenants/{tenant_id}/receipts")
async def list_receipts(tenant_id: str, _: None = Depends(require("keys:manage"))):
    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        rows = await conn.fetch(
            "SELECT receipt_id::text AS receipt_id, key_id, body_size,"
            " encode(body_sha256, 'hex') AS sha256, created_at,"
            " 1 AS version, NULL::text AS message_id"
            " FROM receipts WHERE tenant_id = $1"
            " UNION ALL"
            " SELECT receipt_id::text AS receipt_id, key_id, body_size,"
            " encode(body_sha256, 'hex') AS sha256, created_at,"
            " 2 AS version, message_id"
            " FROM v2_receipts WHERE tenant_id = $1"
            " ORDER BY created_at, receipt_id",
            tenant_id,
        )
    return {
        "tenantId": tenant_id,
        "receipts": [
            {
                "receiptId": row["receipt_id"],
                "version": row["version"],
                "messageId": row["message_id"],
                "keyId": row["key_id"],
                "size": row["body_size"],
                "sha256": row["sha256"],
                "createdAt": row["created_at"].isoformat(),
            }
            for row in rows
        ],
    }
