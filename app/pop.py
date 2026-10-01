"""Pre-promotion proof-of-possession: tenant policy, challenges and proofs."""
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends
from pydantic import BaseModel

from . import db
from .auth import require
from .errors import ApiError
from .util import b64url_decode_unpadded, b64url_encode

router = APIRouter(tags=["proof-of-possession"])


class PolicyRequest(BaseModel):
    popRequired: bool
    challengeTtlSeconds: int | None = None


class ChallengeProofRequest(BaseModel):
    signature: str


def canonical_message(
    tenant_id: str,
    candidate_key_id: str,
    current_key_id: str,
    current_generation: int,
    challenge_id: str,
    nonce: bytes,
) -> bytes:
    """Exact bytes the candidate private key must sign.

    Every contextual value is included so a signature cannot be moved across
    tenants, key ids, generations or challenges.
    """
    return (
        b"coldchain-pop-v1"
        + f"\ntenant={tenant_id}".encode()
        + f"\ncandidate={candidate_key_id}".encode()
        + f"\ncurrent={current_key_id}".encode()
        + f"\ngeneration={current_generation}".encode()
        + f"\nchallenge={challenge_id}".encode()
        + b"\nnonce="
        + b64url_encode(nonce).encode("ascii")
    )


def _is_expired(expires_at, now) -> bool:
    return now >= expires_at


async def _expire_open_challenges(conn, tenant_id: str) -> None:
    """Flip every still-open challenge past its deadline to 'expired'."""
    await conn.execute(
        f"UPDATE pop_challenges SET status = 'expired'"
        f" WHERE tenant_id = $1 AND status IN ('issued', 'answered')"
        f" AND expires_at <= {db.VIRTUAL_NOW_SQL}",
        tenant_id,
    )


def _challenge_view(row, now) -> dict:
    status = row["status"]
    if status in ("issued", "answered") and _is_expired(row["expires_at"], now):
        status = "expired"
    return {
        "challengeId": str(row["challenge_id"]),
        "candidateKeyId": row["candidate_key_id"],
        "currentKeyId": row["current_key_id"],
        "currentGeneration": row["current_generation"],
        "nonce": b64url_encode(bytes(row["nonce"])),
        "status": status,
        "ttlSeconds": row["ttl_seconds"],
        "issuedAt": row["issued_at"].isoformat(),
        "expiresAt": row["expires_at"].isoformat(),
        "answeredAt": row["answered_at"].isoformat() if row["answered_at"] else None,
        "consumedAt": row["consumed_at"].isoformat() if row["consumed_at"] else None,
    }


async def _policy_row(conn, tenant_id: str):
    return await conn.fetchrow(
        "SELECT pop_required, challenge_ttl FROM tenant_policies WHERE tenant_id = $1",
        tenant_id,
    )


async def consume_proof(conn, tenant_id: str, roles: dict):
    """Inside the promote transaction: validate and atomically consume a proof.

    Returns nothing on success (the caller performs the role swap afterwards);
    raises ApiError with the authoritative roles and a precise code otherwise.
    Key roles are never modified on failure.
    """
    policy = await _policy_row(conn, tenant_id)
    if policy is None or not policy["pop_required"]:
        return  # legacy tenant: promotion keeps its original behaviour

    candidate_id = roles["candidate"]
    current_id = roles["current"]
    now = await conn.fetchval(f"SELECT {db.VIRTUAL_NOW_SQL}")

    # Short-circuit every open challenge that has passed its deadline.
    await _expire_open_challenges(conn, tenant_id)

    # Exactly one open (issued/answered) challenge can exist per
    # tenant+candidate, and every answered proof whose context no longer
    # matches was already short-circuited at answer time.
    proof = await conn.fetchrow(
        "SELECT * FROM pop_challenges"
        " WHERE tenant_id = $1 AND candidate_key_id = $2 AND status = 'answered'"
        " FOR UPDATE",
        tenant_id,
        candidate_id,
    )
    if proof is not None and not _is_expired(proof["expires_at"], now):
        if proof["current_key_id"] != current_id:
            raise ApiError(409, "POP_PROOF_MISMATCH", roles=roles)
        gen = await conn.fetchval(
            "SELECT key_generation FROM tenant_state WHERE tenant_id = $1",
            tenant_id,
        )
        if gen != proof["current_generation"]:
            raise ApiError(409, "POP_PROOF_MISMATCH", roles=roles)
        consumed = await conn.fetchrow(
            f"UPDATE pop_challenges SET status = 'consumed', consumed_at = {db.VIRTUAL_NOW_SQL}"
            " WHERE challenge_id = $1 AND tenant_id = $2 AND status = 'answered'"
            " RETURNING challenge_id",
            proof["challenge_id"],
            tenant_id,
        )
        if consumed is None:  # concurrent consumption: proof no longer valid
            raise ApiError(409, "POP_PROOF_CONSUMED", roles=roles)
        return

    # No usable proof: report the most specific reason.
    prior = await conn.fetchrow(
        "SELECT status, expires_at FROM pop_challenges"
        " WHERE tenant_id = $1 AND candidate_key_id = $2"
        " ORDER BY issued_at DESC, challenge_id DESC LIMIT 1",
        tenant_id,
        candidate_id,
    )
    if prior is not None and prior["status"] == "consumed":
        raise ApiError(409, "POP_PROOF_CONSUMED", roles=roles)
    if prior is not None and _is_expired(prior["expires_at"], now):
        raise ApiError(410, "POP_PROOF_EXPIRED", roles=roles)
    raise ApiError(409, "POP_PROOF_REQUIRED", roles=roles)


@router.get("/tenants/{tenant_id}/policy")
async def get_policy(tenant_id: str, _: None = Depends(require("keys:manage"))):
    from .keys import _check_ids

    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        row = await _policy_row(conn, tenant_id)
    if row is None:
        return {
            "tenantId": tenant_id,
            "popRequired": False,
            "challengeTtlSeconds": db.default_challenge_ttl(),
        }
    return {
        "tenantId": tenant_id,
        "popRequired": row["pop_required"],
        "challengeTtlSeconds": row["challenge_ttl"],
    }


@router.put("/tenants/{tenant_id}/policy", status_code=200)
async def put_policy(
    tenant_id: str,
    body: PolicyRequest,
    _: None = Depends(require("keys:manage")),
):
    from .keys import _check_ids, _lock_tenant

    _check_ids(tenant_id)
    ttl = body.challengeTtlSeconds
    if ttl is not None and not (1 <= ttl <= 86400):
        raise ApiError(400, "BAD_REQUEST", field="challengeTtlSeconds")
    ttl = ttl or db.default_challenge_ttl()

    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            await conn.execute(
                "INSERT INTO tenant_policies (tenant_id, pop_required, challenge_ttl, updated_at)"
                f" VALUES ($1, $2, $3, {db.VIRTUAL_NOW_SQL})"
                " ON CONFLICT (tenant_id) DO UPDATE"
                " SET pop_required = EXCLUDED.pop_required,"
                "     challenge_ttl = EXCLUDED.challenge_ttl,"
                "     updated_at = EXCLUDED.updated_at",
                tenant_id,
                body.popRequired,
                ttl,
            )
            # Outstanding challenges are intentionally left in place while the
            # policy is off: they can neither be answered nor consumed then. On
            # re-enable, one whose tenant/candidate/current/generation still
            # matches remains valid; one whose context moved is rejected with
            # POP_PROOF_MISMATCH at answer time.
    return {"tenantId": tenant_id, "popRequired": body.popRequired, "challengeTtlSeconds": ttl}


@router.post("/tenants/{tenant_id}/pop-challenges", status_code=201)
async def issue_challenge(tenant_id: str, _: None = Depends(require("keys:manage"))):
    """Mint a one-time challenge for the current candidate key."""
    from .keys import _check_ids, _fetch_roles, _lock_tenant

    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            policy = await _policy_row(conn, tenant_id)
            if policy is None or not policy["pop_required"]:
                raise ApiError(409, "POP_POLICY_DISABLED")

            roles, _ = await _fetch_roles(conn, tenant_id)
            if roles["candidate"] is None:
                raise ApiError(409, "ILLEGAL_TRANSITION", roles=roles)

            await _expire_open_challenges(conn, tenant_id)
            existing = await conn.fetchrow(
                "SELECT * FROM pop_challenges"
                " WHERE tenant_id = $1 AND candidate_key_id = $2"
                " AND status IN ('issued', 'answered') FOR UPDATE",
                tenant_id,
                roles["candidate"],
            )
            now = await conn.fetchval(f"SELECT {db.VIRTUAL_NOW_SQL}")
            if existing is not None and not _is_expired(existing["expires_at"], now):
                return _challenge_view(existing, now)  # idempotent re-request

            # Ensure the tenant has a generation row (0 for its first key).
            await conn.execute(
                "INSERT INTO tenant_state (tenant_id, key_generation) VALUES ($1, 0)"
                " ON CONFLICT (tenant_id) DO NOTHING",
                tenant_id,
            )
            generation = await conn.fetchval(
                "SELECT key_generation FROM tenant_state WHERE tenant_id = $1",
                tenant_id,
            )

            challenge_id = uuid.uuid4()
            nonce = uuid.uuid4().bytes
            ttl = policy["challenge_ttl"]
            row = await conn.fetchrow(
                f"INSERT INTO pop_challenges (challenge_id, tenant_id, candidate_key_id,"
                f" current_key_id, current_generation, nonce, status, ttl_seconds,"
                f" issued_at, expires_at)"
                f" VALUES ($1, $2, $3, $4, $5, $6, 'issued', $7, {db.VIRTUAL_NOW_SQL},"
                f" {db.VIRTUAL_NOW_SQL} + make_interval(secs => $7::integer))"
                " RETURNING *",
                challenge_id,
                tenant_id,
                roles["candidate"],
                roles["current"],
                generation,
                nonce,
                ttl,
            )
            return _challenge_view(row, row["issued_at"])


@router.post("/tenants/{tenant_id}/pop-challenges/{challenge_id}/answer", status_code=200)
async def answer_challenge(
    tenant_id: str,
    challenge_id: str,
    body: ChallengeProofRequest,
    _: None = Depends(require("keys:manage")),
):
    """Register a time-limited proof: verify the candidate's signature."""
    from .keys import _check_ids, _fetch_roles, _lock_tenant

    _check_ids(tenant_id)
    try:
        parsed_id = uuid.UUID(challenge_id)
    except ValueError:
        raise ApiError(404, "POP_CHALLENGE_NOT_FOUND") from None
    signature = b64url_decode_unpadded(body.signature, error_code="BAD_SIGNATURE")
    if len(signature) != 64:
        raise ApiError(400, "BAD_SIGNATURE")

    async with db.pool.acquire() as conn:
        async with conn.transaction():
            await _lock_tenant(conn, tenant_id)
            policy = await _policy_row(conn, tenant_id)
            if policy is None or not policy["pop_required"]:
                raise ApiError(409, "POP_POLICY_DISABLED")

            row = await conn.fetchrow(
                "SELECT * FROM pop_challenges"
                " WHERE tenant_id = $1 AND challenge_id = $2 FOR UPDATE",
                tenant_id,
                parsed_id,
            )
            if row is None:
                # Other tenants' challenges are indistinguishable from unknown.
                raise ApiError(404, "POP_CHALLENGE_NOT_FOUND")

            now = await conn.fetchval(f"SELECT {db.VIRTUAL_NOW_SQL}")
            if row["status"] == "expired":
                raise ApiError(410, "POP_CHALLENGE_EXPIRED", challengeId=challenge_id)
            if _is_expired(row["expires_at"], now):
                await conn.execute(
                    "UPDATE pop_challenges SET status = 'expired'"
                    " WHERE challenge_id = $1 AND tenant_id = $2",
                    parsed_id,
                    tenant_id,
                )
                terminal_error = ApiError(410, "POP_CHALLENGE_EXPIRED", challengeId=challenge_id)
                result = None
            elif row["status"] == "consumed":
                raise ApiError(409, "POP_PROOF_CONSUMED", challengeId=challenge_id)
            elif row["status"] == "answered":
                raise ApiError(409, "POP_PROOF_DUPLICATE", challengeId=challenge_id)
            else:
                roles, _ = await _fetch_roles(conn, tenant_id)
                context_ok = (
                    roles["candidate"] == row["candidate_key_id"]
                    and roles["current"] == row["current_key_id"]
                )
                generation = await conn.fetchval(
                    "SELECT key_generation FROM tenant_state WHERE tenant_id = $1",
                    tenant_id,
                )
                if not context_ok or generation != row["current_generation"]:
                    # Candidate/current moved: the proof can never be consumed.
                    await conn.execute(
                        "UPDATE pop_challenges SET status = 'expired'"
                        " WHERE challenge_id = $1 AND tenant_id = $2",
                        parsed_id,
                        tenant_id,
                    )
                    terminal_error = ApiError(
                        409, "POP_PROOF_MISMATCH", roles=roles, challengeId=challenge_id
                    )
                    result = None
                else:
                    key_row = await conn.fetchrow(
                        "SELECT public_key FROM tenant_keys"
                        " WHERE tenant_id = $1 AND key_id = $2 AND role = 'candidate'",
                        tenant_id,
                        row["candidate_key_id"],
                    )
                    if key_row is None:
                        raise ApiError(
                            409, "POP_PROOF_MISMATCH", roles=roles, challengeId=challenge_id
                        )

                    message = canonical_message(
                        tenant_id,
                        row["candidate_key_id"],
                        row["current_key_id"],
                        row["current_generation"],
                        str(row["challenge_id"]),
                        bytes(row["nonce"]),
                    )
                    try:
                        Ed25519PublicKey.from_public_bytes(
                            bytes(key_row["public_key"])
                        ).verify(signature, message)
                    except InvalidSignature:
                        # A bad signature does not consume or invalidate the
                        # challenge; rollback leaves its state untouched.
                        raise ApiError(400, "BAD_SIGNATURE") from None

                    updated = await conn.fetchrow(
                        f"UPDATE pop_challenges SET status = 'answered',"
                        f" answered_at = {db.VIRTUAL_NOW_SQL}"
                        " WHERE challenge_id = $1 AND tenant_id = $2 AND status = 'issued'"
                        " RETURNING *",
                        parsed_id,
                        tenant_id,
                    )
                    if updated is None:  # lost a concurrent answer
                        raise ApiError(409, "POP_PROOF_DUPLICATE", challengeId=challenge_id)
                    terminal_error = None
                    result = _challenge_view(updated, now)

    # The transaction has committed: raise only *after* any terminal status
    # change (expired / mismatch) is durably stored.
    if terminal_error is not None:
        raise terminal_error
    return result


@router.get("/tenants/{tenant_id}/pop-challenges")
async def list_challenges(tenant_id: str, _: None = Depends(require("keys:manage"))):
    from .keys import _check_ids

    _check_ids(tenant_id)
    async with db.pool.acquire() as conn:
        now = await conn.fetchval(f"SELECT {db.VIRTUAL_NOW_SQL}")
        rows = await conn.fetch(
            "SELECT * FROM pop_challenges WHERE tenant_id = $1"
            " ORDER BY issued_at, challenge_id",
            tenant_id,
        )
    return {
        "tenantId": tenant_id,
        "challenges": [_challenge_view(row, now) for row in rows],
    }
