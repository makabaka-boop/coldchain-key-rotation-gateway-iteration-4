"""Gateway message verification.

Two contracts share one endpoint:

* v1 (default): the Ed25519 signature covers the raw request body bytes only.
  Every accepted request produces an independent receipt.
* v2 (opt-in via ``X-Verify-Version: 2``): the signature covers a canonical
  message binding the protocol domain, tenant, key id, message id and a
  SHA-256 digest of the body. Within a tenant, a message id maps to exactly
  one immutable receipt; byte-identical retries return that receipt even after
  the signing key is retired, while reusing the id with another key or body is
  a conflict. Retired keys may never sign new v2 messages.
"""
import hashlib
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse

from . import db
from .auth import require
from .config import MAX_BODY_BYTES
from .errors import ApiError
from .keys import _ID_RE
from .util import b64url_decode_unpadded

router = APIRouter(tags=["verify"])

V2_DOMAIN = "coldchain-verify-v2"


async def _read_body(request: Request) -> bytes:
    """Read at most MAX_BODY_BYTES; anything larger is a 413."""
    content_length = request.headers.get("content-length")
    try:
        declared = int(content_length) if content_length is not None else None
    except ValueError:
        declared = None
    if declared is not None and declared > MAX_BODY_BYTES:
        raise ApiError(413, "PAYLOAD_TOO_LARGE", limit=MAX_BODY_BYTES)
    chunks: list[bytes] = []
    size = 0
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BODY_BYTES:
            raise ApiError(413, "PAYLOAD_TOO_LARGE", limit=MAX_BODY_BYTES)
        chunks.append(chunk)
    return b"".join(chunks)


def _verify_signature(public_key: bytes, signature: bytes, message: bytes) -> None:
    """Raise BAD_SIGNATURE unless `signature` is valid for `message`."""
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except InvalidSignature:
        raise ApiError(400, "BAD_SIGNATURE") from None


def v2_canonical_message(
    tenant_id: str, key_id: str, message_id: str, body: bytes
) -> bytes:
    """Exact bytes a v2 client must sign.

    The protocol domain keeps the string unusable on any other contract;
    tenant/key/message bind it to this context, and the body digest commits
    the signature to the request payload without signing up to 1 MiB.
    """
    digest_hex = hashlib.sha256(body).hexdigest()
    return (
        f"{V2_DOMAIN}\n"
        f"tenant={tenant_id}\n"
        f"key={key_id}\n"
        f"message={message_id}\n"
        f"body_sha256={digest_hex}"
    ).encode("ascii")


def _parse_headers(request: Request):
    tenant_id = request.headers.get("x-tenant-id")
    key_id = request.headers.get("x-key-id")
    signature_b64 = request.headers.get("x-signature")
    if not tenant_id or not key_id or not signature_b64:
        raise ApiError(
            400, "BAD_REQUEST",
            detail="X-Tenant-Id, X-Key-Id and X-Signature headers are required",
        )

    version_header = request.headers.get("x-verify-version")
    if version_header is None or version_header.strip() == "1":
        version = 1
    elif version_header.strip() == "2":
        version = 2
    else:
        raise ApiError(400, "BAD_REQUEST", field="X-Verify-Version")

    message_id = request.headers.get("x-message-id")
    if version == 2:
        if not message_id or not _ID_RE.fullmatch(message_id):
            raise ApiError(400, "BAD_REQUEST", field="X-Message-Id")
    return version, tenant_id, key_id, signature_b64, message_id


async def _verify_v1(conn, tenant_id: str, key_id: str, signature: bytes, body: bytes) -> str:
    # The role read is the ordering point against a concurrent retire: a
    # snapshot taken before the retire commits may still verify; one taken
    # after observes 'retired' and fails with KEY_RETIRED.
    row = await conn.fetchrow(
        "SELECT role, public_key FROM tenant_keys WHERE tenant_id = $1 AND key_id = $2",
        tenant_id, key_id,
    )
    if row is None:
        # Unknown key ids and other tenants' keys are indistinguishable.
        raise ApiError(404, "KEY_UNKNOWN")
    if row["role"] == "retired":
        raise ApiError(410, "KEY_RETIRED")
    _verify_signature(bytes(row["public_key"]), signature, body)

    receipt_id = uuid.uuid4()
    await conn.execute(
        "INSERT INTO receipts (receipt_id, tenant_id, key_id, body_sha256, body_size)"
        " VALUES ($1, $2, $3, $4, $5)",
        receipt_id, tenant_id, key_id, hashlib.sha256(body).digest(), len(body),
    )
    return str(receipt_id)


async def _verify_v2(
    conn, tenant_id: str, key_id: str, message_id: str, signature: bytes, body: bytes
) -> tuple[int, str]:
    """Return (status_code, receipt_id) for the v2 contract.

    All reads and the insert happen in one transaction: any error rolls the
    transaction back, so rejected requests never leave a placeholder row.
    """
    row = await conn.fetchrow(
        "SELECT role, public_key FROM tenant_keys WHERE tenant_id = $1 AND key_id = $2",
        tenant_id, key_id,
    )
    if row is None:
        # Unknown key ids and other tenants' keys are indistinguishable.
        raise ApiError(404, "KEY_UNKNOWN")

    # The signature is checked *before* any receipt state is consulted, so an
    # invalid signature is always BAD_SIGNATURE and the response cannot reveal
    # whether the message id already exists.
    canonical = v2_canonical_message(tenant_id, key_id, message_id, body)
    _verify_signature(bytes(row["public_key"]), signature, canonical)

    body_digest = hashlib.sha256(body).digest()

    existing = await conn.fetchrow(
        "SELECT receipt_id, key_id, body_sha256 FROM v2_receipts"
        " WHERE tenant_id = $1 AND message_id = $2",
        tenant_id, message_id,
    )
    if existing is not None:
        if existing["key_id"] == key_id and bytes(existing["body_sha256"]) == body_digest:
            # Exact retry (same key, same body): the original receipt is
            # authoritative even when the key has since been retired.
            return 200, str(existing["receipt_id"])
        # Same id, different content or key: answer generically so the stored
        # receipt's contents are not disclosed.
        raise ApiError(409, "MESSAGE_CONFLICT", messageId=message_id)

    # The id is still free: a retired key may not open a new message.
    if row["role"] == "retired":
        raise ApiError(410, "KEY_RETIRED")

    receipt_id = uuid.uuid4()
    inserted = await conn.fetchval(
        "INSERT INTO v2_receipts (receipt_id, tenant_id, message_id, key_id,"
        " body_sha256, body_size)"
        " VALUES ($1, $2, $3, $4, $5, $6)"
        " ON CONFLICT (tenant_id, message_id) DO NOTHING"
        " RETURNING receipt_id",
        receipt_id, tenant_id, message_id, key_id, body_digest, len(body),
    )
    if inserted is not None:
        return 202, str(receipt_id)

    # Lost the race against a concurrent instance: its row is now the
    # authority; decide exact retry versus conflict against it.
    winner = await conn.fetchrow(
        "SELECT receipt_id, key_id, body_sha256 FROM v2_receipts"
        " WHERE tenant_id = $1 AND message_id = $2",
        tenant_id, message_id,
    )
    if (
        winner is not None
        and winner["key_id"] == key_id
        and bytes(winner["body_sha256"]) == body_digest
    ):
        return 200, str(winner["receipt_id"])
    raise ApiError(409, "MESSAGE_CONFLICT", messageId=message_id)


@router.post("/verify")
async def verify_message(request: Request, _: None = Depends(require("verify"))):
    version, tenant_id, key_id, signature_b64, message_id = _parse_headers(request)
    body = await _read_body(request)
    signature = b64url_decode_unpadded(signature_b64, error_code="BAD_SIGNATURE")
    if len(signature) != 64:
        raise ApiError(400, "BAD_SIGNATURE")

    async with db.pool.acquire() as conn:
        if version == 1:
            async with conn.transaction():
                receipt_id = await _verify_v1(
                    conn, tenant_id, key_id, signature, body
                )
            return JSONResponse({"receiptId": receipt_id}, status_code=202)

        async with conn.transaction():
            status_code, receipt_id = await _verify_v2(
                conn, tenant_id, key_id, message_id, signature, body
            )
        response = {"receiptId": receipt_id}
        if status_code == 200:
            response["duplicate"] = True
        return JSONResponse(response, status_code=status_code)
