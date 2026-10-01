"""Acceptance tests for the opt-in v2 verification contract.

v2 binds protocol domain, tenant, key id, message id and body digest into the
signature and makes (tenant, message id) an immutable, single receipt. These
tests run against the real API over HTTP; the dual-instance races hit two
independent uvicorn processes sharing one PostgreSQL database.
"""
import asyncio
import hashlib
import os

import pytest

from conftest import (
    promote,
    register_key,
    retire,
    submit,
    submit_v2,
    v2_sign,
)


def _receipts(admin_client, tenant_id):
    resp = admin_client.get(f"/v1/tenants/{tenant_id}/receipts")
    assert resp.status_code == 200, resp.text
    return resp.json()["receipts"]


def _v2_receipts(admin_client, tenant_id):
    return [r for r in _receipts(admin_client, tenant_id) if r["version"] == 2]


def _send(admin_client, gateway_client, tenant_id, key, message_id, body):
    sig = v2_sign(key, tenant_id, key.key_id, message_id, body)
    resp = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig, body)
    assert resp.status_code == 202, resp.text
    receipt_id = resp.json()["receiptId"]
    receipts = _v2_receipts(admin_client, tenant_id)
    assert len(receipts) == 1
    assert receipts[0]["receiptId"] == receipt_id
    assert receipts[0]["messageId"] == message_id
    assert receipts[0]["keyId"] == key.key_id
    assert receipts[0]["sha256"] == hashlib.sha256(body).hexdigest()
    return receipt_id


def test_v2_first_acceptance_creates_one_immutable_receipt(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = "msg-0001"
    body = b"temperature=-18.5;door=closed"
    _send(admin_client, gateway_client, tenant_id, key, message_id, body)


def test_v2_exact_retry_returns_the_original_receipt(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id, body = "msg-retry", b"reading-A"
    first_id = _send(admin_client, gateway_client, tenant_id, key, message_id, body)

    # Same id, same body, freshly recomputed signature: an exact retry.
    resp = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["receiptId"] == first_id
    assert resp.json()["duplicate"] is True
    # Still exactly one receipt.
    assert len(_v2_receipts(admin_client, tenant_id)) == 1


def test_v2_retry_still_returns_original_receipt_after_key_retirement(
    admin_client, gateway_client, tenant_id, make_key
):
    old, new = make_key(), make_key()
    register_key(admin_client, tenant_id, old)
    register_key(admin_client, tenant_id, new)
    promote(admin_client, tenant_id)
    message_id, body = "msg-before-retire", b"reading-B"
    first_id = _send(admin_client, gateway_client, tenant_id, old, message_id, body)

    retire(admin_client, tenant_id)
    # A new message with the retired key is refused...
    resp = submit_v2(
        gateway_client, tenant_id, old.key_id, "msg-new-after-retire",
        v2_sign(key=old, tenant_id=tenant_id, key_id=old.key_id,
                message_id="msg-new-after-retire", body=body),
        body,
    )
    assert resp.status_code == 410
    assert resp.json()["error"] == "KEY_RETIRED"

    # ...but the exact retry of the already-accepted message returns its
    # original receipt even though the key is now retired.
    retry = submit_v2(
        gateway_client, tenant_id, old.key_id, message_id,
        v2_sign(key=old, tenant_id=tenant_id, key_id=old.key_id,
                message_id=message_id, body=body),
        body,
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["receiptId"] == first_id
    assert len(_v2_receipts(admin_client, tenant_id)) == 1


def test_v2_same_id_different_body_is_conflict(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = "msg-conflict-body"
    body_a, body_b = b"payload-A", b"payload-B-different"
    _send(admin_client, gateway_client, tenant_id, key, message_id, body_a)

    resp = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body_b), body_b,
    )
    assert resp.status_code == 409, resp.text
    # The conflict response must not leak the stored content/key.
    assert resp.json() == {"error": "MESSAGE_CONFLICT", "messageId": message_id}
    # The original receipt is untouched and no second receipt exists.
    receipts = _v2_receipts(admin_client, tenant_id)
    assert len(receipts) == 1
    assert receipts[0]["sha256"] == hashlib.sha256(body_a).hexdigest()

    # The connection/transaction failure must not poison later requests.
    followup = submit_v2(
        gateway_client, tenant_id, key.key_id, "msg-after-conflict",
        v2_sign(key, tenant_id, key.key_id, "msg-after-conflict", body_a), body_a,
    )
    assert followup.status_code == 202, followup.text


def test_v2_same_id_different_key_is_conflict_and_blocks_rotation_bypass(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    message_id, body = "msg-conflict-key", b"payload-C"
    _send(admin_client, gateway_client, tenant_id, k1, message_id, body)

    # Rotation must not make the message id reusable under the new key.
    promote(admin_client, tenant_id)
    resp = submit_v2(
        gateway_client, tenant_id, k2.key_id, message_id,
        v2_sign(k2, tenant_id, k2.key_id, message_id, body), body,
    )
    assert resp.status_code == 409, resp.text
    assert resp.json() == {"error": "MESSAGE_CONFLICT", "messageId": message_id}
    assert len(_v2_receipts(admin_client, tenant_id)) == 1

    # Retired key: after full retirement the old key cannot sign a new id.
    retire(admin_client, tenant_id)
    new_msg = submit_v2(
        gateway_client, tenant_id, k1.key_id, "msg-fresh-on-retired",
        v2_sign(k1, tenant_id, k1.key_id, "msg-fresh-on-retired", body), body,
    )
    assert new_msg.status_code == 410
    assert new_msg.json()["error"] == "KEY_RETIRED"
    assert _v2_receipts(admin_client, tenant_id) == _v2_receipts(
        admin_client, tenant_id
    ) and len(_v2_receipts(admin_client, tenant_id)) == 1


def test_v2_bad_signature_is_rejected_without_a_receipt_or_leak(
    admin_client, gateway_client, tenant_id, make_key
):
    key, other = make_key(), make_key()
    register_key(admin_client, tenant_id, key)
    message_id, body = "msg-bad-sig", b"payload-D"

    # Forged signature (well-formed, wrong private key): BAD_SIGNATURE and no
    # placeholder row.
    forged = v2_sign(other, tenant_id, key.key_id, message_id, body)
    resp = submit_v2(gateway_client, tenant_id, key.key_id, message_id, forged, body)
    assert resp.status_code == 400
    assert resp.json() == {"error": "BAD_SIGNATURE"}
    assert _v2_receipts(admin_client, tenant_id) == []

    # A valid v1 raw-body signature is not a valid v2 signature (domain
    # separation): the message id must not become occupied, so the genuine v2
    # request immediately afterwards still succeeds.
    resp = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id, key.sign(body), body
    )
    assert resp.status_code == 400
    assert resp.json() == {"error": "BAD_SIGNATURE"}
    assert _v2_receipts(admin_client, tenant_id) == []

    good = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    )
    assert good.status_code == 202, good.text

    # An invalid signature against an already-existing id is still BAD_SIGNATURE
    # (signature is checked before receipt lookup, so existence is not leaked).
    resp = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id, forged, body
    )
    assert resp.status_code == 400
    assert resp.json() == {"error": "BAD_SIGNATURE"}
    assert len(_v2_receipts(admin_client, tenant_id)) == 1


def test_v2_cross_tenant_message_ids_are_isolated(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    other_tenant = tenant_id + "-other"
    register_key(admin_client, other_tenant, key)  # same key id string, same pubkey
    message_id, body = "shared-id", b"payload-E"

    first = _send(admin_client, gateway_client, tenant_id, key, message_id, body)
    second = submit_v2(
        gateway_client, other_tenant, key.key_id, message_id,
        v2_sign(key, other_tenant, key.key_id, message_id, body), body,
    )
    assert second.status_code == 202, second.text
    assert second.json()["receiptId"] != first
    assert len(_v2_receipts(admin_client, tenant_id)) == 1
    assert len(_v2_receipts(admin_client, other_tenant)) == 1

    # The signature binds the tenant: a signature made for tenant A cannot be
    # replayed under tenant B even with the same key and message id.
    replay = submit_v2(
        gateway_client, other_tenant, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    )
    assert replay.status_code == 400
    assert replay.json()["error"] == "BAD_SIGNATURE"


def test_v2_requires_message_id_and_known_version(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"payload-F"

    # v2 without X-Message-Id.
    resp = gateway_client.post(
        "/v1/verify", content=body,
        headers={
            "X-Verify-Version": "2",
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": key.key_id,
            "X-Signature": v2_sign(key, tenant_id, key.key_id, "m", body),
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_REQUEST"
    assert _v2_receipts(admin_client, tenant_id) == []

    # Unsupported version value.
    resp = gateway_client.post(
        "/v1/verify", content=body,
        headers={
            "X-Verify-Version": "3",
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": key.key_id,
            "X-Message-Id": "m",
            "X-Signature": v2_sign(key, tenant_id, key.key_id, "m", body),
        },
    )
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_REQUEST"


def test_v1_contract_is_unchanged_alongside_v2(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"v1-payload"

    # No version header: raw-body signature, independent receipts per request.
    r1 = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    r2 = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert r1.status_code == r2.status_code == 202
    assert r1.json()["receiptId"] != r2.json()["receiptId"]
    v1_receipts = [r for r in _receipts(admin_client, tenant_id) if r["version"] == 1]
    assert len(v1_receipts) == 2

    # Explicit X-Verify-Version: 1 is the v1 contract as well.
    explicit = gateway_client.post(
        "/v1/verify", content=body,
        headers={
            "X-Verify-Version": "1",
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": key.key_id,
            "X-Signature": key.sign(body),
        },
    )
    assert explicit.status_code == 202


def test_v2_unknown_and_cross_tenant_key_are_indistinguishable(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"payload-G"
    sig = v2_sign(key, tenant_id, key.key_id, "m", body)
    cross = submit_v2(gateway_client, tenant_id + "-x", key.key_id, "m", sig, body)
    unknown = submit_v2(gateway_client, tenant_id, "no-such-key", "m", sig, body)
    assert cross.status_code == unknown.status_code == 404
    assert cross.json() == unknown.json() == {"error": "KEY_UNKNOWN"}
    assert _v2_receipts(admin_client, tenant_id) == []


def _concurrent_pair(headers_a, body_a, headers_b, body_b):
    """Fire two verify requests truly concurrently against both instances."""
    import httpx

    from conftest import BASE2_URL, BASE_URL

    async def _go():
        async with httpx.AsyncClient(timeout=30.0) as client:
            return await asyncio.gather(
                client.post(f"{BASE_URL}/v1/verify", content=body_a, headers=headers_a),
                client.post(f"{BASE2_URL}/v1/verify", content=body_b, headers=headers_b),
            )

    return asyncio.run(_go())


def test_v2_two_instances_fire_identical_requests_concurrently_single_receipt(
    admin_client, gateway_client, gateway_client2, tenant_id, make_key
):
    """Two service instances receive the exact same request at the same time;
    the database unique constraint plus transactional arbitration must leave
    exactly one receipt, with one 202 and one 200 carrying the same id."""
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"payload-H"

    # Repeat several rounds to give the race real chances of interleaving.
    for round_id in range(5):
        mid = f"msg-race-exact-{round_id}"
        sig = v2_sign(key, tenant_id, key.key_id, mid, body)
        h1 = {
            "X-Verify-Version": "2",
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": key.key_id,
            "X-Message-Id": mid,
            "X-Signature": sig,
            **gateway_client.headers,
        }
        h2 = {**h1, **gateway_client2.headers}
        results = _concurrent_pair(h1, body, h2, body)
        statuses = sorted(r.status_code for r in results)
        assert statuses == [200, 202], [(r.status_code, r.text) for r in results]
        ids = {r.json()["receiptId"] for r in results}
        assert len(ids) == 1

    receipts = _v2_receipts(admin_client, tenant_id)
    assert len(receipts) == 5


def test_v2_concurrent_conflicting_bodies_single_receipt_and_conflict(
    admin_client, gateway_client, gateway_client2, tenant_id, make_key
):
    """Concurrent instances racing the same id with *different* bodies: one
    commits a receipt, the other gets MESSAGE_CONFLICT; never two receipts."""
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id = "msg-race-conflict"
    body_a, body_b = b"payload-I", b"payload-I-different"
    headers_a = {
        "X-Verify-Version": "2",
        "X-Tenant-Id": tenant_id,
        "X-Key-Id": key.key_id,
        "X-Message-Id": message_id,
        "X-Signature": v2_sign(key, tenant_id, key.key_id, message_id, body_a),
        **gateway_client.headers,
    }
    headers_b = {
        "X-Verify-Version": "2",
        "X-Tenant-Id": tenant_id,
        "X-Key-Id": key.key_id,
        "X-Message-Id": message_id,
        "X-Signature": v2_sign(key, tenant_id, key.key_id, message_id, body_b),
        **gateway_client2.headers,
    }
    results = _concurrent_pair(headers_a, body_a, headers_b, body_b)
    assert sorted(r.status_code for r in results) == [202, 409], [
        (r.status_code, r.text) for r in results
    ]
    conflict = next(r for r in results if r.status_code == 409)
    assert conflict.json() == {"error": "MESSAGE_CONFLICT", "messageId": message_id}
    receipts = _v2_receipts(admin_client, tenant_id)
    assert len(receipts) == 1
    assert receipts[0]["sha256"] in (
        hashlib.sha256(body_a).hexdigest(),
        hashlib.sha256(body_b).hexdigest(),
    )


def test_v2_database_unique_constraint_is_the_backstop(tenant_id):
    """Against the real database: the partial (tenant, message id) uniqueness
    exists and rejects a second insert even if an application bug tried one."""
    import asyncpg

    dsn = os.environ.get(
        "DATABASE_URL", "postgresql://coldchain:coldchain@localhost:5432/coldchain"
    )
    asyncio.run(_db_check(dsn, tenant_id))


async def _db_check(dsn, tenant_id):
    import asyncpg
    import uuid

    conn = await asyncpg.connect(dsn)
    try:
        count = await conn.fetchval(
            "SELECT count(*) FROM pg_constraint"
            " WHERE conname = 'v2_receipts_one_per_message'"
        )
        assert count == 1
        mid = "db-backstop-" + uuid.uuid4().hex
        await conn.execute(
            "INSERT INTO v2_receipts (receipt_id, tenant_id, message_id, key_id,"
            " body_sha256, body_size)"
            " VALUES ($1, $2, $3, 'k', $4, 1)",
            uuid.uuid4(), tenant_id, mid, b"\x00" * 32,
        )
        with pytest.raises(asyncpg.UniqueViolationError):
            await conn.execute(
                "INSERT INTO v2_receipts (receipt_id, tenant_id, message_id, key_id,"
                " body_sha256, body_size)"
                " VALUES ($1, $2, $3, 'k2', $4, 1)",
                uuid.uuid4(), tenant_id, mid, b"\x11" * 32,
            )
        # A different tenant can hold the same message id.
        await conn.execute(
            "INSERT INTO v2_receipts (receipt_id, tenant_id, message_id, key_id,"
            " body_sha256, body_size)"
            " VALUES ($1, $2, $3, 'k', $4, 1)",
            uuid.uuid4(), tenant_id + "-other", mid, b"\x00" * 32,
        )
    finally:
        await conn.close()
