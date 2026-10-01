"""Acceptance tests for irreversible per-tenant key revocation.

Revocation is orthogonal to the current/candidate/retiring/retired roles:
- a revoked candidate is not promotable and immediately releases its seat;
- a revoked current key keeps rotating out via the ordinary promote flow;
- after revocation the key's v1 requests and all v2 requests (new messages
  and byte-identical retries of messages accepted earlier) are refused with
  KEY_REVOKED, and no new receipt is created;
- receipts that predate the revocation stay queryable;
- invalid signatures cannot be used to probe message existence;
- revoke/verify interleavings on two instances are ordered wholly before or
  wholly after the revocation commit (pinned with the tenant advisory lock);
- revocation is tenant-scoped and every failure path rolls back.

Tests hit the real API over HTTP, and the fixed-interleave races drive two
independent uvicorn processes sharing one PostgreSQL database.
"""
import asyncio
import os
import uuid

import asyncpg
import httpx
import pytest

from conftest import (
    BASE2_URL,
    BASE_URL,
    promote,
    prove,
    register_key,
    retire,
    revoke,
    set_policy,
    submit,
    submit_v2,
    v2_sign,
)

DSN = os.environ.get(
    "DATABASE_URL", "postgresql://coldchain:coldchain@localhost:5432/coldchain"
)
TENANT_LOCK = "pg_advisory_xact_lock(hashtext('tenant_keys'), hashtext($1))"
WAITING_LOCKS_SQL = (
    "SELECT count(*) FROM pg_locks"
    " WHERE locktype = 'advisory' AND NOT granted"
    " AND classid = hashtext('tenant_keys')"
    " AND objid = hashtext($1) AND objsubid = 2"
)


def _receipts(admin_client, tenant_id):
    resp = admin_client.get(f"/v1/tenants/{tenant_id}/receipts")
    assert resp.status_code == 200, resp.text
    return resp.json()["receipts"]


def _v2_receipts(admin_client, tenant_id):
    return [r for r in _receipts(admin_client, tenant_id) if r["version"] == 2]


def _revoked_view(admin_client, tenant_id):
    resp = admin_client.get(f"/v1/tenants/{tenant_id}/keys")
    assert resp.status_code == 200, resp.text
    return resp.json()


def _assert_revoked(revocations, key_id):
    ids = {item["keyId"]: item for item in revocations}
    assert key_id in ids
    assert ids[key_id]["revokedAt"]  # durable, ISO timestamp
    return ids[key_id]["revokedAt"]


async def _wait_waiting(conn, tenant_id, expected, timeout=10.0):
    """Wait until `expected` API transactions are queued on the tenant lock."""
    deadline = asyncio.get_running_loop().time() + timeout
    while True:
        waiting = await conn.fetchval(WAITING_LOCKS_SQL, tenant_id)
        if waiting >= expected:
            return
        if asyncio.get_running_loop().time() > deadline:
            raise AssertionError(
                f"only {waiting} waiter(s) queued on the tenant lock, wanted {expected}"
            )
        await asyncio.sleep(0.02)


async def _post(full_url, headers, content):
    async with httpx.AsyncClient(timeout=30.0) as client:
        return await client.post(full_url, headers=headers, content=content)


async def _hold_tenant_lock(tenant_id):
    """Open a transaction holding the tenant advisory xact lock."""
    conn = await asyncpg.connect(DSN)
    tx = conn.transaction()
    await tx.start()
    await conn.execute(f"SELECT {TENANT_LOCK}", tenant_id)
    return conn, tx


# ---------------------------------------------------------------------------
# Lifecycle semantics
# ---------------------------------------------------------------------------

def test_revoke_persists_time_and_is_visible_in_key_view(
    admin_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    resp = revoke(admin_client, tenant_id, key.key_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["keyId"] == key.key_id
    assert body["revoked"] is True
    revoked_at = _assert_revoked(body["revocations"], key.key_id)

    view = _revoked_view(admin_client, tenant_id)
    assert _assert_revoked(view["revoked"], key.key_id) == revoked_at


def test_revoke_is_idempotent_and_keeps_first_durable_timestamp(
    admin_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    first = revoke(admin_client, tenant_id, key.key_id).json()["revocations"]
    second = revoke(admin_client, tenant_id, key.key_id)
    assert second.status_code == 200, second.text
    assert second.json()["revoked"] is True
    # The first revocation time is durable; repeating never moves it.
    assert second.json()["revocations"] == first


def test_revoked_candidate_releases_seat_and_is_not_promotable(
    admin_client, tenant_id, make_key
):
    current, candidate = make_key(), make_key()
    register_key(admin_client, tenant_id, current)
    register_key(admin_client, tenant_id, candidate)

    resp = revoke(admin_client, tenant_id, candidate.key_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # The candidate seat is free again and the key is no longer current.
    assert body["roles"] == {"current": current.key_id, "candidate": None, "retiring": None}
    assert candidate.key_id not in body["retired"]
    _assert_revoked(body["revocations"], candidate.key_id)

    # Promote with no candidate is an illegal transition.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "ILLEGAL_TRANSITION"

    # The freed seat accepts a replacement immediately.
    replacement = make_key()
    resp = register_key(admin_client, tenant_id, replacement)
    assert resp.status_code == 201, resp.text
    assert resp.json()["role"] == "candidate"

    # Promotion moves the replacement in; the revoked candidate never returns.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"] == {
        "current": replacement.key_id,
        "candidate": None,
        "retiring": current.key_id,
    }

    view = _revoked_view(admin_client, tenant_id)
    _assert_revoked(view["revoked"], candidate.key_id)
    assert candidate.key_id not in view["retired"]


def test_revoked_current_key_rotates_out_via_normal_promote(
    admin_client, tenant_id, make_key
):
    current, candidate = make_key(), make_key()
    register_key(admin_client, tenant_id, current)
    register_key(admin_client, tenant_id, candidate)

    resp = revoke(admin_client, tenant_id, current.key_id)
    assert resp.status_code == 200, resp.text
    # The revoked current key keeps its role until rotated...
    assert resp.json()["roles"]["current"] == current.key_id
    _assert_revoked(resp.json()["revocations"], current.key_id)

    # ...and the ordinary promote flow replaces it: candidate -> current,
    # revoked current -> retiring.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"] == {
        "current": candidate.key_id,
        "candidate": None,
        "retiring": current.key_id,
    }

    # Retire then releases the retiring seat normally.
    resp = retire(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"]["retiring"] is None
    view = _revoked_view(admin_client, tenant_id)
    _assert_revoked(view["revoked"], current.key_id)
    assert current.key_id not in view["retired"]


def test_revoked_retiring_key_still_retired_by_normal_flow(
    admin_client, tenant_id, make_key
):
    old, new = make_key(), make_key()
    register_key(admin_client, tenant_id, old)
    register_key(admin_client, tenant_id, new)
    promote(admin_client, tenant_id)  # old is retiring

    resp = revoke(admin_client, tenant_id, old.key_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"]["retiring"] == old.key_id

    resp = retire(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"]["retiring"] is None
    view = _revoked_view(admin_client, tenant_id)
    _assert_revoked(view["revoked"], old.key_id)
    assert old.key_id not in view["retired"]


def test_revoked_candidate_with_answered_proof_cannot_be_promoted(
    admin_client, tenant_id, make_key
):
    """Pop policy enabled, candidate already holds an answered proof. Its
    revocation releases the seat; the stale proof can never drive a promotion,
    and a replacement candidate still needs its own proof."""
    current, candidate = make_key(), make_key()
    register_key(admin_client, tenant_id, current)
    register_key(admin_client, tenant_id, candidate)
    set_policy(admin_client, tenant_id, True, ttl=300)
    prove(admin_client, tenant_id, candidate)

    assert revoke(admin_client, tenant_id, candidate.key_id).status_code == 200

    # No candidate seat occupied: promote fails (and never consumes the proof).
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "ILLEGAL_TRANSITION"
    assert resp.json()["roles"]["candidate"] is None

    # Registering a replacement is allowed even under the PoP policy...
    replacement = make_key()
    resp = register_key(admin_client, tenant_id, replacement)
    assert resp.status_code == 201
    # ...but it must prove possession itself: no proof for it yet.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "POP_PROOF_REQUIRED"

    # With its own proof the replacement promotes; the revoked key stays out.
    prove(admin_client, tenant_id, replacement)
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"] == {
        "current": replacement.key_id,
        "candidate": None,
        "retiring": current.key_id,
    }


def test_revoke_unknown_and_other_tenant_key_is_404(
    admin_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    resp = revoke(admin_client, tenant_id, "no-such-key")
    assert resp.status_code == 404
    assert resp.json() == {"error": "KEY_UNKNOWN"}

    # A distinct key under another tenant: A cannot revoke it even though it
    # exists and is valid, because revocation is scoped to (tenant, key).
    other = tenant_id + "-other"
    foreign = make_key()
    register_key(admin_client, other, foreign)
    resp = revoke(admin_client, tenant_id, foreign.key_id)
    assert resp.status_code == 404
    assert resp.json() == {"error": "KEY_UNKNOWN"}
    # B's key is untouched and still verifies.
    view = _revoked_view(admin_client, other)
    assert view["revoked"] == []

    # Revoking B's key *as B* still works.
    resp = revoke(admin_client, other, foreign.key_id)
    assert resp.status_code == 200


def test_revoke_requires_admin_scope(tenant_id, make_key):
    from conftest import GATEWAY_HEADERS

    key = make_key()
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as anon:
        assert anon.post(
            f"/v1/tenants/{tenant_id}/keys/{key.key_id}/revoke"
        ).status_code == 401
    with httpx.Client(base_url=BASE_URL, headers=GATEWAY_HEADERS, timeout=30.0) as gw:
        assert gw.post(
            f"/v1/tenants/{tenant_id}/keys/{key.key_id}/revoke"
        ).status_code == 403


# ---------------------------------------------------------------------------
# v1 verification against a revoked key
# ---------------------------------------------------------------------------

def test_v1_receipts_before_revocation_remain_queryable_new_requests_refused(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"reading-before"
    before = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert before.status_code == 202, before.text
    before_id = before.json()["receiptId"]

    assert revoke(admin_client, tenant_id, key.key_id).status_code == 200

    # Pre-revocation receipts are still listed to the administrator.
    receipts = _receipts(admin_client, tenant_id)
    assert [r["receiptId"] for r in receipts] == [before_id]
    assert receipts[0]["keyId"] == key.key_id
    assert receipts[0]["version"] == 1

    # Every new v1 request (same or new content) is refused, no new receipt.
    for payload in (body, b"reading-after"):
        resp = submit(gateway_client, tenant_id, key.key_id, key.sign(payload), payload)
        assert resp.status_code == 410
        assert resp.json() == {"error": "KEY_REVOKED"}
    assert [r["receiptId"] for r in _receipts(admin_client, tenant_id)] == [before_id]


def test_v1_revoked_key_refusal_is_stable_regardless_of_signature(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    revoke(admin_client, tenant_id, key.key_id)
    body = b"x"
    good = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    bad = submit(gateway_client, tenant_id, key.key_id, make_key().sign(body), body)
    assert good.status_code == bad.status_code == 410
    assert good.json() == bad.json() == {"error": "KEY_REVOKED"}
    assert _receipts(admin_client, tenant_id) == []


# ---------------------------------------------------------------------------
# v2 verification against a revoked key
# ---------------------------------------------------------------------------

def test_v2_revoke_blocks_new_messages_exact_retries_and_creates_no_receipt(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id, body = "msg-before-revoke", b"payload-R"
    first = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    )
    assert first.status_code == 202, first.text
    first_id = first.json()["receiptId"]

    # The exact-retry escape hatch works before revocation (legacy semantics).
    retry = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    )
    assert retry.status_code == 200
    assert retry.json()["receiptId"] == first_id

    assert revoke(admin_client, tenant_id, key.key_id).status_code == 200

    # 1) Byte-identical retry of the OLD message id no longer fetches the old
    #    receipt: the replay window is closed.
    old_retry = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    )
    assert old_retry.status_code == 410
    assert old_retry.json() == {"error": "KEY_REVOKED"}

    # 2) A brand new message id is refused as well.
    new_msg = submit_v2(
        gateway_client, tenant_id, key.key_id, "msg-after-revoke",
        v2_sign(key, tenant_id, key.key_id, "msg-after-revoke", body), body,
    )
    assert new_msg.status_code == 410
    assert new_msg.json() == {"error": "KEY_REVOKED"}

    # The original pre-revocation receipt is untouched and still queryable.
    v2_rows = _v2_receipts(admin_client, tenant_id)
    assert len(v2_rows) == 1
    assert v2_rows[0]["receiptId"] == first_id
    assert v2_rows[0]["messageId"] == message_id


def test_v2_bad_signature_after_revocation_does_not_probe_existence(
    admin_client, gateway_client, tenant_id, make_key
):
    key, forger = make_key(), make_key()
    register_key(admin_client, tenant_id, key)
    existing_id, body = "msg-exists", b"payload-S"
    submit_v2(
        gateway_client, tenant_id, key.key_id, existing_id,
        v2_sign(key, tenant_id, key.key_id, existing_id, body), body,
    )
    revoke(admin_client, tenant_id, key.key_id)

    # Forged signatures against an existing and a never-seen message id must
    # be answered identically (BAD_SIGNATURE): existence is not leaked and the
    # revocation gate is never reached by an unverified request.
    for mid in (existing_id, "msg-does-not-exist"):
        resp = submit_v2(
            gateway_client, tenant_id, key.key_id, mid,
            v2_sign(forger, tenant_id, key.key_id, mid, body), body,
        )
        assert resp.status_code == 400
        assert resp.json() == {"error": "BAD_SIGNATURE"}
    assert len(_v2_receipts(admin_client, tenant_id)) == 1


def test_non_revoked_retired_key_keeps_exact_retry_semantics(
    admin_client, gateway_client, tenant_id, make_key
):
    """Migration guarantee: an ordinary (unrevoked) retired key still answers
    exact v2 retries with the original receipt."""
    old, new = make_key(), make_key()
    register_key(admin_client, tenant_id, old)
    register_key(admin_client, tenant_id, new)
    promote(admin_client, tenant_id)
    message_id, body = "msg-legacy", b"payload-L"
    first = submit_v2(
        gateway_client, tenant_id, old.key_id, message_id,
        v2_sign(old, tenant_id, old.key_id, message_id, body), body,
    )
    assert first.status_code == 202
    retire(admin_client, tenant_id)

    retry = submit_v2(
        gateway_client, tenant_id, old.key_id, message_id,
        v2_sign(old, tenant_id, old.key_id, message_id, body), body,
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["receiptId"] == first.json()["receiptId"]
    assert retry.json()["duplicate"] is True


def test_revocation_is_scoped_to_its_tenant(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    other = tenant_id + "-sibling"
    register_key(admin_client, other, key)  # same key id + public key

    revoke(admin_client, tenant_id, key.key_id)

    body = b"tenant-scoped"
    # Tenant A: revoked.
    a = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert a.status_code == 410
    assert a.json() == {"error": "KEY_REVOKED"}
    # Tenant B: independent lifecycle, fully operational.
    b = submit(gateway_client, other, key.key_id, key.sign(body), body)
    assert b.status_code == 202, b.text
    assert len(_receipts(admin_client, tenant_id)) == 0
    assert len(_receipts(admin_client, other)) == 1


# ---------------------------------------------------------------------------
# Fixed revoke/verify interleavings across two instances
# ---------------------------------------------------------------------------

def test_interleave_revoke_first_verify_second_verify_is_refused(
    admin_client, gateway_client2, tenant_id, make_key
):
    """Pinned R-then-V queue order on the tenant advisory lock: the revoke
    (instance 1) is queued first and the verify (instance 2) second; when the
    holder releases they are admitted in that order, so the revoke commits
    first and the verify is refused. No receipt may appear."""
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"interleave-after"
    v_headers = {
        "X-Tenant-Id": tenant_id,
        "X-Key-Id": key.key_id,
        "X-Signature": key.sign(body),
        **gateway_client2.headers,
    }

    async def scenario():
        conn, tx = await _hold_tenant_lock(tenant_id)
        try:
            revoke_task = asyncio.create_task(
                _post(
                    f"{BASE_URL}/v1/tenants/{tenant_id}/keys/{key.key_id}/revoke",
                    dict(admin_client.headers), b"",
                )
            )
            await _wait_waiting(conn, tenant_id, 1)
            verify_task = asyncio.create_task(
                _post(f"{BASE2_URL}/v1/verify", v_headers, body)
            )
            await _wait_waiting(conn, tenant_id, 2)
            # Release: the queued operations are granted in queue order.
            await tx.commit()
            return await asyncio.gather(revoke_task, verify_task)
        finally:
            await conn.close()

    results = asyncio.run(scenario())
    statuses = {r.status_code for r in results}
    assert statuses == {200, 410}, [(r.status_code, r.text) for r in results]
    revoke_resp = next(r for r in results if r.status_code == 200)
    verify_resp = next(r for r in results if r.status_code == 410)
    assert revoke_resp.json()["revoked"] is True
    assert verify_resp.json() == {"error": "KEY_REVOKED"}
    assert _receipts(admin_client, tenant_id) == []


def test_interleave_verify_first_revoke_second_receipt_precedes_revocation(
    admin_client, gateway_client, gateway_client2, tenant_id, make_key
):
    """Pinned V-then-R queue order: the verify (instance 2) is queued first,
    the revoke (instance 1) second. Verify commits before the revocation and
    produces a receipt; the revocation is committed afterwards. Together with
    the R-then-V case this proves every outcome is attributable to one side
    of the boundary -- never 'revoke committed yet a receipt appeared'."""
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"interleave-before"
    v_headers = {
        "X-Tenant-Id": tenant_id,
        "X-Key-Id": key.key_id,
        "X-Signature": key.sign(body),
        **gateway_client2.headers,
    }

    async def scenario():
        conn, tx = await _hold_tenant_lock(tenant_id)
        try:
            verify_task = asyncio.create_task(
                _post(f"{BASE2_URL}/v1/verify", v_headers, body)
            )
            await _wait_waiting(conn, tenant_id, 1)
            revoke_task = asyncio.create_task(
                _post(
                    f"{BASE_URL}/v1/tenants/{tenant_id}/keys/{key.key_id}/revoke",
                    dict(admin_client.headers), b"",
                )
            )
            await _wait_waiting(conn, tenant_id, 2)
            await tx.commit()
            return await asyncio.gather(verify_task, revoke_task)
        finally:
            await conn.close()

    results = asyncio.run(scenario())
    statuses = sorted(r.status_code for r in results)
    assert statuses == [200, 202], [(r.status_code, r.text) for r in results]
    verify_resp = next(r for r in results if r.status_code == 202)
    receipt_id = verify_resp.json()["receiptId"]

    receipts = _receipts(admin_client, tenant_id)
    assert len(receipts) == 1
    assert receipts[0]["receiptId"] == receipt_id

    _assert_revoked(_revoked_view(admin_client, tenant_id)["revoked"], key.key_id)
    # Any request strictly after the committed revoke is refused.
    after = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert after.status_code == 410
    assert after.json() == {"error": "KEY_REVOKED"}


def test_concurrent_revoke_and_verify_never_leave_a_post_revocation_receipt(
    admin_client, gateway_client2, tenant_id, make_key
):
    """Rounds of true concurrency across two instances. The database is the
    final arbiter: no receipt for a revoked key may carry a timestamp later
    than that key's revocation time."""

    async def one_round(round_id):
        round_tenant = f"{tenant_id}-r{round_id}"
        key = make_key()
        async with httpx.AsyncClient(
            base_url=BASE_URL, timeout=30.0, headers=dict(admin_client.headers)
        ) as admin:
            r = await admin.post(
                f"/v1/tenants/{round_tenant}/keys",
                json={"keyId": key.key_id, "publicKey": key.public_key_b64},
            )
            assert r.status_code == 201, r.text

        body = f"race-{round_id}".encode()
        v_headers = {
            "X-Tenant-Id": round_tenant,
            "X-Key-Id": key.key_id,
            "X-Signature": key.sign(body),
            **gateway_client2.headers,
        }
        return await asyncio.gather(
            _post(f"{BASE2_URL}/v1/verify", v_headers, body),
            _post(
                f"{BASE_URL}/v1/tenants/{round_tenant}/keys/{key.key_id}/revoke",
                dict(admin_client.headers), b"",
            ),
        )

    rounds = [asyncio.run(one_round(i)) for i in range(8)]

    async def check_invariant():
        conn = await asyncpg.connect(DSN)
        try:
            for table in ("receipts", "v2_receipts"):
                bad = await conn.fetchval(
                    f"SELECT count(*) FROM {table} rc"
                    " JOIN key_revocations kr"
                    "   ON kr.tenant_id = rc.tenant_id AND kr.key_id = rc.key_id"
                    " WHERE rc.tenant_id LIKE $1 || '%'"
                    "   AND rc.created_at > kr.revoked_at",
                    f"{tenant_id}-r",
                )
                assert bad == 0, f"{bad} {table} rows created after revocation"
        finally:
            await conn.close()

    asyncio.run(check_invariant())

    for verify_resp, revoke_resp in rounds:
        assert revoke_resp.status_code == 200, revoke_resp.text
        if verify_resp.status_code == 202:
            assert "receiptId" in verify_resp.json()
        else:
            assert verify_resp.status_code == 410
            assert verify_resp.json() == {"error": "KEY_REVOKED"}


# ---------------------------------------------------------------------------
# Failure rollback and migration
# ---------------------------------------------------------------------------

def test_revoke_failure_rolls_back_and_keeps_state(
    admin_client, tenant_id, make_key
):
    current, candidate = make_key(), make_key()
    register_key(admin_client, tenant_id, current)
    register_key(admin_client, tenant_id, candidate)
    before = _revoked_view(admin_client, tenant_id)

    # Revoking an unknown key is a 404 inside the transaction: nothing changes.
    resp = revoke(admin_client, tenant_id, "missing-key")
    assert resp.status_code == 404
    assert _revoked_view(admin_client, tenant_id) == before

    # Bad ids are rejected before any statement runs.
    resp = revoke(admin_client, tenant_id, "bad key id!")
    assert resp.status_code == 400
    assert _revoked_view(admin_client, tenant_id) == before


def test_migration_preserves_keys_receipts_and_adds_revocation_table():
    """Real-database checks: old data is untouched and the revocation table
    exists, is keyed per (tenant, key), and a second insert cannot overwrite
    the durable timestamp."""

    async def check():
        conn = await asyncpg.connect(DSN)
        try:
            assert await conn.fetchval(
                "SELECT to_regclass('public.key_revocations') IS NOT NULL"
            )
            assert await conn.fetchval(
                "SELECT count(*) FROM pg_constraint"
                " WHERE conrelid = 'key_revocations'::regclass AND contype = 'p'"
            ) == 1

            tenant = f"migrate-{uuid.uuid4().hex[:12]}"
            key_id = f"k-{uuid.uuid4().hex[:12]}"
            await conn.execute(
                "INSERT INTO tenant_keys (tenant_id, key_id, role, public_key)"
                " VALUES ($1, $2, 'current', $3)",
                tenant, key_id, b"\xaa" * 32,
            )
            rid = uuid.uuid4()
            await conn.execute(
                "INSERT INTO receipts (receipt_id, tenant_id, key_id,"
                " body_sha256, body_size) VALUES ($1, $2, $3, $4, 7)",
                rid, tenant, key_id, b"\xbb" * 32,
            )
            await conn.execute(
                "INSERT INTO key_revocations (tenant_id, key_id) VALUES ($1, $2)",
                tenant, key_id,
            )
            # A re-revocation cannot move the durable timestamp.
            await conn.execute(
                "INSERT INTO key_revocations (tenant_id, key_id, revoked_at)"
                " VALUES ($1, $2, now() + interval '10 years')"
                " ON CONFLICT (tenant_id, key_id) DO NOTHING",
                tenant, key_id,
            )
            assert await conn.fetchval(
                "SELECT count(*) FROM key_revocations"
                " WHERE tenant_id = $1 AND key_id = $2",
                tenant, key_id,
            ) == 1
            # Old receipt and key survive untouched.
            assert await conn.fetchval(
                "SELECT count(*) FROM receipts WHERE receipt_id = $1", rid
            ) == 1
            assert await conn.fetchval(
                "SELECT role FROM tenant_keys WHERE tenant_id = $1 AND key_id = $2",
                tenant, key_id,
            ) == "current"
            # A revocation cannot reference a non-existent key (FK).
            with pytest.raises(asyncpg.ForeignKeyViolationError):
                await conn.execute(
                    "INSERT INTO key_revocations (tenant_id, key_id)"
                    " VALUES ($1, 'ghost')",
                    tenant,
                )
        finally:
            await conn.close()

    asyncio.run(check())
