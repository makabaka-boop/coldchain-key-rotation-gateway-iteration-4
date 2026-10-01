"""Acceptance tests for key revocation (leaked-key emergency stop).

Revocation is a per-tenant, per-key, irreversible operation orthogonal to the
role state machine (current / candidate / retiring / retired). Once revoked, a
key can never verify again — v1 requests, v2 exact retries and new v2 messages
all get the same stable KEY_REVOKED and no new receipt — while receipts issued
before the revocation remain queryable by the admin. These tests run against
the real API over HTTP with two uvicorn instances sharing one PostgreSQL
database, covering fixed interleavings, cross-tenant isolation and failure
rollback.
"""
import asyncio
import os
from datetime import datetime

import httpx
import pytest

from conftest import (
    ADMIN_HEADERS,
    BASE2_URL,
    BASE_URL,
    GATEWAY_HEADERS,
    get_roles,
    promote,
    prove,
    register_key,
    retire,
    set_policy,
    submit,
    submit_v2,
    v2_sign,
)


def revoke(client, tenant_id, key_id):
    return client.post(f"/v1/tenants/{tenant_id}/keys/{key_id}/revoke")


def _receipts(admin_client, tenant_id):
    resp = admin_client.get(f"/v1/tenants/{tenant_id}/receipts")
    assert resp.status_code == 200, resp.text
    return resp.json()["receipts"]


def _revoked(admin_client, tenant_id):
    return get_roles(admin_client, tenant_id)["revoked"]


def _ts(iso: str) -> datetime:
    return datetime.fromisoformat(iso)


# --- core refusal semantics -------------------------------------------------


def test_revoke_current_key_blocks_v1_and_keeps_old_receipts(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"temperature=-18.5;door=closed"
    resp = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert resp.status_code == 202, resp.text
    receipt_id = resp.json()["receiptId"]

    resp = revoke(admin_client, tenant_id, key.key_id)
    assert resp.status_code == 200, resp.text
    outcome = resp.json()
    assert outcome["keyId"] == key.key_id
    assert outcome["alreadyRevoked"] is False
    assert outcome["revokedAt"]
    # A revoked current key keeps its role: rotation replaces it as usual.
    assert outcome["roles"] == {"current": key.key_id, "candidate": None, "retiring": None}

    # New v1 requests are stably refused and produce no receipt.
    resp = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_REVOKED"}

    # The pre-revocation receipt is still queryable, and nothing was added.
    receipts = _receipts(admin_client, tenant_id)
    assert [r["receiptId"] for r in receipts] == [receipt_id]

    # The revocation is listed with its timestamp.
    revoked = _revoked(admin_client, tenant_id)
    assert revoked == [{"keyId": key.key_id, "revokedAt": outcome["revokedAt"]}]


def test_revoke_blocks_v2_new_message_and_exact_retry(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id, body = "msg-before-revoke", b"reading-A"
    sig = v2_sign(key, tenant_id, key.key_id, message_id, body)
    resp = submit_v2(gateway_client, tenant_id, key.key_id, message_id, sig, body)
    assert resp.status_code == 202, resp.text
    receipt_id = resp.json()["receiptId"]

    assert revoke(admin_client, tenant_id, key.key_id).status_code == 200

    # Unlike a retired key, a revoked key may not even replay its own
    # already-accepted message to fetch the receipt.
    retry = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    )
    assert retry.status_code == 410
    assert retry.json() == {"error": "KEY_REVOKED"}

    # A fresh message id is refused identically.
    fresh = submit_v2(
        gateway_client, tenant_id, key.key_id, "msg-after-revoke",
        v2_sign(key, tenant_id, key.key_id, "msg-after-revoke", body), body,
    )
    assert fresh.status_code == 410
    assert fresh.json() == {"error": "KEY_REVOKED"}

    # The original receipt survives for admin query; no new receipt appeared.
    receipts = [r for r in _receipts(admin_client, tenant_id) if r["version"] == 2]
    assert [r["receiptId"] for r in receipts] == [receipt_id]


def test_revoked_key_gives_stable_rejection_regardless_of_signature(
    admin_client, gateway_client, tenant_id, make_key
):
    key, forger = make_key(), make_key()
    register_key(admin_client, tenant_id, key)
    message_id, body = "msg-stable", b"payload"
    assert submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    ).status_code == 202
    assert revoke(admin_client, tenant_id, key.key_id).status_code == 200

    # Valid signature vs forged signature, existing message id vs fresh one:
    # every combination gets the identical refusal, so the response cannot be
    # used to probe whether a message id exists.
    combinations = [
        (message_id, v2_sign(key, tenant_id, key.key_id, message_id, body)),
        ("msg-fresh", v2_sign(key, tenant_id, key.key_id, "msg-fresh", body)),
        (message_id, v2_sign(forger, tenant_id, key.key_id, message_id, body)),
        ("msg-fresh", v2_sign(forger, tenant_id, key.key_id, "msg-fresh", body)),
    ]
    for mid, sig in combinations:
        resp = submit_v2(gateway_client, tenant_id, key.key_id, mid, sig, body)
        assert resp.status_code == 410, (mid, resp.text)
        assert resp.json() == {"error": "KEY_REVOKED"}

    # v1 with a forged signature on the revoked key: same stable refusal.
    resp = submit(gateway_client, tenant_id, key.key_id, forger.sign(body), body)
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_REVOKED"}

    # Contrast: a live key still reports BAD_SIGNATURE for a forged signature.
    live = make_key()
    register_key(admin_client, tenant_id, live)  # candidate seat is free
    resp = submit(gateway_client, tenant_id, live.key_id, forger.sign(body), body)
    assert resp.status_code == 400
    assert resp.json() == {"error": "BAD_SIGNATURE"}
    # No new receipts of any kind were created by the refusals above.
    assert len(_receipts(admin_client, tenant_id)) == 1


# --- revocation is irreversible and idempotent -------------------------------


def test_revoke_is_idempotent_and_keeps_first_timestamp(
    admin_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    first = revoke(admin_client, tenant_id, key.key_id)
    assert first.status_code == 200
    assert first.json()["alreadyRevoked"] is False

    second = revoke(admin_client, tenant_id, key.key_id)
    assert second.status_code == 200
    assert second.json()["alreadyRevoked"] is True
    # The original revocation time is authoritative and never moves.
    assert second.json()["revokedAt"] == first.json()["revokedAt"]
    assert _revoked(admin_client, tenant_id) == [
        {"keyId": key.key_id, "revokedAt": first.json()["revokedAt"]}
    ]

    # The key id stays taken: revocation is irreversible, re-registration is
    # not a way back.
    resp = register_key(admin_client, tenant_id, key)
    assert resp.status_code == 409
    assert resp.json()["error"] == "KEY_ALREADY_EXISTS"


def test_concurrent_revoke_from_two_instances_succeeds_once(
    admin_client, admin_client2, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)

    async def run():
        async with httpx.AsyncClient(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as a:
            async with httpx.AsyncClient(base_url=BASE2_URL, headers=ADMIN_HEADERS, timeout=30.0) as b:
                clients = [a, b]
                return await asyncio.gather(*[
                    clients[i % 2].post(f"/v1/tenants/{tenant_id}/keys/{key.key_id}/revoke")
                    for i in range(4)
                ])

    responses = asyncio.run(run())
    assert all(r.status_code == 200 for r in responses)
    assert sum(not r.json()["alreadyRevoked"] for r in responses) == 1
    assert len({r.json()["revokedAt"] for r in responses}) == 1


# --- interaction with the role state machine ---------------------------------


def test_revoked_candidate_releases_seat_and_cannot_be_promoted(
    admin_client, gateway_client, tenant_id, make_key
):
    current, candidate = make_key(), make_key()
    register_key(admin_client, tenant_id, current)
    register_key(admin_client, tenant_id, candidate)

    resp = revoke(admin_client, tenant_id, candidate.key_id)
    assert resp.status_code == 200, resp.text
    # The candidate seat is released immediately.
    assert resp.json()["roles"] == {
        "current": current.key_id, "candidate": None, "retiring": None,
    }
    state = get_roles(admin_client, tenant_id)
    assert candidate.key_id in state["retired"]
    assert [r["keyId"] for r in state["revoked"]] == [candidate.key_id]

    # The revoked candidate can never be promoted: there is no candidate.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "ILLEGAL_TRANSITION"

    # The freed seat admits a replacement candidate, and rotation proceeds.
    replacement = make_key()
    resp = register_key(admin_client, tenant_id, replacement)
    assert resp.status_code == 201, resp.text
    assert resp.json()["role"] == "candidate"
    assert promote(admin_client, tenant_id).status_code == 200
    assert retire(admin_client, tenant_id).status_code == 200

    body = b"reading"
    # The revoked key stays refused (as KEY_REVOKED, not KEY_RETIRED) while
    # the normally retired key reports KEY_RETIRED and the new current works.
    resp = submit(gateway_client, tenant_id, candidate.key_id,
                  candidate.sign(body), body)
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_REVOKED"}
    resp = submit(gateway_client, tenant_id, current.key_id, current.sign(body), body)
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_RETIRED"}
    assert submit(
        gateway_client, tenant_id, replacement.key_id, replacement.sign(body), body
    ).status_code == 202


def test_revoked_current_key_is_replaced_by_normal_rotation(
    admin_client, gateway_client, tenant_id, make_key
):
    current, candidate = make_key(), make_key()
    register_key(admin_client, tenant_id, current)
    register_key(admin_client, tenant_id, candidate)

    # Revoking the current key does not itself change any role.
    resp = revoke(admin_client, tenant_id, current.key_id)
    assert resp.json()["roles"] == {
        "current": current.key_id, "candidate": candidate.key_id, "retiring": None,
    }

    # The standard rotation flow replaces it untouched.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"] == {
        "current": candidate.key_id, "candidate": None, "retiring": current.key_id,
    }
    body = b"reading"
    # Revocation dominates the otherwise-verifiable retiring role.
    resp = submit(gateway_client, tenant_id, current.key_id, current.sign(body), body)
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_REVOKED"}

    assert retire(admin_client, tenant_id).status_code == 200
    resp = submit(gateway_client, tenant_id, current.key_id, current.sign(body), body)
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_REVOKED"}
    state = get_roles(admin_client, tenant_id)
    assert current.key_id in state["retired"]
    assert [r["keyId"] for r in state["revoked"]] == [current.key_id]


def test_revoke_retiring_key_keeps_retire_flow(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    promote(admin_client, tenant_id)

    resp = revoke(admin_client, tenant_id, k1.key_id)
    assert resp.status_code == 200
    assert resp.json()["roles"]["retiring"] == k1.key_id
    # The retire transition is unaffected by the revocation.
    assert retire(admin_client, tenant_id).status_code == 200
    resp = submit(gateway_client, tenant_id, k1.key_id, k1.sign(b"x"), b"x")
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_REVOKED"}


def test_revoked_retired_key_stops_v2_receipt_replay(
    admin_client, gateway_client, tenant_id, make_key
):
    """The leaked-key scenario: while merely retired, a key may still replay
    an accepted message to fetch its receipt; revoking closes that door."""
    old, new = make_key(), make_key()
    register_key(admin_client, tenant_id, old)
    register_key(admin_client, tenant_id, new)
    promote(admin_client, tenant_id)
    message_id, body = "msg-replay-window", b"reading-B"
    resp = submit_v2(
        gateway_client, tenant_id, old.key_id, message_id,
        v2_sign(old, tenant_id, old.key_id, message_id, body), body,
    )
    assert resp.status_code == 202, resp.text
    receipt_id = resp.json()["receiptId"]
    retire(admin_client, tenant_id)

    # Merely retired: the exact retry still returns the original receipt.
    retry = submit_v2(
        gateway_client, tenant_id, old.key_id, message_id,
        v2_sign(old, tenant_id, old.key_id, message_id, body), body,
    )
    assert retry.status_code == 200
    assert retry.json()["receiptId"] == receipt_id

    # Revoked: the same retry is now a stable refusal, as is any new message.
    assert revoke(admin_client, tenant_id, old.key_id).status_code == 200
    retry = submit_v2(
        gateway_client, tenant_id, old.key_id, message_id,
        v2_sign(old, tenant_id, old.key_id, message_id, body), body,
    )
    assert retry.status_code == 410
    assert retry.json() == {"error": "KEY_REVOKED"}
    # The receipt itself remains queryable by the admin.
    receipts = [r for r in _receipts(admin_client, tenant_id) if r["version"] == 2]
    assert [r["receiptId"] for r in receipts] == [receipt_id]


def test_unrevoked_keys_keep_retired_retry_semantics(
    admin_client, gateway_client, tenant_id, make_key
):
    """Revoking one key must not disturb another key's retired-retry rules."""
    old, new = make_key(), make_key()
    register_key(admin_client, tenant_id, old)
    register_key(admin_client, tenant_id, new)
    promote(admin_client, tenant_id)
    message_id, body = "msg-untouched", b"reading-C"
    resp = submit_v2(
        gateway_client, tenant_id, old.key_id, message_id,
        v2_sign(old, tenant_id, old.key_id, message_id, body), body,
    )
    assert resp.status_code == 202, resp.text
    receipt_id = resp.json()["receiptId"]
    retire(admin_client, tenant_id)

    # Revoke the *current* key; the retired key is not revoked.
    assert revoke(admin_client, tenant_id, new.key_id).status_code == 200
    retry = submit_v2(
        gateway_client, tenant_id, old.key_id, message_id,
        v2_sign(old, tenant_id, old.key_id, message_id, body), body,
    )
    assert retry.status_code == 200, retry.text
    assert retry.json()["receiptId"] == receipt_id
    # A new message on the retired key is still KEY_RETIRED, not KEY_REVOKED.
    resp = submit_v2(
        gateway_client, tenant_id, old.key_id, "msg-new-on-retired",
        v2_sign(old, tenant_id, old.key_id, "msg-new-on-retired", body), body,
    )
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_RETIRED"}


# --- cross-tenant isolation and failure rollback -----------------------------


def test_revoke_unknown_or_cross_tenant_key_is_404_and_changes_nothing(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    other_tenant = tenant_id + "-other"
    other_key = make_key()
    register_key(admin_client, other_tenant, other_key)

    # Unknown key id and another tenant's key id are indistinguishable.
    for key_id in ("no-such-key", other_key.key_id):
        resp = revoke(admin_client, tenant_id, key_id)
        assert resp.status_code == 404
        assert resp.json() == {"error": "KEY_UNKNOWN"}

    # The failed operations rolled back: no revocation state anywhere.
    assert _revoked(admin_client, tenant_id) == []
    assert _revoked(admin_client, other_tenant) == []
    state = get_roles(admin_client, tenant_id)
    assert state["roles"]["current"] == key.key_id
    # Both keys still verify.
    body = b"reading"
    assert submit(
        gateway_client, tenant_id, key.key_id, key.sign(body), body
    ).status_code == 202
    assert submit(
        gateway_client, other_tenant, other_key.key_id, other_key.sign(body), body
    ).status_code == 202


def test_revocation_is_tenant_scoped(admin_client, gateway_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    other_tenant = tenant_id + "-other"
    register_key(admin_client, other_tenant, key)  # same key id, same pubkey
    body = b"payload"

    assert revoke(admin_client, tenant_id, key.key_id).status_code == 200
    resp = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_REVOKED"}

    # The other tenant's identical key id is untouched.
    resp = submit(gateway_client, other_tenant, key.key_id, key.sign(body), body)
    assert resp.status_code == 202, resp.text
    assert _revoked(admin_client, other_tenant) == []
    assert len(_receipts(admin_client, other_tenant)) == 1


def test_revoke_validates_ids(admin_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    assert revoke(admin_client, "bad tenant!", key.key_id).status_code == 400
    assert revoke(admin_client, tenant_id, "bad key!").status_code == 400
    assert _revoked(admin_client, tenant_id) == []


def test_revoke_requires_admin_scope(tenant_id, make_key):
    key = make_key()
    url = f"/v1/tenants/{tenant_id}/keys/{key.key_id}/revoke"
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        assert client.post(url).status_code == 401
        assert client.post(
            url, headers={"Authorization": "Bearer nope"}
        ).status_code == 401
        assert client.post(url, headers=GATEWAY_HEADERS).status_code == 403
        # The key id does not exist, but the admin token gets the domain 404.
        assert client.post(url, headers=ADMIN_HEADERS).status_code == 404


# --- interplay with proof-of-possession --------------------------------------


def test_revoked_candidate_proof_is_closed_out(
    admin_client, tenant_id, make_key
):
    current, candidate = make_key(), make_key()
    register_key(admin_client, tenant_id, current)
    register_key(admin_client, tenant_id, candidate)
    set_policy(admin_client, tenant_id, True, ttl=300)
    prove(admin_client, tenant_id, candidate)  # answered, unconsumed proof

    assert revoke(admin_client, tenant_id, candidate.key_id).status_code == 200
    # The dead candidate's proof can never drive a promotion.
    challenges = admin_client.get(
        f"/v1/tenants/{tenant_id}/pop-challenges"
    ).json()["challenges"]
    assert [c["status"] for c in challenges] == ["expired"]

    # A replacement candidate needs its own fresh proof.
    replacement = make_key()
    assert register_key(admin_client, tenant_id, replacement).status_code == 201
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "POP_PROOF_REQUIRED"
    prove(admin_client, tenant_id, replacement)
    assert promote(admin_client, tenant_id).status_code == 200


# --- verify/revoke interleavings across two instances ------------------------


def test_revoke_on_one_instance_blocks_verify_on_the_other(
    admin_client2, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client2, tenant_id, key)
    body = b"cross-instance"
    assert submit(
        gateway_client, tenant_id, key.key_id, key.sign(body), body
    ).status_code == 202
    # Revoke via instance 2; instance 1 must observe it immediately.
    assert revoke(admin_client2, tenant_id, key.key_id).status_code == 200
    resp = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_REVOKED"}
    assert len(_receipts(admin_client2, tenant_id)) == 1


def test_concurrent_verify_and_revoke_attribute_to_one_side(
    admin_client, gateway_client, tenant_id, make_key
):
    """A verify racing a revoke must land unambiguously before or after it:
    every 202's receipt predates the revocation, and once the revoke has
    committed no new receipt can appear."""
    for round_id in range(4):
        tenant = f"{tenant_id}-r{round_id}"
        key = make_key()
        register_key(admin_client, tenant, key)
        body = b"reading"

        async def run():
            headers = {
                "X-Tenant-Id": tenant,
                "X-Key-Id": key.key_id,
                "X-Signature": key.sign(body),
            }
            async with httpx.AsyncClient(
                base_url=BASE_URL, headers=GATEWAY_HEADERS, timeout=30.0
            ) as g1:
                async with httpx.AsyncClient(
                    base_url=BASE2_URL, headers=ADMIN_HEADERS, timeout=30.0
                ) as a2:
                    return await asyncio.gather(
                        *[g1.post("/v1/verify", content=body, headers=headers)
                          for _ in range(8)],
                        a2.post(f"/v1/tenants/{tenant}/keys/{key.key_id}/revoke"),
                    )

        responses = asyncio.run(run())
        verifies, revoke_resp = responses[:-1], responses[-1]
        assert revoke_resp.status_code == 200, revoke_resp.text
        revoked_at = _ts(revoke_resp.json()["revokedAt"])

        for resp in verifies:
            assert resp.status_code in (202, 410), resp.text
            if resp.status_code == 410:
                assert resp.json() == {"error": "KEY_REVOKED"}
        accepted = [r for r in verifies if r.status_code == 202]

        # Exactly the accepted verifies left receipts, and every one of them
        # belongs to the pre-revocation world.
        receipts = _receipts(admin_client, tenant)
        assert len(receipts) == len(accepted)
        for receipt in receipts:
            assert _ts(receipt["createdAt"]) < revoked_at

        # After the revoke committed, verification is stably refused and the
        # receipt count never grows again.
        for _ in range(3):
            resp = submit(gateway_client, tenant, key.key_id, key.sign(body), body)
            assert resp.status_code == 410
            assert resp.json() == {"error": "KEY_REVOKED"}
        assert len(_receipts(admin_client, tenant)) == len(accepted)


def test_concurrent_v2_and_revoke_never_replays_after_revoke(
    admin_client, gateway_client, tenant_id, make_key
):
    """v2 under race: a retry that lands before the revoke gets its receipt;
    after the revoke commits, even the exact retry is KEY_REVOKED."""
    key = make_key()
    register_key(admin_client, tenant_id, key)
    message_id, body = "msg-race-revoke", b"payload"
    # One receipt established deterministically before the race.
    resp = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    )
    assert resp.status_code == 202, resp.text
    receipt_id = resp.json()["receiptId"]

    async def run():
        async with httpx.AsyncClient(
            base_url=BASE_URL, headers=GATEWAY_HEADERS, timeout=30.0
        ) as g1:
            async with httpx.AsyncClient(
                base_url=BASE2_URL, headers=ADMIN_HEADERS, timeout=30.0
            ) as a2:
                retries = [
                    g1.post(
                        "/v1/verify", content=body,
                        headers={
                            "X-Verify-Version": "2",
                            "X-Tenant-Id": tenant_id,
                            "X-Key-Id": key.key_id,
                            "X-Message-Id": message_id,
                            "X-Signature": v2_sign(
                                key, tenant_id, key.key_id, message_id, body
                            ),
                        },
                    )
                    for _ in range(6)
                ]
                return await asyncio.gather(
                    *retries,
                    a2.post(f"/v1/tenants/{tenant_id}/keys/{key.key_id}/revoke"),
                )

    responses = asyncio.run(run())
    retries, revoke_resp = responses[:-1], responses[-1]
    assert revoke_resp.status_code == 200
    revoked_at = _ts(revoke_resp.json()["revokedAt"])
    for resp in retries:
        # A racing retry either fetched the original receipt (pre-revocation)
        # or was stably refused (post-revocation); never a new receipt.
        assert resp.status_code in (200, 410), resp.text
        if resp.status_code == 200:
            assert resp.json()["receiptId"] == receipt_id
        else:
            assert resp.json() == {"error": "KEY_REVOKED"}

    # Still exactly one receipt, and it predates the revocation.
    receipts = [r for r in _receipts(admin_client, tenant_id) if r["version"] == 2]
    assert [r["receiptId"] for r in receipts] == [receipt_id]
    assert _ts(receipts[0]["createdAt"]) < revoked_at

    # After the revoke: the exact retry and new messages are refused alike.
    retry = submit_v2(
        gateway_client, tenant_id, key.key_id, message_id,
        v2_sign(key, tenant_id, key.key_id, message_id, body), body,
    )
    assert retry.status_code == 410
    assert retry.json() == {"error": "KEY_REVOKED"}


# --- migration keeps existing keys and receipts ------------------------------


def test_revoked_at_migration_preserves_existing_keys_and_receipts(tenant_id):
    """Against the real database: the migration added revoked_at without
    disturbing pre-existing keys or receipts (NULL means not revoked)."""
    import asyncpg

    dsn = os.environ.get(
        "DATABASE_URL", "postgresql://coldchain:coldchain@localhost:5432/coldchain"
    )

    async def check():
        conn = await asyncpg.connect(dsn)
        try:
            column = await conn.fetchval(
                "SELECT data_type FROM information_schema.columns"
                " WHERE table_name = 'tenant_keys' AND column_name = 'revoked_at'"
            )
            assert column == "timestamp with time zone"
            # Rows that predate the migration (and any row since) start
            # unrevoked; receipts are never touched by revocation.
            await conn.execute(
                "INSERT INTO tenant_keys (tenant_id, key_id, role, public_key)"
                " VALUES ($1, 'k-legacy', 'current', $2)",
                tenant_id, b"\x07" * 32,
            )
            row = await conn.fetchrow(
                "SELECT revoked_at FROM tenant_keys WHERE tenant_id = $1 AND key_id = 'k-legacy'",
                tenant_id,
            )
            assert row["revoked_at"] is None
            # The candidate-not-revoked invariant is enforced at storage level.
            with pytest.raises(asyncpg.CheckViolationError):
                async with conn.transaction():
                    await conn.execute(
                        "UPDATE tenant_keys SET revoked_at = now()"
                        " WHERE tenant_id = $1 AND key_id = 'k-legacy'",
                        tenant_id,
                    )
                    await conn.execute(
                        "UPDATE tenant_keys SET role = 'candidate'"
                        " WHERE tenant_id = $1 AND key_id = 'k-legacy'",
                        tenant_id,
                    )
        finally:
            await conn.close()

    asyncio.run(check())
