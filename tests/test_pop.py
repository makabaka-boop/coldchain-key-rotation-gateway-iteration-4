"""Acceptance: tenant-level pre-promotion proof-of-possession policy."""
import asyncio

import httpx

from conftest import (
    ADMIN_HEADERS,
    BASE2_URL,
    BASE_URL,
    GATEWAY_HEADERS,
    answer_challenge,
    get_roles,
    issue_challenge,
    pop_message,
    promote,
    prove,
    register_key,
    retire,
    set_policy,
    sign_challenge,
    submit,
)


def _setup_candidate(admin_client, tenant_id, make_key):
    current, candidate = make_key(), make_key()
    assert register_key(admin_client, tenant_id, current).status_code == 201
    assert register_key(admin_client, tenant_id, candidate).status_code == 201
    return current, candidate


# --- policy is opt-in; legacy behaviour is the default ---------------------


def test_policy_defaults_off_and_is_tenant_scoped(admin_client, tenant_id, make_key):
    other = tenant_id + "-other"
    resp = admin_client.get(f"/v1/tenants/{tenant_id}/policy")
    assert resp.status_code == 200
    assert resp.json() == {
        "tenantId": tenant_id,
        "popRequired": False,
        "challengeTtlSeconds": 120,
    }
    # Enabling one tenant leaves the other on the legacy path.
    assert set_policy(admin_client, tenant_id, True, ttl=60).status_code == 200
    assert admin_client.get(f"/v1/tenants/{other}/policy").json()["popRequired"] is False


def test_legacy_tenant_promotes_without_proof(admin_client, tenant_id, make_key):
    current, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"] == {
        "current": candidate.key_id,
        "candidate": None,
        "retiring": current.key_id,
    }
    # Legacy tenants do not even have a challenge endpoint usable.
    assert issue_challenge(admin_client, tenant_id).status_code == 409


def test_challenge_endpoint_requires_policy_and_candidate(admin_client, tenant_id, make_key):
    current = make_key()
    register_key(admin_client, tenant_id, current)
    set_policy(admin_client, tenant_id, True)
    # No candidate yet: illegal transition with authoritative roles.
    resp = issue_challenge(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "ILLEGAL_TRANSITION"
    assert resp.json()["roles"] == {"current": current.key_id, "candidate": None, "retiring": None}


def test_policy_ttl_validation(admin_client, tenant_id):
    for bad in (0, -1, 86401):
        resp = set_policy(admin_client, tenant_id, True, ttl=bad)
        assert resp.status_code == 400, bad
        assert resp.json()["error"] == "BAD_REQUEST"


# --- happy path -------------------------------------------------------------


def test_proof_issued_and_promote_consumes_it_once(admin_client, tenant_id, make_key):
    current, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True, ttl=60)

    challenge, proof = prove(admin_client, tenant_id, candidate)
    assert challenge["status"] == "issued"
    assert challenge["currentGeneration"] == 0
    assert challenge["candidateKeyId"] == candidate.key_id
    assert challenge["currentKeyId"] == current.key_id
    assert proof["status"] == "answered"
    assert proof["answeredAt"] is not None
    assert proof["consumedAt"] is None

    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["roles"] == {
        "current": candidate.key_id,
        "candidate": None,
        "retiring": current.key_id,
    }
    assert body["keyGeneration"] == 1

    listed = admin_client.get(f"/v1/tenants/{tenant_id}/pop-challenges")
    assert listed.status_code == 200
    record = listed.json()["challenges"][0]
    assert record["status"] == "consumed"
    assert record["consumedAt"] is not None

    # One-time: re-promoting the consumed proof fails with the now-current
    # roles and an explicit reason.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "ILLEGAL_TRANSITION"
    assert resp.json()["roles"]["candidate"] is None
    assert resp.json()["roles"]["retiring"] == current.key_id


def test_promote_without_proof_is_rejected_with_roles(admin_client, tenant_id, make_key):
    current, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True)
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "POP_PROOF_REQUIRED"
    assert body["roles"] == {
        "current": current.key_id,
        "candidate": candidate.key_id,
        "retiring": None,
    }
    # Roles untouched.
    assert get_roles(admin_client, tenant_id)["roles"] == body["roles"]


# --- challenge expiry and proof expiry, across two instances ----------------


def test_expired_challenge_cannot_be_answered(admin_client, tenant_id, make_key, virtual_clock):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True, ttl=60)
    resp = issue_challenge(admin_client, tenant_id)
    assert resp.status_code == 201
    challenge = resp.json()

    # Advance the shared clock through the second API instance: expiry is
    # visible cluster-wide.
    virtual_clock(61, base_url=BASE2_URL)
    sig = sign_challenge(candidate, tenant_id, challenge)
    resp = answer_challenge(admin_client, tenant_id, challenge["challengeId"], sig)
    assert resp.status_code == 410
    assert resp.json()["error"] == "POP_CHALLENGE_EXPIRED"

    listed = admin_client.get(f"/v1/tenants/{tenant_id}/pop-challenges").json()["challenges"]
    assert listed[0]["status"] == "expired"
    # The terminal status was committed together with the rejected answer:
    # re-answering reports the same expired state rather than re-opening it.
    sig = sign_challenge(candidate, tenant_id, listed[0])
    resp = answer_challenge(admin_client, tenant_id, challenge["challengeId"], sig)
    assert resp.status_code == 410
    assert resp.json()["error"] == "POP_CHALLENGE_EXPIRED"
    # Expired proof cannot promote.
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 410
    assert resp.json()["error"] == "POP_PROOF_EXPIRED"
    assert "roles" in resp.json()


def test_answered_proof_expiring_before_promote_is_rejected(
    admin_client, tenant_id, make_key, virtual_clock
):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True, ttl=60)
    prove(admin_client, tenant_id, candidate)

    virtual_clock(61)
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 410
    assert resp.json()["error"] == "POP_PROOF_EXPIRED"
    roles = get_roles(admin_client, tenant_id)["roles"]
    assert roles["candidate"] == candidate.key_id  # roles unchanged


def test_expiry_then_new_challenge_allows_promotion(
    admin_client, tenant_id, make_key, virtual_clock
):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True, ttl=60)
    first = issue_challenge(admin_client, tenant_id).json()
    virtual_clock(61)
    stale_sig = sign_challenge(candidate, tenant_id, first)
    assert answer_challenge(
        admin_client, tenant_id, first["challengeId"], stale_sig
    ).status_code == 410

    # New clock window: a fresh challenge supersedes the expired one.
    challenge = issue_challenge(admin_client, tenant_id).json()
    assert challenge["challengeId"] != first["challengeId"]
    answer_challenge(
        admin_client, tenant_id, challenge["challengeId"],
        sign_challenge(candidate, tenant_id, challenge),
    )
    assert promote(admin_client, tenant_id).status_code == 200


# --- replays ----------------------------------------------------------------


def test_challenge_answer_is_single_use(admin_client, tenant_id, make_key):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True, ttl=60)
    challenge = issue_challenge(admin_client, tenant_id).json()
    sig = sign_challenge(candidate, tenant_id, challenge)
    assert answer_challenge(
        admin_client, tenant_id, challenge["challengeId"], sig
    ).status_code == 200
    # Replaying the exact same proof body is rejected.
    resp = answer_challenge(admin_client, tenant_id, challenge["challengeId"], sig)
    assert resp.status_code == 409
    assert resp.json()["error"] == "POP_PROOF_DUPLICATE"


def test_consumed_proof_cannot_drive_a_second_promote(
    admin_client, tenant_id, make_key, virtual_clock
):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True, ttl=300)
    prove(admin_client, tenant_id, candidate)
    assert promote(admin_client, tenant_id).status_code == 200

    # Answering the same challenge after consumption is rejected, and the
    # proof cannot be reused for any later candidate.
    listed = admin_client.get(f"/v1/tenants/{tenant_id}/pop-challenges").json()["challenges"]
    consumed = [c for c in listed if c["status"] == "consumed"][0]
    sig = sign_challenge(candidate, tenant_id, consumed)
    resp = answer_challenge(admin_client, tenant_id, consumed["challengeId"], sig)
    assert resp.status_code == 409
    assert resp.json()["error"] == "POP_PROOF_CONSUMED"


def test_issue_challenge_is_idempotent_while_open(admin_client, tenant_id, make_key):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True, ttl=60)
    first = issue_challenge(admin_client, tenant_id)
    second = issue_challenge(admin_client, tenant_id)
    assert first.status_code == second.status_code == 201
    assert first.json()["challengeId"] == second.json()["challengeId"]


# --- cross-tenant reuse -----------------------------------------------------


def test_challenge_cannot_be_answered_for_another_tenant(
    admin_client, tenant_id, make_key
):
    current, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True)
    challenge = issue_challenge(admin_client, tenant_id).json()
    sig = sign_challenge(candidate, tenant_id, challenge)

    # Submitting the same signature through another tenant's answer endpoint
    # cannot register the proof there.
    other = tenant_id + "-other"
    register_key(admin_client, other, make_key())
    register_key(admin_client, other, make_key())
    set_policy(admin_client, other, True)
    resp = answer_challenge(admin_client, other, challenge["challengeId"], sig)
    assert resp.status_code == 404
    assert resp.json() == {"error": "POP_CHALLENGE_NOT_FOUND"}


def test_proof_signature_is_tenant_and_context_bound(
    admin_client, tenant_id, make_key
):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True)
    challenge = issue_challenge(admin_client, tenant_id).json()

    # A signature built with tampered context fields must not verify.
    forged = candidate.sign(
        pop_message(
            tenant_id + "-x",
            challenge["candidateKeyId"],
            challenge["currentKeyId"],
            challenge["currentGeneration"],
            challenge["challengeId"],
            challenge["nonce"],
        )
    )
    resp = answer_challenge(admin_client, tenant_id, challenge["challengeId"], forged)
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_SIGNATURE"
    # The failed attempt leaves the challenge usable.
    assert answer_challenge(
        admin_client, tenant_id, challenge["challengeId"],
        sign_challenge(candidate, tenant_id, challenge),
    ).status_code == 200


def test_wrong_key_signature_is_bad_signature_and_consumes_nothing(
    admin_client, tenant_id, make_key
):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    other = make_key()
    set_policy(admin_client, tenant_id, True)
    challenge = issue_challenge(admin_client, tenant_id).json()
    sig = sign_challenge(other, tenant_id, challenge)
    resp = answer_challenge(admin_client, tenant_id, challenge["challengeId"], sig)
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_SIGNATURE"
    # No proof registered, so promote stays blocked.
    assert promote(admin_client, tenant_id).json()["error"] == "POP_PROOF_REQUIRED"


# --- role / generation changes invalidate old proofs ------------------------


def test_role_change_via_policy_off_rotation_invalidates_old_challenge(
    admin_client, tenant_id, make_key
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    set_policy(admin_client, tenant_id, True)
    challenge = issue_challenge(admin_client, tenant_id).json()
    assert challenge["currentGeneration"] == 0

    # Operator rotates while the policy is disabled (legacy path).
    set_policy(admin_client, tenant_id, False)
    assert promote(admin_client, tenant_id).status_code == 200  # k2 current, k1 retiring
    retire(admin_client, tenant_id)
    k3 = make_key()
    register_key(admin_client, tenant_id, k3)  # new candidate
    set_policy(admin_client, tenant_id, True)

    # The old challenge's candidate/current/generation no longer exist; the
    # stored signature cannot pass the context check.
    sig = sign_challenge(k2, tenant_id, challenge)
    resp = answer_challenge(admin_client, tenant_id, challenge["challengeId"], sig)
    assert resp.status_code == 409
    assert resp.json()["error"] == "POP_PROOF_MISMATCH"
    assert resp.json()["roles"]["candidate"] == k3.key_id
    assert resp.json()["roles"]["current"] == k2.key_id
    listed = admin_client.get(f"/v1/tenants/{tenant_id}/pop-challenges").json()["challenges"]
    assert [c["status"] for c in listed] == ["expired"]

    # Only a fresh proof for the actual candidate (k3) unlocks promotion.
    assert promote(admin_client, tenant_id).json()["error"] == "POP_PROOF_REQUIRED"
    prove(admin_client, tenant_id, k3)
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200
    assert resp.json()["keyGeneration"] == 2


# --- concurrency: exactly one promotion succeeds ----------------------------


def _race_promote(tenant_id, count=4):
    async def run():
        async with httpx.AsyncClient(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as a:
            async with httpx.AsyncClient(base_url=BASE2_URL, headers=ADMIN_HEADERS, timeout=30.0) as b:
                clients = [a, b]
                return await asyncio.gather(*[
                    clients[i % 2].post(f"/v1/tenants/{tenant_id}/keys/promote")
                    for i in range(count)
                ])

    return asyncio.run(run())


def test_concurrent_promote_with_single_proof_succeeds_once(
    admin_client, tenant_id, make_key
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    set_policy(admin_client, tenant_id, True, ttl=300)
    prove(admin_client, tenant_id, k2)

    responses = _race_promote(tenant_id)
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1, statuses
    assert statuses.count(409) == 3, statuses
    for resp in responses:
        if resp.status_code == 409:
            body = resp.json()
            assert body["error"] == "ILLEGAL_TRANSITION"
            assert body["roles"] == {
                "current": k2.key_id,
                "candidate": None,
                "retiring": k1.key_id,
            }
    roles = get_roles(admin_client, tenant_id)["roles"]
    assert roles == {"current": k2.key_id, "candidate": None, "retiring": k1.key_id}
    listed = admin_client.get(f"/v1/tenants/{tenant_id}/pop-challenges").json()["challenges"]
    assert [c["status"] for c in listed] == ["consumed"]


def test_concurrent_answer_of_one_challenge_registers_one_proof(
    admin_client, tenant_id, make_key
):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True, ttl=300)
    challenge = issue_challenge(admin_client, tenant_id).json()
    sig = sign_challenge(candidate, tenant_id, challenge)

    async def run():
        async with httpx.AsyncClient(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as a:
            async with httpx.AsyncClient(base_url=BASE2_URL, headers=ADMIN_HEADERS, timeout=30.0) as b:
                clients = [a, b]
                return await asyncio.gather(*[
                    clients[i % 2].post(
                        f"/v1/tenants/{tenant_id}/pop-challenges/{challenge['challengeId']}/answer",
                        json={"signature": sig},
                    )
                    for i in range(4)
                ])

    responses = asyncio.run(run())
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1, statuses
    assert statuses.count(409) == 3, statuses
    assert all(r.json().get("error") == "POP_PROOF_DUPLICATE"
               for r in responses if r.status_code == 409)


# --- authentication, tenant isolation, retired-key rejection, receipts ------


def test_pop_endpoints_require_admin_scope(tenant_id, make_key):
    current, candidate = make_key(), make_key()
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        url = f"/v1/tenants/{tenant_id}/policy"
        assert client.put(url, json={"popRequired": True}).status_code == 401
        assert client.put(
            url, json={"popRequired": True},
            headers={"Authorization": "Bearer nope"},
        ).status_code == 401
        assert client.put(
            url, json={"popRequired": True}, headers=GATEWAY_HEADERS
        ).status_code == 403
        assert client.post(
            f"/v1/tenants/{tenant_id}/pop-challenges", headers=GATEWAY_HEADERS
        ).status_code == 403


def test_clock_control_plane_is_admin_only_and_disabled_by_default(tenant_id):
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        resp = client.post("/internal/clock/advance", json={"seconds": 1})
        assert resp.status_code in (401, 404)
        if resp.status_code == 401:  # control plane enabled on this deployment
            assert client.post(
                "/internal/clock/advance", json={"seconds": 1}, headers=GATEWAY_HEADERS
            ).status_code == 403
            assert client.post(
                "/internal/clock/advance", json={"seconds": 1}, headers=ADMIN_HEADERS
            ).status_code == 200
            client.post("/internal/clock/reset", headers=ADMIN_HEADERS)


def test_retired_key_still_rejected_and_receipts_rules_unchanged(
    admin_client, gateway_client, tenant_id, make_key
):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    set_policy(admin_client, tenant_id, True, ttl=300)
    prove(admin_client, tenant_id, k2)
    promote(admin_client, tenant_id)
    body = b"cold-chain-reading"
    # Retiring key still verifies and creates a receipt.
    assert submit(gateway_client, tenant_id, k1.key_id, k1.sign(body), body).status_code == 202
    receipts = admin_client.get(f"/v1/tenants/{tenant_id}/receipts").json()["receipts"]
    assert len(receipts) == 1 and receipts[0]["keyId"] == k1.key_id
    retire(admin_client, tenant_id)
    resp = submit(gateway_client, tenant_id, k1.key_id, k1.sign(body), body)
    assert resp.status_code == 410
    assert resp.json() == {"error": "KEY_RETIRED"}
    # No new receipt on rejection.
    receipts = admin_client.get(f"/v1/tenants/{tenant_id}/receipts").json()["receipts"]
    assert len(receipts) == 1


def test_unknown_challenge_id_is_404_and_body_validated(admin_client, tenant_id, make_key):
    _, candidate = _setup_candidate(admin_client, tenant_id, make_key)
    set_policy(admin_client, tenant_id, True)
    resp = answer_challenge(admin_client, tenant_id, "not-a-uuid", "AAAA")
    assert resp.status_code == 404
    assert resp.json() == {"error": "POP_CHALLENGE_NOT_FOUND"}

    challenge = issue_challenge(admin_client, tenant_id).json()
    for bad in ("!!!", "AAAA", "AA=="):
        resp = answer_challenge(admin_client, tenant_id, challenge["challengeId"], bad)
        assert resp.status_code == 400
        assert resp.json()["error"] == "BAD_SIGNATURE"
