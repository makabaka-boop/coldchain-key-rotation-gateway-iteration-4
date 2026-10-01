"""Acceptance tests for the tenant key lifecycle and its concurrency invariants."""
import asyncio

import httpx

from conftest import (
    ADMIN_HEADERS,
    BASE_URL,
    GATEWAY_HEADERS,
    get_roles,
    promote,
    register_key,
    retire,
)


def test_first_key_becomes_current(admin_client, tenant_id, make_key):
    key = make_key()
    resp = register_key(admin_client, tenant_id, key)
    assert resp.status_code == 201, resp.text
    assert resp.json()["role"] == "current"
    roles = get_roles(admin_client, tenant_id)["roles"]
    assert roles == {"current": key.key_id, "candidate": None, "retiring": None}


def test_second_key_becomes_candidate(admin_client, tenant_id, make_key):
    first, second = make_key(), make_key()
    assert register_key(admin_client, tenant_id, first).status_code == 201
    resp = register_key(admin_client, tenant_id, second)
    assert resp.status_code == 201, resp.text
    assert resp.json()["role"] == "candidate"
    roles = get_roles(admin_client, tenant_id)["roles"]
    assert roles == {"current": first.key_id, "candidate": second.key_id, "retiring": None}


def test_third_key_rejected_with_authoritative_roles(admin_client, tenant_id, make_key):
    first, second, third = make_key(), make_key(), make_key()
    register_key(admin_client, tenant_id, first)
    register_key(admin_client, tenant_id, second)
    resp = register_key(admin_client, tenant_id, third)
    assert resp.status_code == 409
    body = resp.json()
    assert body["error"] == "ILLEGAL_TRANSITION"
    assert body["roles"] == {"current": first.key_id, "candidate": second.key_id, "retiring": None}


def test_full_rotation_lifecycle(admin_client, tenant_id, make_key):
    k1, k2, k3 = make_key(), make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)

    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"] == {"current": k2.key_id, "candidate": None, "retiring": k1.key_id}

    # A retiring key blocks new candidates.
    resp = register_key(admin_client, tenant_id, k3)
    assert resp.status_code == 409
    assert resp.json()["roles"]["retiring"] == k1.key_id

    resp = retire(admin_client, tenant_id)
    assert resp.status_code == 200, resp.text
    assert resp.json()["roles"]["retiring"] is None
    assert k1.key_id in get_roles(admin_client, tenant_id)["retired"]

    resp = register_key(admin_client, tenant_id, k3)
    assert resp.status_code == 201
    assert resp.json()["role"] == "candidate"

    resp = promote(admin_client, tenant_id)
    assert resp.json()["roles"] == {"current": k3.key_id, "candidate": None, "retiring": k2.key_id}
    retire(admin_client, tenant_id)
    state = get_roles(admin_client, tenant_id)
    assert state["roles"] == {"current": k3.key_id, "candidate": None, "retiring": None}
    assert set(state["retired"]) == {k1.key_id, k2.key_id}


def test_promote_without_candidate_is_409(admin_client, tenant_id, make_key):
    register_key(admin_client, tenant_id, make_key())
    resp = promote(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "ILLEGAL_TRANSITION"
    assert "roles" in resp.json()


def test_retire_without_retiring_is_409(admin_client, tenant_id, make_key):
    register_key(admin_client, tenant_id, make_key())
    resp = retire(admin_client, tenant_id)
    assert resp.status_code == 409
    assert resp.json()["error"] == "ILLEGAL_TRANSITION"


def test_duplicate_key_id_is_409(admin_client, tenant_id, make_key):
    key = make_key()
    assert register_key(admin_client, tenant_id, key).status_code == 201
    resp = register_key(admin_client, tenant_id, key)
    assert resp.status_code == 409
    assert resp.json()["error"] == "KEY_ALREADY_EXISTS"


def test_public_key_must_be_32_byte_unpadded_base64url(admin_client, tenant_id, make_key):
    key = make_key()
    for bad in ("AQID", key.public_key_b64 + "==", "!!!not-base64!!!", ""):
        resp = admin_client.post(
            f"/v1/tenants/{tenant_id}/keys",
            json={"keyId": make_key().key_id, "publicKey": bad},
        )
        assert resp.status_code == 400, bad
        assert resp.json()["error"] == "BAD_PUBLIC_KEY"


def test_authentication_and_authorization(tenant_id, make_key):
    key = make_key()
    payload = {"keyId": key.key_id, "publicKey": key.public_key_b64}
    url = f"/v1/tenants/{tenant_id}/keys"
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        assert client.post(url, json=payload).status_code == 401
        assert client.post(url, json=payload, headers={"Authorization": "Bearer nope"}).status_code == 401
        assert client.post(url, json=payload, headers=GATEWAY_HEADERS).status_code == 403
        assert client.get(url, headers=GATEWAY_HEADERS).status_code == 403
        assert client.post(url, json=payload, headers=ADMIN_HEADERS).status_code == 201


def _race_register(tenant_id, keys):
    async def run():
        async with httpx.AsyncClient(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as client:
            return await asyncio.gather(*[
                client.post(
                    f"/v1/tenants/{tenant_id}/keys",
                    json={"keyId": k.key_id, "publicKey": k.public_key_b64},
                )
                for k in keys
            ])

    return asyncio.run(run())


def test_concurrent_first_registration_keeps_single_current(admin_client, tenant_id, make_key):
    keys = [make_key() for _ in range(6)]
    responses = _race_register(tenant_id, keys)
    statuses = [r.status_code for r in responses]
    assert statuses.count(201) == 2  # exactly one current plus one candidate
    assert statuses.count(409) == 4
    roles = get_roles(admin_client, tenant_id)["roles"]
    winners = {k.key_id for k, r in zip(keys, responses) if r.status_code == 201}
    assert roles["current"] in winners
    assert roles["candidate"] in winners
    assert roles["current"] != roles["candidate"]
    assert roles["retiring"] is None


def test_concurrent_candidate_registration_keeps_single_candidate(admin_client, tenant_id, make_key):
    first = make_key()
    assert register_key(admin_client, tenant_id, first).status_code == 201
    hopefuls = [make_key() for _ in range(8)]
    responses = _race_register(tenant_id, hopefuls)
    statuses = [r.status_code for r in responses]
    assert statuses.count(201) == 1
    assert statuses.count(409) == 7
    roles = get_roles(admin_client, tenant_id)["roles"]
    assert roles["current"] == first.key_id
    assert roles["candidate"] in {k.key_id for k in hopefuls}
    assert roles["retiring"] is None


def test_concurrent_promote_is_atomic(admin_client, tenant_id, make_key):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)

    async def run():
        async with httpx.AsyncClient(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as client:
            return await asyncio.gather(*[
                client.post(f"/v1/tenants/{tenant_id}/keys/promote") for _ in range(4)
            ])

    responses = asyncio.run(run())
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1
    assert statuses.count(409) == 3
    roles = get_roles(admin_client, tenant_id)["roles"]
    assert roles == {"current": k2.key_id, "candidate": None, "retiring": k1.key_id}


def test_concurrent_retire_is_atomic(admin_client, tenant_id, make_key):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    promote(admin_client, tenant_id)

    async def run():
        async with httpx.AsyncClient(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as client:
            return await asyncio.gather(*[
                client.post(f"/v1/tenants/{tenant_id}/keys/retire") for _ in range(4)
            ])

    responses = asyncio.run(run())
    statuses = [r.status_code for r in responses]
    assert statuses.count(200) == 1
    assert statuses.count(409) == 3
    state = get_roles(admin_client, tenant_id)
    assert state["roles"]["retiring"] is None
    assert state["retired"] == [k1.key_id]
