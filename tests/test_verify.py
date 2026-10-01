"""Acceptance tests for gateway message verification."""
import hashlib

import httpx

from conftest import (
    ADMIN_HEADERS,
    BASE_URL,
    promote,
    register_key,
    retire,
    submit,
)


def _receipts(admin_client, tenant_id):
    resp = admin_client.get(f"/v1/tenants/{tenant_id}/receipts")
    assert resp.status_code == 200, resp.text
    return resp.json()["receipts"]


def test_valid_signature_returns_202_and_receipt(admin_client, gateway_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"temperature=-18.5;door=closed"
    resp = submit(gateway_client, tenant_id, key.key_id, key.sign(body), body)
    assert resp.status_code == 202, resp.text
    receipt_id = resp.json()["receiptId"]
    receipts = _receipts(admin_client, tenant_id)
    assert [r["receiptId"] for r in receipts] == [receipt_id]
    assert receipts[0]["keyId"] == key.key_id
    assert receipts[0]["size"] == len(body)
    assert receipts[0]["sha256"] == hashlib.sha256(body).hexdigest()


def test_all_in_use_roles_can_verify(admin_client, gateway_client, tenant_id, make_key):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    body = b"reading"
    assert submit(gateway_client, tenant_id, k1.key_id, k1.sign(body), body).status_code == 202
    assert submit(gateway_client, tenant_id, k2.key_id, k2.sign(body), body).status_code == 202
    promote(admin_client, tenant_id)
    # k1 is now retiring and must still verify.
    assert submit(gateway_client, tenant_id, k1.key_id, k1.sign(body), body).status_code == 202


def test_retired_key_is_rejected(admin_client, gateway_client, tenant_id, make_key):
    k1, k2 = make_key(), make_key()
    register_key(admin_client, tenant_id, k1)
    register_key(admin_client, tenant_id, k2)
    promote(admin_client, tenant_id)
    body = b"reading"
    # Snapshot before the retire: still accepted.
    assert submit(gateway_client, tenant_id, k1.key_id, k1.sign(body), body).status_code == 202
    retire(admin_client, tenant_id)
    # Snapshot after the retire: KEY_RETIRED.
    resp = submit(gateway_client, tenant_id, k1.key_id, k1.sign(body), body)
    assert resp.status_code == 410
    assert resp.json()["error"] == "KEY_RETIRED"


def test_unknown_key_id(admin_client, gateway_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"x"
    resp = submit(gateway_client, tenant_id, "no-such-key", key.sign(body), body)
    assert resp.status_code == 404
    assert resp.json() == {"error": "KEY_UNKNOWN"}


def test_cross_tenant_key_is_indistinguishable_from_unknown(
    admin_client, gateway_client, tenant_id, make_key
):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"cross"
    sig = key.sign(body)
    cross = submit(gateway_client, tenant_id + "-other", key.key_id, sig, body)
    unknown = submit(gateway_client, tenant_id, "no-such-key", sig, body)
    assert cross.status_code == 404
    assert unknown.status_code == 404
    assert cross.json() == unknown.json() == {"error": "KEY_UNKNOWN"}


def test_bad_signature_creates_no_receipt(admin_client, gateway_client, tenant_id, make_key):
    key, other = make_key(), make_key()
    register_key(admin_client, tenant_id, key)
    body = b"payload"
    forged = other.sign(body)  # well-formed Ed25519 signature, wrong key
    resp = submit(gateway_client, tenant_id, key.key_id, forged, body)
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_SIGNATURE"
    assert _receipts(admin_client, tenant_id) == []


def test_tampered_body_is_rejected(admin_client, gateway_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    resp = submit(gateway_client, tenant_id, key.key_id, key.sign(b"original"), b"tampered")
    assert resp.status_code == 400
    assert _receipts(admin_client, tenant_id) == []


def test_empty_body_is_allowed(admin_client, gateway_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    resp = submit(gateway_client, tenant_id, key.key_id, key.sign(b""), b"")
    assert resp.status_code == 202


def test_size_limit(admin_client, gateway_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = bytes(1_048_576)  # exactly the limit: accepted
    assert submit(gateway_client, tenant_id, key.key_id, key.sign(body), body).status_code == 202
    over = bytes(1_048_577)  # one byte over: rejected
    resp = submit(gateway_client, tenant_id, key.key_id, key.sign(over), over)
    assert resp.status_code == 413
    assert resp.json()["error"] == "PAYLOAD_TOO_LARGE"


def test_verify_requires_a_valid_token(admin_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    body = b"data"
    headers = {"X-Tenant-Id": tenant_id, "X-Key-Id": key.key_id, "X-Signature": key.sign(body)}
    with httpx.Client(base_url=BASE_URL, timeout=30.0) as client:
        assert client.post("/v1/verify", content=body, headers=headers).status_code == 401
        assert client.post(
            "/v1/verify", content=body, headers={**headers, "Authorization": "Bearer nope"}
        ).status_code == 401
        # The admin token also carries the verify scope.
        assert client.post(
            "/v1/verify", content=body, headers={**headers, **ADMIN_HEADERS}
        ).status_code == 202


def test_missing_headers_rejected(admin_client, gateway_client, tenant_id, make_key):
    key = make_key()
    register_key(admin_client, tenant_id, key)
    resp = gateway_client.post("/v1/verify", content=b"x")
    assert resp.status_code == 400
    assert resp.json()["error"] == "BAD_REQUEST"
