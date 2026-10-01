"""Black-box acceptance fixtures: the API under test is reached over HTTP."""
import base64
import hashlib
import os
import uuid

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

BASE_URL = os.environ.get("API_BASE_URL", "http://localhost:8000").rstrip("/")
BASE2_URL = os.environ.get("API_BASE2_URL", "http://localhost:8001").rstrip("/")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "dev-admin-token")
GATEWAY_TOKEN = os.environ.get("GATEWAY_TOKEN", "dev-gateway-token")

ADMIN_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
GATEWAY_HEADERS = {"Authorization": f"Bearer {GATEWAY_TOKEN}"}


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


# Wire contract for proof-of-possession signatures; mirrors the canonical
# message built by the service.
def pop_message(tenant_id, candidate_id, current_id, generation, challenge_id, nonce_b64):
    return (
        b"coldchain-pop-v1"
        + f"\ntenant={tenant_id}".encode()
        + f"\ncandidate={candidate_id}".encode()
        + f"\ncurrent={current_id}".encode()
        + f"\ngeneration={generation}".encode()
        + f"\nchallenge={challenge_id}".encode()
        + f"\nnonce={nonce_b64}".encode()
    )


class TenantKey:
    """An Ed25519 keypair identified by a key id."""

    def __init__(self, key_id: str):
        self.key_id = key_id
        self._private = Ed25519PrivateKey.generate()
        self.public_key_b64 = b64url(self._private.public_key().public_bytes_raw())

    def sign(self, body: bytes) -> str:
        return b64url(self._private.sign(body))


@pytest.fixture()
def admin_client():
    with httpx.Client(base_url=BASE_URL, headers=ADMIN_HEADERS, timeout=30.0) as client:
        yield client


@pytest.fixture()
def admin_client2():
    with httpx.Client(base_url=BASE2_URL, headers=ADMIN_HEADERS, timeout=30.0) as client:
        yield client


@pytest.fixture()
def gateway_client():
    with httpx.Client(base_url=BASE_URL, headers=GATEWAY_HEADERS, timeout=30.0) as client:
        yield client


@pytest.fixture()
def gateway_client2():
    with httpx.Client(base_url=BASE2_URL, headers=GATEWAY_HEADERS, timeout=30.0) as client:
        yield client


@pytest.fixture()
def tenant_id():
    return f"t-{uuid.uuid4().hex[:16]}"


@pytest.fixture()
def make_key():
    def _make(key_id: str | None = None) -> TenantKey:
        return TenantKey(key_id or f"k-{uuid.uuid4().hex[:12]}")

    return _make


def _clock_reset(base_url: str = BASE_URL):
    return httpx.post(f"{base_url}/internal/clock/reset", headers=ADMIN_HEADERS, timeout=5.0)


@pytest.fixture(autouse=True)
def _reset_virtual_clock():
    """Keep the shared virtual clock at zero around every test when the
    control plane is exposed; deployments without it run unchanged."""
    try:
        resp = _clock_reset()
    except httpx.HTTPError:
        resp = None
    yield
    if resp is not None and resp.status_code == 200:
        _clock_reset()


@pytest.fixture()
def virtual_clock():
    """Advance the shared virtual clock. Skips when the control plane is off."""
    try:
        resp = _clock_reset()
    except httpx.HTTPError:
        pytest.skip("clock control plane unavailable")
    if resp.status_code == 404:
        pytest.skip("clock control plane disabled (set CLOCK_CONTROL_ENABLED=1)")
    assert resp.status_code == 200, resp.text

    def _advance(seconds: int, base_url: str = BASE_URL):
        r = httpx.post(
            f"{base_url}/internal/clock/advance",
            headers=ADMIN_HEADERS,
            json={"seconds": seconds},
            timeout=10.0,
        )
        assert r.status_code == 200, r.text
        return r.json()["offsetSeconds"]

    return _advance


def register_key(client, tenant_id, key):
    return client.post(
        f"/v1/tenants/{tenant_id}/keys",
        json={"keyId": key.key_id, "publicKey": key.public_key_b64},
    )


def promote(client, tenant_id):
    return client.post(f"/v1/tenants/{tenant_id}/keys/promote")


def retire(client, tenant_id):
    return client.post(f"/v1/tenants/{tenant_id}/keys/retire")


def revoke(client, tenant_id, key_id):
    return client.post(f"/v1/tenants/{tenant_id}/keys/{key_id}/revoke")


def get_roles(client, tenant_id):
    resp = client.get(f"/v1/tenants/{tenant_id}/keys")
    assert resp.status_code == 200, resp.text
    return resp.json()


def set_policy(client, tenant_id, pop_required, ttl=None):
    body = {"popRequired": pop_required}
    if ttl is not None:
        body["challengeTtlSeconds"] = ttl
    return client.put(f"/v1/tenants/{tenant_id}/policy", json=body)


def issue_challenge(client, tenant_id):
    return client.post(f"/v1/tenants/{tenant_id}/pop-challenges")


def answer_challenge(client, tenant_id, challenge_id, signature):
    return client.post(
        f"/v1/tenants/{tenant_id}/pop-challenges/{challenge_id}/answer",
        json={"signature": signature},
    )


def sign_challenge(key, tenant_id, challenge):
    message = pop_message(
        tenant_id,
        challenge["candidateKeyId"],
        challenge["currentKeyId"],
        challenge["currentGeneration"],
        challenge["challengeId"],
        challenge["nonce"],
    )
    return key.sign(message)


def prove(admin_client, tenant_id, candidate_key):
    """Issue a challenge and register a proof with the candidate key."""
    resp = issue_challenge(admin_client, tenant_id)
    assert resp.status_code == 201, resp.text
    challenge = resp.json()
    answer = answer_challenge(
        admin_client, tenant_id, challenge["challengeId"],
        sign_challenge(candidate_key, tenant_id, challenge),
    )
    assert answer.status_code == 200, answer.text
    return challenge, answer.json()


def submit(client, tenant_id, key_id, signature, body):
    return client.post(
        "/v1/verify",
        content=body,
        headers={
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": key_id,
            "X-Signature": signature,
        },
    )


# Wire contract for v2 verification signatures; mirrors the canonical message
# built by the service (domain + tenant + key + message id + body digest).
def v2_message(tenant_id, key_id, message_id, body):
    return (
        f"coldchain-verify-v2\n"
        f"tenant={tenant_id}\n"
        f"key={key_id}\n"
        f"message={message_id}\n"
        f"body_sha256={hashlib.sha256(body).hexdigest()}"
    ).encode("ascii")


def v2_sign(key, tenant_id, key_id, message_id, body) -> str:
    return key.sign(v2_message(tenant_id, key_id, message_id, body))


def submit_v2(client, tenant_id, key_id, message_id, signature, body):
    return client.post(
        "/v1/verify",
        content=body,
        headers={
            "X-Verify-Version": "2",
            "X-Tenant-Id": tenant_id,
            "X-Key-Id": key_id,
            "X-Message-Id": message_id,
            "X-Signature": signature,
        },
    )

