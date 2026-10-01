"""Acceptance-only virtual clock control, shared by every API instance.

The offset lives in the database (service_clock), so two API instances observe
the same virtual time. The whole control plane returns 404 unless
CLOCK_CONTROL_ENABLED is set, which keeps it out of production deployments.
"""
from fastapi import APIRouter, Header
from pydantic import BaseModel

from . import db
from .auth import validate_token
from .config import CLOCK_CONTROL_ENABLED
from .errors import ApiError

router = APIRouter(tags=["internal"], include_in_schema=False)


class ClockAdvanceRequest(BaseModel):
    seconds: int


async def _require_admin(authorization: str | None) -> None:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise ApiError(401, "UNAUTHORIZED", headers={"WWW-Authenticate": "Bearer"})
    scopes = validate_token(authorization[7:].strip())
    if "keys:manage" not in scopes:
        raise ApiError(403, "FORBIDDEN")


def _ensure_enabled() -> None:
    if not CLOCK_CONTROL_ENABLED:
        # Intentionally indistinguishable from a missing route.
        raise ApiError(404, "NOT_FOUND")


@router.post("/internal/clock/advance")
async def advance_clock(
    body: ClockAdvanceRequest,
    authorization: str | None = Header(default=None),
):
    _ensure_enabled()
    await _require_admin(authorization)
    if body.seconds < 0:
        raise ApiError(400, "BAD_REQUEST", field="seconds")
    async with db.pool.acquire() as conn:
        offset = await conn.fetchval(
            "UPDATE service_clock SET offset_sec = offset_sec + $1"
            " WHERE id = 1 RETURNING offset_sec",
            body.seconds,
        )
    return {"offsetSeconds": offset}


@router.post("/internal/clock/reset")
async def reset_clock(authorization: str | None = Header(default=None)):
    _ensure_enabled()
    await _require_admin(authorization)
    async with db.pool.acquire() as conn:
        await conn.execute("UPDATE service_clock SET offset_sec = 0 WHERE id = 1")
    return {"offsetSeconds": 0}
