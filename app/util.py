"""Strict unpadded base64url helpers."""
import base64
import binascii

from .errors import ApiError


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode_unpadded(value: str, *, error_code: str) -> bytes:
    """Decode unpadded base64url; anything else is a client error."""
    if not value or "=" in value:
        raise ApiError(400, error_code)
    padded = value + "=" * (-len(value) % 4)
    try:
        return base64.b64decode(padded.encode("ascii"), altchars=b"-_", validate=True)
    except (binascii.Error, ValueError, UnicodeEncodeError):
        raise ApiError(400, error_code) from None
