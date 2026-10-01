"""Domain error type mapped to stable JSON error bodies."""
from fastapi import Request
from fastapi.responses import JSONResponse


class ApiError(Exception):
    def __init__(self, status_code: int, code: str, headers: dict | None = None, **extra):
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.headers = headers or {}
        self.extra = extra


async def api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
    return JSONResponse(
        {"error": exc.code, **exc.extra},
        status_code=exc.status_code,
        headers=exc.headers,
    )
