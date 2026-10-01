"""Runtime configuration from the environment."""
import os

MAX_BODY_BYTES = 1_048_576  # 1 MiB hard limit for gateway payloads

# Default lifetime (in seconds) of a pre-promotion proof-of-possession
# challenge; a tenant policy may override this.
DEFAULT_POP_CHALLENGE_TTL_SECONDS = 120


def _required(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"missing required environment variable: {name}")
    return value


def _bool(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


DATABASE_URL = _required("DATABASE_URL")
ADMIN_TOKEN = _required("ADMIN_TOKEN")
GATEWAY_TOKEN = _required("GATEWAY_TOKEN")

# The virtual clock used for challenge expiry is shared (in the database), so
# every API instance observes the same time; the control plane that lets an
# acceptance run advance it is disabled unless explicitly switched on.
CLOCK_CONTROL_ENABLED = _bool("CLOCK_CONTROL_ENABLED", False)
