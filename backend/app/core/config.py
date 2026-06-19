"""Configuration + .env loading for the Continue-with-Google feature.

Stdlib only -- no python-dotenv dependency. This module:

1. Loads a repo-root `.env` file (if present) into ``os.environ`` so a local
   developer can keep their Google credentials in one git-ignored file.
2. Exposes the Google OAuth settings and an ``is_google_configured()`` gate.

Design notes (production posture):
- **Real environment variables always win** over ``.env`` values. A container,
  CI runner, or hosting platform injects config through the real environment;
  we never let a stale committed-by-mistake ``.env`` override it.
- **Importing this module is non-fatal.** A missing or unreadable ``.env`` is
  ignored, and absent credentials simply make ``is_google_configured()`` return
  ``False`` -- the app still boots and the password flow is unaffected.
- **No secret is hardcoded here.** Everything comes from the environment.
"""

import logging
import os

logger = logging.getLogger(__name__)

# Repo root: climb from backend/app/core/config.py up three levels to the
# directory that holds `.env` (resolved at import time, CWD-independent).
_BASE_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "..")
_ENV_PATH = os.path.join(_BASE_DIR, ".env")


def _load_dotenv(path: str) -> None:
    """Seed ``os.environ`` from a minimal ``KEY=VALUE`` ``.env`` file.

    Ignores blank lines and ``#`` comments, strips surrounding quotes, and only
    sets keys that are NOT already present in the environment (real env vars
    take precedence). A missing or unreadable file is silently skipped so a
    fresh clone with no ``.env`` still starts cleanly.
    """
    if not os.path.exists(path):
        return
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, value = line.partition("=")
                key = key.strip()
                value = value.strip().strip('"').strip("'")
                if key and key not in os.environ:
                    os.environ[key] = value
    except OSError as exc:
        # A broken/unreadable .env must never crash startup -- log and move on.
        logger.warning("Could not read .env at %s: %s", path, exc)


_load_dotenv(_ENV_PATH)

# --- Google OAuth settings (all sourced from the environment) ----------------
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "")
GOOGLE_REDIRECT_URI = os.environ.get(
    "GOOGLE_REDIRECT_URI", "http://localhost:3001/auth/google/callback"
)

# Network timeout (seconds) for the OIDC discovery + token-exchange calls, so a
# slow/hung Google endpoint cannot pin a worker indefinitely.
OAUTH_HTTP_TIMEOUT = float(os.environ.get("OAUTH_HTTP_TIMEOUT", "10"))


def is_google_configured() -> bool:
    """Return True only when both the client id and secret are present.

    The login route uses this to decide whether to start the real OAuth flow
    or render the friendly "not configured" page.
    """
    return bool(GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET)
