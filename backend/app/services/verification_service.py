"""Email-verification business logic (token issue / verify / resend).

This is the only module that touches the verification columns on the ``users``
table. The route layer in ``api/routes/auth.py`` calls these functions and
renders/redirects on the result.

Security posture (all preserved from the closed vulnerabilities):
- VULN-1 (SQL Injection): every SELECT/UPDATE here is parameterized.
- VULN-3 (Reflected XSS): the token is never reflected back to the client; the
  /verify route renders a fixed outcome message, not the token.
- VULN-7 / VULN-8: the resend entry point is reached only via ``POST
  /verify/resend``, which the existing rate-limit + CSRF middleware already
  guard. This module adds no new auth surface of its own.

Token model (stateful):
- ``secrets.token_urlsafe(32)`` (256-bit) stored raw in ``verification_token``.
- ``verification_token_expires`` is ``time.time()`` + TTL (default 1 hour).
- A successful verify clears both columns, making the link single-use.
"""

import logging
import secrets
import threading
import time

from fastapi.responses import JSONResponse

from app.db.session import get_db
from app.core import config, mailer
from app.core.security import verify_password

logger = logging.getLogger(__name__)


def start_verification(
    user_id: int, username: str, email: str, background: bool = False
) -> bool:
    """Issue a fresh token for ``user_id`` and email the verification link.

    Writes the token + expiry with a parameterized UPDATE (always synchronous,
    so the token is persisted before this returns), then sends the email.

    ``background=False`` (resend): send synchronously and return the mailer's
    success boolean, so the caller can report an accurate "sent / failed".

    ``background=True`` (signup): hand the SMTP send to a daemon thread and
    return ``True`` immediately. The SMTP handshake can take several seconds;
    doing it inline would block the signup response (and the event loop). The
    token is already in the DB, so a slow/failed send never loses state -- the
    user can resend from the login page.
    """
    token = secrets.token_urlsafe(32)
    expires = time.time() + config.EMAIL_VERIFICATION_TTL_SECONDS

    conn = get_db()
    try:
        conn.execute(
            "UPDATE users SET verification_token = ?, verification_token_expires = ? "
            "WHERE id = ?",
            [token, expires, user_id],
        )
        conn.commit()
    finally:
        conn.close()

    verify_url = f"{config.APP_BASE_URL}/verify?token={token}"

    if background:
        threading.Thread(
            target=mailer.send_verification_email,
            args=(email, username, verify_url),
            daemon=True,
        ).start()
        return True

    return mailer.send_verification_email(email, username, verify_url)


def verify_email_token(token: str) -> dict:
    """Validate a verification token and mark the account verified on success.

    Returns a dict ``{"status": <str>, "user": <dict|None>}`` where status is:
    - ``"ok"``      -- token matched and was unexpired; the row is now
                       is_verified = 1 with both token columns cleared
                       (single-use). ``user`` carries ``{id, username, email}``
                       so the route can log the user straight in.
    - ``"expired"`` -- token matched but is past its expiry; no state change.
    - ``"invalid"`` -- missing/blank token, no matching row (covers an
                       already-consumed token), or any DB error.
    """
    if not token:
        return {"status": "invalid", "user": None}

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, verification_token_expires FROM users "
            "WHERE verification_token = ?",
            [token],
        ).fetchone()
        if not row:
            return {"status": "invalid", "user": None}

        expires = row["verification_token_expires"]
        if expires is None or time.time() > float(expires):
            return {"status": "expired", "user": None}

        conn.execute(
            "UPDATE users SET is_verified = 1, verification_token = NULL, "
            "verification_token_expires = NULL WHERE id = ?",
            [row["id"]],
        )
        conn.commit()
        return {
            "status": "ok",
            "user": {
                "id": row["id"],
                "username": row["username"],
                "email": row["email"],
            },
        }
    except Exception:
        logger.exception("verify_email_token failed")
        return {"status": "invalid", "user": None}
    finally:
        conn.close()


def resend_for_credentials(username: str, password: str) -> JSONResponse:
    """Re-issue + re-send the verification email, gated on valid credentials.

    Because login is BLOCKED until verification, an unverified user has no
    session to gate on. The login page calls this with the same username +
    password the user just entered: the correct password is the authorization,
    which (a) stops anyone spamming a stranger's inbox and (b) resists username
    enumeration (a wrong username/password gets the same generic 401 as a
    failed login).

    Returns JSON for every outcome (mirrors ``auth_service.login``) so the
    login page's fetch() handler can render feedback inline.
    """
    if not username or not password:
        return JSONResponse(
            content={"error": "Invalid username or password"}, status_code=401
        )

    conn = get_db()
    try:
        row = conn.execute(
            "SELECT id, username, email, password, is_verified FROM users "
            "WHERE username = ?",
            [username],
        ).fetchone()
    finally:
        conn.close()

    if not row or not verify_password(password, row["password"]):
        return JSONResponse(
            content={"error": "Invalid username or password"}, status_code=401
        )

    if row["is_verified"]:
        return JSONResponse(
            content={
                "success": True,
                "message": "Your email is already verified. You can log in.",
            }
        )

    if start_verification(row["id"], row["username"], row["email"]):
        return JSONResponse(
            content={
                "success": True,
                "message": "Verification email sent. Check your inbox.",
            }
        )

    return JSONResponse(
        content={
            "error": "Could not send the verification email. Please try again later."
        },
        status_code=400,
    )
