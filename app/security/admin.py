"""Who may use the admin endpoints.

Two ways in:
1. The admin panel: a logged-in browser session (httpOnly cookie).
   Changes must also carry the header  X-ScamRead-Admin: 1 , which other
   websites cannot add, so they cannot make your browser change anything.
2. Scripts: the server's admin token as  Authorization: Bearer <token>.
"""

import hmac

from fastapi import HTTPException, Request, status

from app import config
from app.services import admin_auth

SESSION_COOKIE = "__Host-sr_admin" if config.IS_PRODUCTION else "sr_admin"
CSRF_HEADER = "x-scamread-admin"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


def _bearer_ok(request: Request) -> bool:
    if not config.ADMIN_TOKEN:
        return False
    scheme, _, token = (request.headers.get("authorization") or "").partition(" ")
    return scheme.lower() == "bearer" and hmac.compare_digest(
        token.strip().encode("utf-8"), config.ADMIN_TOKEN.encode("utf-8")
    )


def require_admin(request: Request) -> str:
    if _bearer_ok(request):
        return "token"

    user = admin_auth.session_user(request.cookies.get(SESSION_COOKIE))
    if user:
        if request.method not in SAFE_METHODS and request.headers.get(CSRF_HEADER) != "1":
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Missing admin header.")
        return user

    raise HTTPException(
        status.HTTP_401_UNAUTHORIZED,
        "Please log in.",
        headers={"WWW-Authenticate": "Bearer"},
    )
