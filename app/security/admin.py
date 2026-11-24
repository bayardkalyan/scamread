"""Admin token check for write endpoints.

Admin endpoints are disabled unless SCAMREAD_ADMIN_TOKEN is set on the server.
Send the token as:  Authorization: Bearer <token>
"""

import hmac

from fastapi import Header, HTTPException, status

from app import config


def require_admin(authorization: str | None = Header(default=None)) -> None:
    if not config.ADMIN_TOKEN:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found.")
    scheme, _, token = (authorization or "").partition(" ")
    if scheme.lower() != "bearer" or not hmac.compare_digest(
        token.strip().encode("utf-8"), config.ADMIN_TOKEN.encode("utf-8")
    ):
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED,
            "Admin token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )
