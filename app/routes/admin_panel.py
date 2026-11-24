"""The admin panel page and its login/logout/password endpoints."""

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app import config
from app.routes.web import render
from app.security.admin import CSRF_HEADER, SESSION_COOKIE, require_admin
from app.services import admin_auth

router = APIRouter(include_in_schema=False)

NO_STORE = {"Cache-Control": "no-store", "X-Robots-Tag": "noindex, nofollow"}


@router.api_route("/admin", methods=["GET", "HEAD"], response_class=HTMLResponse)
def admin_page() -> HTMLResponse:
    return HTMLResponse(render("admin.html"), headers=NO_STORE)


class LoginIn(BaseModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=200)


class PasswordIn(BaseModel):
    current_password: str = Field(min_length=1, max_length=200)
    new_password: str = Field(min_length=1, max_length=200)


def _client_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _check_header(request: Request) -> None:
    if request.headers.get(CSRF_HEADER) != "1":
        raise HTTPException(403, "Missing admin header.")


@router.post("/admin/api/login")
def login(payload: LoginIn, request: Request, response: Response) -> dict:
    _check_header(request)
    key = _client_key(request)
    wait = admin_auth.limiter.retry_after(key)
    if wait:
        raise HTTPException(
            429,
            f"Too many wrong tries. Please wait {max(1, wait // 60)} minute(s).",
            headers={"Retry-After": str(wait)},
        )
    user = admin_auth.check_credentials(payload.username, payload.password)
    if user is None:
        admin_auth.limiter.failed(key)
        raise HTTPException(401, "Wrong username or password.")
    admin_auth.limiter.succeeded(key)
    response.set_cookie(
        SESSION_COOKIE,
        admin_auth.create_session(user),
        max_age=config.ADMIN_SESSION_DAYS * 86400,
        httponly=True,
        secure=config.IS_PRODUCTION,
        samesite="strict",
        path="/",
    )
    response.headers.update(NO_STORE)
    return {"ok": True, "username": user}


@router.post("/admin/api/logout")
def logout(request: Request, response: Response) -> dict:
    _check_header(request)
    admin_auth.end_session(request.cookies.get(SESSION_COOKIE))
    response.delete_cookie(SESSION_COOKIE, path="/", secure=config.IS_PRODUCTION, httponly=True, samesite="strict")
    return {"ok": True}


@router.get("/admin/api/me")
def me(user: str = Depends(require_admin)) -> dict:
    return {"username": user}


@router.post("/admin/api/password")
def change_password(payload: PasswordIn, request: Request, response: Response, user: str = Depends(require_admin)) -> dict:
    if user == "token":
        raise HTTPException(400, "Log in to the panel to change the password.")
    if admin_auth.check_credentials(user, payload.current_password) is None:
        raise HTTPException(401, "Your current password is not right.")
    try:
        admin_auth.set_password(user, payload.new_password)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from exc
    # All sessions were ended; give this browser a fresh one.
    response.set_cookie(
        SESSION_COOKIE,
        admin_auth.create_session(user),
        max_age=config.ADMIN_SESSION_DAYS * 86400,
        httponly=True,
        secure=config.IS_PRODUCTION,
        samesite="strict",
        path="/",
    )
    return {"ok": True}
