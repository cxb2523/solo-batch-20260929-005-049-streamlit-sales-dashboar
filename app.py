"""Single-page auth shell.

app.py only renders the login page and the top status bar; every
judgement, session and credential decision is delegated to the auth
library. Run with: uvicorn app:app --port 8000
"""
from __future__ import annotations

from pathlib import Path

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from auth import check_login, credentials as credentials_view, current_user, logout
from auth.service import captcha_challenge, retry_migration, status as auth_status
from auth.session import MAX_AGE, SESSION_COOKIE

templates = Jinja2Templates(directory=str(Path(__file__).parent / "templates"))
app = FastAPI(title="Auth State Machine")


def _render_login(request: Request, error: str = "", challenge: dict | None = None) -> HTMLResponse:
    challenge = challenge or captcha_challenge()
    return templates.TemplateResponse(
        request,
        "login.html",
        {"challenge": challenge, "error": error, "board": auth_status(), "credentials": credentials_view()},
    )


@app.get("/", response_class=HTMLResponse)
def index(request: Request) -> HTMLResponse:
    token = request.cookies.get(SESSION_COOKIE)
    user = current_user(token)
    if user is None:
        return _render_login(request)
    return templates.TemplateResponse(
        request, "home.html", {"user": user, "board": auth_status(), "credentials": credentials_view()}
    )


@app.post("/login")
def login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    captcha: str = Form(""),
    captcha_token: str = Form(""),
):
    result = check_login(username, password, captcha_token, captcha)
    if not result["ok"]:
        return _render_login(request, error=result["error"])
    if result.get("degraded"):
        # Authenticated, but migration fell back: stay on login page with
        # the status bar offering an in-place retry.
        return _render_login(request, error="凭据迁移失败，已回退 pkl，可在状态条原地重试")
    response = RedirectResponse(url="/", status_code=303)
    response.set_cookie(
        SESSION_COOKIE,
        result["token"],
        max_age=MAX_AGE,
        httponly=True,
        samesite="lax",
        path="/",
    )
    return response


@app.post("/retry-migration")
def retry(request: Request):
    retry_migration()
    return RedirectResponse(url="/", status_code=303)


@app.post("/logout")
def do_logout(request: Request):
    logout(request.cookies.get(SESSION_COOKIE))
    response = RedirectResponse(url="/", status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


@app.get("/auth/status")
def get_status():
    return auth_status()
