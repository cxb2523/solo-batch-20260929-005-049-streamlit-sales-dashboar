"""auth — login state machine library.

Public surface is exactly four callables:
    check_login(username, password, captcha_token, captcha_guess) -> dict
    logout(token) -> None
    current_user(token) -> dict | None
    credentials() -> dict

Status-bar, captcha and retry helpers are internal submodules used by the
presentation layer; the package itself never imports a web framework or
template engine.
"""
from .service import check_login, credentials, current_user, logout

__all__ = ["check_login", "logout", "current_user", "credentials"]
