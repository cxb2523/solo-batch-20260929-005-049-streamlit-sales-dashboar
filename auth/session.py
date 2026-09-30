"""Session storage locked inside the auth package.

Signed cookie token (itsdangerous), in-process revocation on logout.
"""
from __future__ import annotations

import os
import secrets as _secrets
from typing import Optional

from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from . import paths

SESSION_COOKIE = "auth_session"
MAX_AGE = 60 * 60 * 24 * 7  # 7 days


def _load_or_create_secret() -> bytes:
    paths.ensure_config_dir()
    if paths.SECRET_PATH.exists():
        value = paths.SECRET_PATH.read_text(encoding="utf-8").strip()
        if value:
            return value.encode("utf-8")
    value = _secrets.token_hex(32)
    tmp = paths.SECRET_PATH.with_suffix(".key.tmp")
    tmp.write_text(value, encoding="utf-8")
    try:
        os.replace(tmp, paths.SECRET_PATH)
    except OSError:
        if paths.SECRET_PATH.exists():
            return paths.SECRET_PATH.read_text(encoding="utf-8").strip().encode()
        raise
    return value.encode("utf-8")


_serializer: Optional[URLSafeTimedSerializer] = None
_revoked: set[str] = set()


def _serializer_instance() -> URLSafeTimedSerializer:
    global _serializer
    if _serializer is None:
        _serializer = URLSafeTimedSerializer(_load_or_create_secret(), salt="auth-session")
    return _serializer


def create_session(username: str, name: str) -> str:
    token = _serializer_instance().dumps({"u": username, "n": name})
    return token


def read_session(token: Optional[str]) -> Optional[dict]:
    if not token:
        return None
    if token in _revoked:
        return None
    try:
        data = _serializer_instance().loads(token, max_age=MAX_AGE)
    except (BadSignature, SignatureExpired):
        return None
    return {"username": data.get("u"), "name": data.get("n")}


def revoke(token: Optional[str]) -> None:
    if token:
        _revoked.add(token)
        if len(_revoked) > 10000:
            _revoked.clear()
