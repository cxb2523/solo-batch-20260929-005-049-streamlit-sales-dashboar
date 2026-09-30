"""Session handling and the public authentication state machine.

Public surface (re-exported from :mod:`auth`):
    check_login, logout, current_user, credentials

This module deliberately imports only the Python standard library and the
argon2 password hashing library. It knows nothing about pages or rendering.
"""

from __future__ import annotations

import os
from collections.abc import MutableMapping
from typing import Any

from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError
from argon2 import PasswordHasher

from ._states import (
    AUTHENTICATED,
    CHECKING,
    CredentialsSnapshot,
    FALLBACK,
    GENERIC_LOGIN_ERROR,
    LoginResult,
    MIGRATING,
    REASON_BAD_CAPTCHA,
    REASON_BAD_CREDENTIALS,
    REASON_NO_CREDENTIALS,
    SOURCE_PKL,
    SOURCE_TOML,
    STAGE_CAPTCHA,
    STAGE_CREDENTIALS,
    STAGE_MIGRATE,
    STAGE_SESSION,
    STAGE_VERIFY,
    Stage,
    STEP_ACTIVE,
    STEP_DONE,
    STEP_FAILED,
    UNAUTHENTICATED,
    User,
)
from . import _store
from ._store import load_credentials

SESSION_KEY = "auth_user"
_HASHER = PasswordHasher()
_DEFAULT_BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _base(base_dir: str | None) -> str:
    return os.path.abspath(base_dir) if base_dir else _DEFAULT_BASE


def _fail(stages: list[Stage], status: str = UNAUTHENTICATED,
          reason: str = "", error: str = "", source: str = "") -> LoginResult:
    return LoginResult(
        status=status, authenticated=False, source=source,
        reason=reason, error=error, stages=tuple(stages),
    )


def _ok(stages: list[Stage], status: str, source: str) -> LoginResult:
    return LoginResult(
        status=status, authenticated=True, source=source,
        stages=tuple(stages),
    )


def credentials(base_dir: str | None = None) -> CredentialsSnapshot | None:
    loaded = load_credentials(_base(base_dir))
    if loaded is None:
        return None
    users = {username: name for username, (name, _hash) in loaded.record.users.items()}
    return CredentialsSnapshot(loaded.source, loaded.record.version, users)


def current_user(session: MutableMapping[str, Any]) -> User | None:
    data = session.get(SESSION_KEY)
    if isinstance(data, dict) and isinstance(data.get("username"), str):
        return User(data["username"], str(data.get("name", data["username"])))
    return None


def logout(session: MutableMapping[str, Any]) -> None:
    session.pop(SESSION_KEY, None)


def _captcha_ok(captcha: str, answer: str) -> bool:
    if answer == "" or captcha is None:
        return False
    return str(captcha).strip() == str(answer).strip()


def _password_ok(stored_hash: str, password: str) -> bool:
    try:
        return _HASHER.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError, TypeError):
        return False


def _retry_migration(session: MutableMapping[str, Any], stages: list[Stage],
                     base_dir: str) -> LoginResult:
    info = session[SESSION_KEY]
    stages.append(Stage(STAGE_SESSION, STEP_DONE, f"当前会话：{info['username']}"))
    stages.append(Stage(STAGE_MIGRATE, STEP_ACTIVE, "正在重试迁移…"))
    result = _store.migrate_to_toml(base_dir)
    if result.ok:
        stages[-1] = Stage(
            STAGE_MIGRATE, STEP_DONE,
            "迁移完成（已复用其他进程的结果）" if not result.performed
            else "迁移完成，真值已切换为 credentials.toml",
        )
        info["source"] = result.source
        if result.source == SOURCE_TOML:
            loaded = load_credentials(base_dir)
            if loaded is not None:
                info["version"] = loaded.record.version
        session[SESSION_KEY] = dict(info)
        return _ok(stages, AUTHENTICATED, result.source)
    stages[-1] = Stage(STAGE_MIGRATE, STEP_FAILED, result.error)
    return LoginResult(
        status=FALLBACK, authenticated=True, source=SOURCE_PKL,
        reason=result.reason, error=result.error, stages=tuple(stages),
    )


def check_login(
    session: MutableMapping[str, Any],
    username: str | None,
    password: str | None,
    captcha: str | None = "",
    captcha_answer: str | None = "",
    *,
    base_dir: str | None = None,
    retry_migration: bool = False,
) -> LoginResult:
    """Validate credentials and drive the auth state machine.

    Returns a :class:`LoginResult`. The user-facing ``error`` message is the
    same sentence for a bad captcha and a bad password; only the internal
    ``reason`` code distinguishes them.
    """
    base = _base(base_dir)

    # Already authenticated -> AUTHENTICATED (or MIGRATING/FALLBACK on retry).
    if isinstance(session.get(SESSION_KEY), dict):
        stages: list[Stage] = []
        if retry_migration:
            return _retry_migration(session, stages, base)
        stages.append(Stage(STAGE_SESSION, STEP_DONE, "会话有效"))
        source = str(session[SESSION_KEY].get("source", ""))
        status = FALLBACK if source == SOURCE_PKL else AUTHENTICATED
        return _ok(stages, status, source)

    stages = [
        Stage(STAGE_CREDENTIALS), Stage(STAGE_CAPTCHA),
        Stage(STAGE_VERIFY), Stage(STAGE_MIGRATE), Stage(STAGE_SESSION),
    ]

    # --- 未认证 -> 校验中 ---
    stages[0] = Stage(STAGE_CREDENTIALS, STEP_ACTIVE, "正在读取凭据来源…")
    loaded = load_credentials(base)
    if loaded is None:
        stages[0] = Stage(STAGE_CREDENTIALS, STEP_FAILED, "未找到任何凭据来源")
        return _fail(stages, reason=REASON_NO_CREDENTIALS,
                     error="服务器未配置任何登录凭据")
    source_detail = (
        "来源：config/credentials.toml" if loaded.source == SOURCE_TOML
        else "来源：hashed_pw.pkl（兼容只读源，待迁移）"
    )
    stages[0] = Stage(STAGE_CREDENTIALS, STEP_DONE, source_detail)

    # Captcha gate.
    stages[1] = Stage(STAGE_CAPTCHA, STEP_ACTIVE, "正在校验验证码…")
    if not _captcha_ok(captcha or "", captcha_answer or ""):
        stages[1] = Stage(STAGE_CAPTCHA, STEP_FAILED, "验证码未通过")
        return _fail(stages, reason=REASON_BAD_CAPTCHA,
                     error=GENERIC_LOGIN_ERROR, source=loaded.source)
    stages[1] = Stage(STAGE_CAPTCHA, STEP_DONE, "验证码通过")

    # Password gate (argon2 only).
    stages[2] = Stage(STAGE_VERIFY, STEP_ACTIVE, "正在校验用户名/口令…")
    entry = loaded.record.users.get(username or "")
    if entry is None or not _password_ok(entry[1], password or ""):
        stages[2] = Stage(STAGE_VERIFY, STEP_FAILED, "用户名/口令未通过")
        return _fail(stages, reason=REASON_BAD_CREDENTIALS,
                     error=GENERIC_LOGIN_ERROR, source=loaded.source)
    name = entry[0]
    stages[2] = Stage(STAGE_VERIFY, STEP_DONE, f"用户名/口令通过（{name}）")

    # --- 已认证 -> 迁移中 ---
    if loaded.source == SOURCE_PKL:
        stages[3] = Stage(STAGE_MIGRATE, STEP_ACTIVE, "首次登录，正在迁移凭据到 toml…")
        migration = _store.migrate_to_toml(base)
        if migration.ok:
            detail = ("迁移完成，真值已切换为 credentials.toml" if migration.performed
                      else "已复用其他进程的迁移结果")
            stages[3] = Stage(STAGE_MIGRATE, STEP_DONE, detail)
            final_source = SOURCE_TOML
            final_status: str = AUTHENTICATED
            loaded = load_credentials(base)
        else:
            # --- 迁移中 -> 回退：原文件保留，pkl 继续作为唯一真值 ---
            stages[3] = Stage(STAGE_MIGRATE, STEP_FAILED, migration.error)
            final_source = SOURCE_PKL
            final_status = FALLBACK
    else:
        stages[3] = Stage(STAGE_MIGRATE, STEP_DONE,
                          "已使用 credentials.toml，无需迁移")
        final_source = SOURCE_TOML
        final_status = AUTHENTICATED

    version = loaded.record.version if loaded is not None else 0
    stages[4] = Stage(STAGE_SESSION, STEP_DONE, "会话已建立")
    session[SESSION_KEY] = {
        "username": username,
        "name": name,
        "source": final_source,
        "version": version,
    }
    if final_status == FALLBACK:
        return LoginResult(
            status=FALLBACK, authenticated=True, source=SOURCE_PKL,
            reason=migration.reason, error=migration.error,
            stages=tuple(stages),
        )
    return _ok(stages, final_status, final_source)
