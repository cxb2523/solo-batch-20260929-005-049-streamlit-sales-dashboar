"""Login state machine: UNVERIFIED -> CHECKING -> AUTHENTICATED
                                     -> MIGRATING -> FALLBACK.

All judgement, session handling and credential-source knowledge lives in
this module. No web framework or template engine is imported anywhere in
the auth package.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from . import captcha as _captcha
from . import session as _session
from .store import SOURCE_PKL, SOURCE_TOML, get_store

UNVERIFIED = "unverified"
CHECKING = "checking"
AUTHENTICATED = "authenticated"
MIGRATING = "migrating"
FALLBACK = "fallback"

STEPS = ["unverified", "checking", "authenticated", "migrating", "fallback"]

GENERIC_LOGIN_ERROR = "验证码或用户名/口令不正确，请重试"

STATE_LABELS = {
    UNVERIFIED: "未认证",
    CHECKING: "校验中",
    AUTHENTICATED: "已认证",
    MIGRATING: "迁移中",
    FALLBACK: "回退",
}

_SOURCE_LABELS = {SOURCE_TOML: "config/credentials.toml", SOURCE_PKL: "hashed_pw.pkl", "none": "无可用凭据"}
_FALLBACK_TEXT = {
    "toml_corrupt": "credentials.toml 已损坏，保留原文件并回退 pkl",
    "toml_missing_keys": "credentials.toml 缺少必需键，保留原文件并回退 pkl",
    "write_interrupted": "写入中断（检测到临时文件），真值未改动，已回退 pkl",
    "lock_timeout": "等待迁移文件锁超时，已回退 pkl",
    "no_pkl_truth": "无可迁移的 pkl 凭据",
}


@dataclass
class _Board:
    state: str = UNVERIFIED
    source: str = "none"
    version: int = 0
    progress: str = ""
    failure: str = ""
    migration: str = ""
    attempts: int = 0
    events: list = field(default_factory=list)

    def log(self, message: str) -> None:
        self.events.append(message)

    def snapshot(self) -> dict:
        store = get_store()
        return {
            "state": self.state,
            "state_label": STATE_LABELS[self.state],
            "source": store.source,
            "source_label": _SOURCE_LABELS.get(store.source, store.source),
            "version": store.version,
            "progress": self.progress,
            "failure": self.failure,
            "migration": self.migration,
            "attempts": self.attempts,
            "stale_tmp": store.stale_temp_present(),
            "steps": self._steps(),
            "events": list(self.events[-8:]),
        }
    # Index of the step the machine is currently standing on.
    _ACTIVE_INDEX = {
        UNVERIFIED: 0,
        CHECKING: 1,
        AUTHENTICATED: 2,
        MIGRATING: 3,
        FALLBACK: 4,
    }

    def _steps(self) -> list:
        active_index = self._ACTIVE_INDEX[self.state]
        result = []
        for index, step in enumerate(STEPS):
            if self.state == FALLBACK and index == 4:
                status = "failed"
            elif index < active_index:
                status = "done"
            elif index == active_index:
                status = "active"
            else:
                status = "pending"
            # The "fallback" step is only reachable when migration fails;
            # while travelling through migration it lights up active.
            if step == "fallback" and self.state != FALLBACK:
                status = "pending"
            result.append({"key": step, "label": STATE_LABELS[step], "status": status})
        return result


_board = _Board()


def _refresh_source_from_store() -> None:
    store = get_store()
    _board.source = store.source
    _board.version = store.version


def status() -> dict:
    """Status-bar snapshot for the single page."""
    _refresh_source_from_store()
    return _board.snapshot()


def credentials() -> dict:
    """Public credential metadata only — never the hashes."""
    store = get_store()
    return {
        "source": store.source,
        "source_label": _SOURCE_LABELS.get(store.source, store.source),
        "version": store.version,
        "users": store.public_users(),
        "fallback_reason": store.fallback_reason,
        "single_truth": store.source != SOURCE_PKL or not _toml_any_present(),
    }


def _toml_any_present() -> bool:
    from . import paths

    return paths.TOML_PATH.exists()


def captcha_challenge() -> dict:
    return _captcha.new_challenge()


def check_login(
    username: str,
    password: str,
    captcha_token: Optional[str],
    captcha_guess: Optional[str],
) -> dict:
    """Validate one login attempt; returns {ok, error, session, board}."""
    _board.attempts += 1
    _board.failure = ""
    _board.migration = ""
    _board.state = CHECKING
    _board.progress = "校验验证码与口令"
    _board.log("进入校验中")

    store = get_store()
    captcha_ok = _captcha.verify_answer(captcha_token, captcha_guess)
    if not captcha_ok:
        _board.state = UNVERIFIED
        _board.progress = ""
        _board.failure = GENERIC_LOGIN_ERROR
        _board.log("校验失败（外部统一提示）")
        return {"ok": False, "error": GENERIC_LOGIN_ERROR, "board": _board.snapshot()}

    password_ok = store.verify(username or "", password or "")
    if not password_ok:
        _board.state = UNVERIFIED
        _board.progress = ""
        _board.failure = GENERIC_LOGIN_ERROR
        _board.log("口令校验失败（外部统一提示）")
        return {"ok": False, "error": GENERIC_LOGIN_ERROR, "board": _board.snapshot()}

    user = store.users[username]
    _board.state = AUTHENTICATED
    _board.log("口令校验通过：已认证")

    if store.source == SOURCE_PKL:
        _board.state = MIGRATING
        _board.progress = "首次登录成功，pkl -> credentials.toml 原子迁移"
        _board.log("进入迁移中")
        outcome = store.migrate()
        if outcome == "migrated":
            _board.state = AUTHENTICATED
            _board.migration = "已迁移：临时文件 os.replace 为 credentials.toml（version %d）" % store.version
            _board.progress = ""
            _board.log("迁移成功，真值唯一为 toml version=%d" % store.version)
        elif outcome == "reused":
            _board.state = AUTHENTICATED
            _board.migration = "复用其它进程已完成的迁移结果（version %d）" % store.version
            _board.progress = ""
            _board.log("锁内发现 toml version=%d，直接复用" % store.version)
        else:
            _enter_fallback(store.fallback_reason or "write_interrupted")
    else:
        _board.progress = ""

    if _board.state == FALLBACK:
        return {"ok": True, "degraded": True, "session": None, "board": _board.snapshot()}

    token = _session.create_session(username, user.get("name", username))
    return {
        "ok": True,
        "session": _session.SESSION_COOKIE,
        "token": token,
        "name": user.get("name", username),
        "username": username,
        "board": _board.snapshot(),
    }


def retry_migration() -> dict:
    """In-place retry from the status bar after an interrupted/failed move."""
    store = get_store()
    _board.state = MIGRATING
    _board.failure = ""
    _board.progress = "原地重试迁移"
    _board.log("状态条触发原地重试")
    outcome = store.migrate()
    if outcome in ("migrated", "reused"):
        _board.state = AUTHENTICATED
        _board.migration = ("重试成功，复用 version %d" % store.version) if outcome == "reused" else (
            "重试迁移成功，credentials.toml version %d" % store.version
        )
        _board.progress = ""
        _board.log("重试后 toml version=%d 生效" % store.version)
    else:
        _enter_fallback(store.fallback_reason or "write_interrupted")
    return _board.snapshot()


def _enter_fallback(reason: str) -> None:
    _board.state = FALLBACK
    _board.failure = _FALLBACK_TEXT.get(reason, reason)
    _board.progress = ""
    _board.log("回退：%s" % _board.failure)


def current_user(token: Optional[str]) -> Optional[dict]:
    return _session.read_session(token)


def logout(token: Optional[str]) -> None:
    _session.revoke(token)
    _board.state = UNVERIFIED
    _board.progress = ""
    _board.failure = ""
    _board.migration = ""
    _board.log("已登出，回到未认证")
    _refresh_source_from_store()


def reset_board() -> None:
    """Test hook."""
    global _board
    _board = _Board()
