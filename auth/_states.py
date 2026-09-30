"""State vocabulary shared inside the :mod:`auth` package.

Nothing in this module imports a web/rendering framework; the state machine
(unauthenticated -> checking -> authenticated -> migrating -> fallback) is
expressed as plain data so the package can be reused by any front-end.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, NamedTuple


# --- machine states -------------------------------------------------------
UNAUTHENTICATED = "unauthenticated"
CHECKING = "checking"
AUTHENTICATED = "authenticated"
MIGRATING = "migrating"
FALLBACK = "fallback"

# --- credential sources ---------------------------------------------------
SOURCE_TOML = "toml"          # config/credentials.toml is the live truth
SOURCE_PKL = "pkl"            # hashed_pw.pkl, read-only compatibility source

# --- machine stages (progress steps, in order) ----------------------------
STAGE_CREDENTIALS = "credentials"
STAGE_CAPTCHA = "captcha"
STAGE_VERIFY = "verify"
STAGE_MIGRATE = "migrate"
STAGE_SESSION = "session"

# --- machine step outcomes ------------------------------------------------
STEP_PENDING = "pending"
STEP_ACTIVE = "active"
STEP_DONE = "done"
STEP_FAILED = "failed"

# --- internal reason codes ------------------------------------------------
REASON_BAD_CAPTCHA = "bad_captcha"
REASON_BAD_CREDENTIALS = "bad_credentials"
REASON_TOML_MISSING_KEYS = "toml_missing_keys"
REASON_TOML_CORRUPT = "toml_corrupt"
REASON_TOML_INTERRUPTED = "toml_interrupted"
REASON_NO_CREDENTIALS = "no_credentials"

# Same sentence for every client-caused login failure: captcha errors and
# password errors are indistinguishable on purpose.
GENERIC_LOGIN_ERROR = "验证码或用户名/密码错误，请重试"
RETRY_MIGRATION = "retry_migration"


class Stage(NamedTuple):
    """One progress step of the authentication state machine."""

    stage: str
    state: str = STEP_PENDING
    detail: str = ""


@dataclass(frozen=True)
class User:
    username: str
    name: str


@dataclass(frozen=True)
class LoginResult:
    """Result object returned by :func:`auth.check_login`.

    ``error`` is the only message meant for end users; ``reason`` is an
    internal code used by the status strip (and tests), never a hint about
    whether the password or the captcha was wrong.
    """

    status: str
    authenticated: bool
    source: str = ""
    reason: str = ""
    error: str = ""
    stages: tuple[Stage, ...] = field(default_factory=tuple)

    def stage_map(self) -> dict[str, Stage]:
        return {stage.stage: stage for stage in self.stages}


@dataclass(frozen=True)
class CredentialsSnapshot:
    """Read-only view of the credential store handed to a front-end."""

    source: str
    version: int
    users: dict[str, str]  # username -> display name

    def usernames(self) -> tuple[str, ...]:
        return tuple(self.users)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "version": self.version,
            "users": dict(self.users),
        }
