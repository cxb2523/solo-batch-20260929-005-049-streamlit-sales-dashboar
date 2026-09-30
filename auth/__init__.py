"""Reusable, UI-agnostic authentication package.

Public surface -- exactly four entry points::

    auth.check_login(...)        validate credentials & drive the state machine
    auth.logout(session)         end the session
    auth.current_user(session)   User | None
    auth.credentials(base_dir)   CredentialsSnapshot | None

``LoginResult`` / ``Stage`` / ``User`` / ``CredentialsSnapshot`` are the data
contracts returned by those entry points. Only the Python standard library
and the argon2 password hashing library are imported; this package never
imports a page or rendering module.
"""

from __future__ import annotations

from ._service import check_login, credentials, current_user, logout
from ._states import (
    CredentialsSnapshot,
    LoginResult,
    Stage,
    User,
)

__all__ = [
    "check_login",
    "logout",
    "current_user",
    "credentials",
]
