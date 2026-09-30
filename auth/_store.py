"""Credential storage: ``config/credentials.toml`` is the single truth.

``hashed_pw.pkl`` is a read-only compatibility source. The migration writes a
temporary file in the same directory and promotes it with ``os.replace``, so a
crash mid-write can never leave a half-written credentials.toml.
"""

from __future__ import annotations

import os
import pickle
import tomllib
from dataclasses import dataclass
from typing import NamedTuple

from ._locks import FileLock
from ._states import REASON_NO_CREDENTIALS, SOURCE_PKL, SOURCE_TOML

TOML_REL = os.path.join("config", "credentials.toml")
LOCK_REL = os.path.join("config", ".credentials.lock")
PKL_REL = "hashed_pw.pkl"
TMP_SUFFIX = ".tmp"

# Display names attached to the original positional pkl layout.
LEGACY_NAMES = {
    "pparker": "Peter Parker",
    "rmiller": "Rebecca Miller",
}


class MissingKeysError(ValueError):
    """The TOML document parsed but lacks required keys."""


class CredentialRecord(NamedTuple):
    version: int
    users: dict[str, tuple[str, str]]  # username -> (display name, argon2 hash)


@dataclass(frozen=True)
class LoadedCredentials:
    record: CredentialRecord
    source: str


@dataclass(frozen=True)
class MigrationResult:
    ok: bool
    performed: bool          # True only for the process that did the write
    source: str              # resulting source of truth
    reason: str = ""
    error: str = ""


def paths(base_dir: str) -> dict[str, str]:
    return {
        "base": base_dir,
        "toml": os.path.join(base_dir, TOML_REL),
        "lock": os.path.join(base_dir, LOCK_REL),
        "pkl": os.path.join(base_dir, PKL_REL),
    }


# --- read-only pkl compatibility source -----------------------------------

def read_pkl(base_dir: str) -> CredentialRecord | None:
    path = paths(base_dir)["pkl"]
    try:
        with open(path, "rb") as handle:
            data = pickle.load(handle)
    except (OSError, pickle.UnpicklingError, EOFError, AttributeError, ValueError):
        return None
    users: dict[str, tuple[str, str]] = {}
    if isinstance(data, dict):
        for username, value in data.items():
            if not isinstance(username, str):
                return None
            if isinstance(value, str):
                users[username] = (LEGACY_NAMES.get(username, username), value)
            elif isinstance(value, dict) and isinstance(value.get("password"), str):
                name = value.get("name") or username
                users[username] = (str(name), value["password"])
            else:
                return None
    elif isinstance(data, (list, tuple)):
        for index, hashed in enumerate(data):
            if not isinstance(hashed, str):
                return None
            username = tuple(LEGACY_NAMES)[index] if index < len(LEGACY_NAMES) else f"user{index}"
            users[username] = (LEGACY_NAMES.get(username, username), hashed)
    else:
        return None
    if not users:
        return None
    return CredentialRecord(0, users)


# --- toml truth -----------------------------------------------------------

def _validate(data: object) -> CredentialRecord:
    if not isinstance(data, dict) or not isinstance(data.get("users"), dict):
        raise MissingKeysError("credentials.toml missing [users] table")
    version = data.get("version", 1)
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise MissingKeysError("credentials.toml has invalid version")
    users: dict[str, tuple[str, str]] = {}
    for username, entry in data["users"].items():
        if not isinstance(username, str) or not isinstance(entry, dict):
            raise MissingKeysError(f"invalid user entry: {username!r}")
        password = entry.get("password")
        if not isinstance(password, str) or not password:
            raise MissingKeysError(f"user {username!r} missing password hash")
        name = entry.get("name") or username
        users[username] = (str(name), password)
    if not users:
        raise MissingKeysError("credentials.toml contains no users")
    return CredentialRecord(version, users)


def read_toml(path: str) -> CredentialRecord:
    with open(path, "rb") as handle:
        return _validate(tomllib.load(handle))


def load_credentials(base_dir: str) -> LoadedCredentials | None:
    """Return the live truth.

    A valid toml always wins. A missing/corrupt/keyless toml falls back to the
    read-only pkl; the broken toml itself is never modified here.
    """
    toml_path = paths(base_dir)["toml"]
    try:
        return LoadedCredentials(read_toml(toml_path), SOURCE_TOML)
    except FileNotFoundError:
        pass
    except (OSError, MissingKeysError, tomllib.TOMLDecodeError, ValueError):
        pass
    record = read_pkl(base_dir)
    if record is not None:
        return LoadedCredentials(record, SOURCE_PKL)
    return None


# --- atomic writing -------------------------------------------------------

def _dump_basic_string(value: str) -> str:
    out = ['"']
    for ch in value:
        if ch == "\\":
            out.append("\\\\")
        elif ch == '"':
            out.append('\\"')
        elif ch == "\b":
            out.append("\\b")
        elif ch == "\f":
            out.append("\\f")
        elif ch == "\n":
            out.append("\\n")
        elif ch == "\r":
            out.append("\\r")
        elif ch == "\t":
            out.append("\\t")
        elif ord(ch) < 0x20:
            out.append(f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def serialize_toml(record: CredentialRecord) -> str:
    lines = [f"version = {record.version}", ""]
    for username, (name, password) in record.users.items():
        lines.append(f"[users.{username}]")
        lines.append(f"name = {_dump_basic_string(name)}")
        lines.append(f"password = {_dump_basic_string(password)}")
        lines.append("")
    return "\n".join(lines)


def atomic_replace(tmp_path: str, dest_path: str) -> None:
    """Promote the temp file. Patched by tests to simulate a write crash."""
    os.replace(tmp_path, dest_path)


def atomic_write(path: str, record: CredentialRecord) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    tmp_path = f"{path}.{os.getpid()}{TMP_SUFFIX}"
    try:
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(serialize_toml(record))
            handle.flush()
            os.fsync(handle.fileno())
        atomic_replace(tmp_path, path)
    except BaseException:
        # An interrupted writer only ever removes its own temp file; the
        # destination (if any) is left byte-for-byte untouched.
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def _clean_stale_tmp(directory: str) -> None:
    try:
        entries = os.listdir(directory)
    except OSError:
        return
    for entry in entries:
        if entry.startswith("credentials.toml.") and entry.endswith(TMP_SUFFIX):
            try:
                os.unlink(os.path.join(directory, entry))
            except OSError:
                pass


# --- locked migration -----------------------------------------------------

def migrate_to_toml(base_dir: str) -> MigrationResult:
    """Elect one migrator with an exclusive file lock + version judgment.

    All concurrent callers end up using exactly one truth: either the winner's
    freshly written toml (``performed=True``) or the toml a competing process
    committed while the lock was held (``performed=False``, reused result).
    """
    p = paths(base_dir)
    os.makedirs(os.path.dirname(p["toml"]), exist_ok=True)
    with FileLock(p["lock"]):
        # Version judgment: a valid toml already present means another process
        # won the election; reuse its result instead of writing a second truth.
        try:
            record = read_toml(p["toml"])
            return MigrationResult(True, False, SOURCE_TOML)
        except FileNotFoundError:
            pass
        except (OSError, MissingKeysError, tomllib.TOMLDecodeError, ValueError):
            # A broken toml must be preserved: never overwrite, fall back.
            return MigrationResult(
                False, False, SOURCE_PKL,
                reason="toml_corrupt",
                error="credentials.toml 已损坏，保留原文件并继续使用 hashed_pw.pkl",
            )

        legacy = read_pkl(base_dir)
        if legacy is None:
            return MigrationResult(
                False, False, SOURCE_PKL,
                reason=REASON_NO_CREDENTIALS,
                error="未找到可用的凭据文件",
            )

        _clean_stale_tmp(os.path.dirname(p["toml"]))
        new_record = CredentialRecord(1, legacy.users)
        try:
            atomic_write(p["toml"], new_record)
            read_toml(p["toml"])  # verify the promoted document
        except (OSError, MissingKeysError, tomllib.TOMLDecodeError, ValueError) as exc:
            # Missing keys cannot happen for our own output; distinguish an
            # interrupted atomic replace from ordinary corruption.
            reason = (
                "toml_interrupted"
                if isinstance(exc, OSError)
                else "toml_corrupt"
            )
            return MigrationResult(
                False, False, SOURCE_PKL,
                reason=reason,
                error="迁移写入中断，已保留原文件并回退到 hashed_pw.pkl",
            )
        return MigrationResult(True, True, SOURCE_TOML)
