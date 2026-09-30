"""Credential truth: config/credentials.toml with read-only pkl fallback.

Rules enforced here:
* TOML is the single source of truth once it exists and is valid.
* hashed_pw.pkl is a read-only compatibility source, never written to.
* First successful login triggers migration via temp file + os.replace.
* Missing keys / corrupt TOML / interrupted writes keep the original file
  and fall back to pkl.
* Migration serialises on a file lock and uses a version field so waiting
  processes reuse the migrator's result instead of writing a second truth.
"""
from __future__ import annotations

import os
import pickle
import tomllib
from dataclasses import dataclass, field
from typing import Optional

import bcrypt

from . import locks, paths

# Canonical order matches hashed_pw.pkl positions from the original app.
CANONICAL_USERS = {
    "pparker": {"name": "Peter Parker"},
    "rmiller": {"name": "Rebecca Miller"},
}

SOURCE_TOML = "toml"
SOURCE_PKL = "pkl"
SOURCE_NONE = "none"


class StoreError(RuntimeError):
    pass


@dataclass
class CredentialStore:
    source: str = SOURCE_NONE
    version: int = 0
    users: dict = field(default_factory=dict)
    fallback_reason: Optional[str] = None

    # ---- loading -------------------------------------------------------
    def load(self) -> "CredentialStore":
        toml_users, toml_version = self._read_toml()
        if toml_users is not None:
            self.source = SOURCE_TOML
            self.version = toml_version
            self.users = toml_users
            self.fallback_reason = None
            return self

        pkl_users = self._read_pkl()
        if pkl_users is not None:
            self.source = SOURCE_PKL
            self.version = 0
            self.users = pkl_users
            return self

        self.source = SOURCE_NONE
        self.users = {}
        return self

    def _read_toml(self) -> tuple[Optional[dict], int]:
        if not paths.TOML_PATH.exists():
            return None, 0
        try:
            data = tomllib.load(paths.TOML_PATH.open("rb"))
        except (tomllib.TOMLDecodeError, OSError):
            self.fallback_reason = "toml_corrupt"
            return None, 0
        raw = data.get("credentials", {}).get("users")
        version = int(data.get("version", 0) or 0)
        if not isinstance(raw, dict) or not raw or version < 1:
            self.fallback_reason = "toml_missing_keys"
            return None, 0
        users: dict = {}
        for username, info in raw.items():
            if not isinstance(info, dict):
                self.fallback_reason = "toml_missing_keys"
                return None, 0
            hash_pw = info.get("hash_pw")
            name = info.get("name") or username
            if not isinstance(hash_pw, str) or not hash_pw.startswith("$2"):
                self.fallback_reason = "toml_missing_keys"
                return None, 0
            users[username] = {"name": name, "hash_pw": hash_pw}
        return users, version

    def _read_pkl(self) -> Optional[dict]:
        try:
            with paths.PKL_PATH.open("rb") as fh:
                hashes = pickle.load(fh)
        except (OSError, pickle.UnpicklingError, EOFError):
            return None
        if not isinstance(hashes, (list, tuple)) or not hashes:
            return None
        ordered = list(CANONICAL_USERS.items())
        if len(hashes) != len(ordered):
            return None
        users = {}
        for (username, meta), hash_pw in zip(ordered, hashes):
            if not isinstance(hash_pw, str) or not hash_pw.startswith("$2"):
                return None
            users[username] = {"name": meta["name"], "hash_pw": hash_pw}
        return users

    # ---- verification --------------------------------------------------
    def verify(self, username: str, password: str) -> bool:
        record = self.users.get(username)
        candidate = password.encode("utf-8")
        if record is None:
            # Constant-time dummy comparison so unknown users look like
            # wrong passwords (captcha error shares the same message too).
            bcrypt.checkpw(candidate, _DUMMY_HASH)
            return False
        try:
            return bcrypt.checkpw(candidate, record["hash_pw"].encode("utf-8"))
        except ValueError:
            return False

    # ---- migration -----------------------------------------------------
    def migrate(self) -> str:
        """Promote pkl -> toml. Returns 'migrated', 'reused' or 'fallback'.

        Safe to call from many processes: only the lock holder writes, and
        it writes only when no valid versioned TOML exists.
        """
        paths.ensure_config_dir()
        tmp: Optional[str] = None
        try:
            with locks.file_lock(timeout=15.0):
                users, version = self._read_toml()
                if users is not None:
                    self.source = SOURCE_TOML
                    self.version = version
                    self.users = users
                    self.fallback_reason = None
                    return "reused"
                # An existing but unreadable / incomplete TOML is preserved
                # verbatim: migration is refused until the file is repaired
                # or removed, and pkl keeps serving as truth.
                if paths.TOML_PATH.exists():
                    pkl_users = self._read_pkl()
                    if pkl_users is not None:
                        self.source = SOURCE_PKL
                        self.users = pkl_users
                    self.fallback_reason = self.fallback_reason or "toml_missing_keys"
                    return "fallback"
                pkl_users = self._read_pkl()
                if pkl_users is None:
                    self.fallback_reason = "no_pkl_truth"
                    return "fallback"

                delay = os.environ.get("AUTH_MIGRATE_DELAY")
                if delay:  # test hook: widens the concurrency window
                    import time as _time

                    _time.sleep(float(delay))

                next_version = max(version, 0) + 1
                tmp = self._write_atomic_toml(pkl_users, next_version)

                if os.environ.get("AUTH_FAULT") == "interrupt_after_tmp":
                    raise RuntimeError("simulated interrupted write")

                os.replace(tmp, paths.TOML_PATH)
                self.source = SOURCE_TOML
                self.version = next_version
                self.users = pkl_users
                self.fallback_reason = None
                return "migrated"
        except locks.LockTimeout:
            self.fallback_reason = "lock_timeout"
            return "fallback"
        except RuntimeError:
            # Simulated (or real) interrupted write: temp stays on disk,
            # original TOML/pkl truth is untouched -> fallback + retry.
            self.source = SOURCE_PKL if self.users else SOURCE_NONE
            self.fallback_reason = "write_interrupted"
            return "fallback"
        except OSError:
            self.source = SOURCE_PKL if self.users else SOURCE_NONE
            self.fallback_reason = "write_interrupted"
            return "fallback"
        finally:
            _ = tmp

    def _write_atomic_toml(self, users: dict, version: int) -> str:
        lines = ["version = %d" % version, "", "[credentials]", "", "[credentials.users]"]
        for username, info in users.items():
            lines.append("")
            lines.append("[credentials.users.%s]" % _quote_key(username))
            lines.append("name = %s" % _quote_str(info["name"]))
            lines.append("hash_pw = %s" % _quote_str(info["hash_pw"]))
        content = "\n".join(lines) + "\n"
        tmp_path = "%s.%d.tmp" % (paths.TOML_PATH, os.getpid())
        with open(tmp_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        return tmp_path

    # ---- introspection -------------------------------------------------
    def public_users(self) -> dict:
        return {u: {"name": info.get("name", u)} for u, info in self.users.items()}

    def stale_temp_present(self) -> bool:
        return any(paths.CONFIG_DIR.glob(os.path.basename(paths.TOML_PATH) + ".*.tmp"))


def _quote_key(key: str) -> str:
    if key.replace("_", "").isalnum() and key[0].isalpha():
        return key
    return _quote_str(key)


def _quote_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return '"%s"' % escaped


_store: Optional[CredentialStore] = None


def get_store() -> CredentialStore:
    global _store
    if _store is None:
        _store = CredentialStore().load()
    return _store


def reset_store() -> CredentialStore:
    """Test hook: rebuild the singleton after env/path changes."""
    global _store
    _store = CredentialStore().load()
    return _store


# Precomputed valid bcrypt hash used solely to equalise timing for
# unknown usernames; it corresponds to no real account.
_DUMMY_HASH = b"$2b$12$mGa2RijCw.bLbNYwYy2jXOZpAut0xaq5buGYhG51FeweGY5DsW7eK"
