"""Tests for the reusable auth package.

Covers the five required paths:
  1. pkl read (read-only compatibility source)
  2. successful first-login migration pkl -> toml
  3. wrong password (same message as a wrong captcha)
  4. corrupt toml -> keep file, fall back to pkl
  5. interrupted write -> fallback, then in-place retry succeeds

Plus a multiprocessing test: concurrent first logins elect a single migrator.
"""

from __future__ import annotations

import multiprocessing as mp
import os
import pickle
import sys
from pathlib import Path

import pytest
from argon2 import PasswordHasher

import auth
from auth import _store

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FAST_HASHER = PasswordHasher(time_cost=1, memory_cost=8192, parallelism=1)
USERNAME = "pparker"
PASSWORD = "abc123"


def _write_pkl(base: Path) -> None:
    hashed = FAST_HASHER.hash(PASSWORD)
    (base / "config").mkdir(parents=True, exist_ok=True)
    with open(base / "hashed_pw.pkl", "wb") as handle:
        pickle.dump([hashed], handle)


def _login(session, base: Path, password=PASSWORD, captcha="7", **kwargs):
    return auth.check_login(
        session, USERNAME, password, captcha, "7",
        base_dir=str(base), **kwargs
    )


@pytest.fixture
def base_dir(tmp_path: Path) -> Path:
    _write_pkl(tmp_path)
    return tmp_path


# --- 1. pkl read -----------------------------------------------------------

def test_pkl_read_is_compatibility_source(base_dir: Path) -> None:
    snap = auth.credentials(str(base_dir))
    assert snap is not None
    assert snap.source == "pkl"
    assert snap.version == 0
    assert USERNAME in snap.users

    session: dict = {}
    result = _login(session, base_dir)
    assert result.authenticated is True
    assert result.source == "toml"  # first login migrated
    user = auth.current_user(session)
    assert user is not None and user.username == USERNAME


# --- 2. successful migration ----------------------------------------------

def test_migration_success_atomic_toml(base_dir: Path) -> None:
    session: dict = {}
    result = _login(session, base_dir)
    toml_path = base_dir / "config" / "credentials.toml"
    assert result.status == "authenticated"
    assert result.source == "toml"
    assert toml_path.exists()

    text = toml_path.read_text(encoding="utf-8")
    assert "version = 1" in text
    assert "[users.pparker]" in text
    assert text.startswith("version =")  # single coherent document
    assert list(base_dir.glob("config/*.tmp")) == []
    assert list(base_dir.glob("config/credentials.toml.*.tmp")) == []

    snap = auth.credentials(str(base_dir))
    assert snap is not None and snap.source == "toml" and snap.version == 1

    # Second login uses toml directly and never rewrites it.
    mtime = toml_path.stat().st_mtime_ns
    other: dict = {}
    again = _login(other, base_dir)
    assert again.source == "toml"
    assert toml_path.stat().st_mtime_ns == mtime


# --- 3. wrong password / wrong captcha: identical message -----------------

def test_wrong_password_same_message_as_wrong_captcha(base_dir: Path) -> None:
    bad_pw = _login({}, base_dir, password="WRONG")
    assert bad_pw.authenticated is False
    assert auth.current_user({}) is None
    assert bad_pw.reason == "bad_credentials"

    bad_captcha = auth.check_login(
        {}, USERNAME, PASSWORD, "999", "7", base_dir=str(base_dir)
    )
    assert bad_captcha.authenticated is False
    assert bad_captcha.reason == "bad_captcha"

    assert bad_pw.error
    assert bad_pw.error == bad_captcha.error

    # Unknown username takes the same path and the same sentence.
    unknown = auth.check_login(
        {}, "nobody", PASSWORD, "7", "7", base_dir=str(base_dir)
    )
    assert unknown.authenticated is False
    assert unknown.error == bad_pw.error

    # No session survives the failure.
    assert auth.current_user({}) is None


# --- 4. corrupt toml: preserve file, fall back to pkl ---------------------

def test_corrupt_toml_preserved_and_falls_back(base_dir: Path) -> None:
    toml_path = base_dir / "config" / "credentials.toml"
    toml_path.parent.mkdir(parents=True, exist_ok=True)
    broken = 'version = 1\n[users.pparker\nname = "x"\n'
    toml_path.write_text(broken, encoding="utf-8")
    pkl_bytes = (base_dir / "hashed_pw.pkl").read_bytes()

    result = _login({}, base_dir)
    assert result.authenticated is True
    assert result.status == "fallback"
    assert result.source == "pkl"
    # The corrupt file is byte-for-byte preserved; no second truth is written.
    assert toml_path.read_text(encoding="utf-8") == broken
    assert (base_dir / "hashed_pw.pkl").read_bytes() == pkl_bytes
    assert result.stages[-2].state == "failed"


def test_toml_missing_keys_preserved(base_dir: Path) -> None:
    toml_path = base_dir / "config" / "credentials.toml"
    toml_path.parent.mkdir(parents=True, exist_ok=True)
    broken = 'version = 1\n[users.pparker]\nname = "x"\n'  # no password key
    toml_path.write_text(broken, encoding="utf-8")

    result = _login({}, base_dir)
    assert result.authenticated is True
    assert result.source == "pkl"
    assert toml_path.read_text(encoding="utf-8") == broken


# --- 5. interrupted write -> fallback, then retry succeeds ----------------

def test_interrupted_write_then_in_place_retry(base_dir: Path, monkeypatch) -> None:
    toml_path = base_dir / "config" / "credentials.toml"

    def boom(tmp_path, dest_path):
        raise OSError("simulated write interruption")

    monkeypatch.setattr(_store, "atomic_replace", boom)
    session: dict = {}
    result = _login(session, base_dir)
    assert result.authenticated is True
    assert result.status == "fallback"
    assert result.source == "pkl"
    assert result.reason == "toml_interrupted"
    assert not toml_path.exists()  # destination preserved (absent)
    assert list(base_dir.glob("config/*.tmp")) == []  # temp cleaned up

    # Login itself worked; retry in place with the writer healthy again.
    monkeypatch.undo()
    retried = auth.check_login(
        session, "", "", base_dir=str(base_dir), retry_migration=True
    )
    assert retried.authenticated is True
    assert retried.status == "authenticated"
    assert retried.source == "toml"
    assert toml_path.exists()
    assert auth.current_user(session).username == USERNAME

def _concurrent_worker(base: str, barrier, queue) -> None:
    # Spawn-friendly worker: rendezvous, then perform the first login.
    session: dict = {}
    barrier.wait()
    result = auth.check_login(
        session, USERNAME, PASSWORD, "7", "7", base_dir=base
    )
    queue.put((result.status, result.authenticated, result.source))


def test_concurrent_first_login_single_migrator(base_dir: Path) -> None:
    # Module-level worker is required because the spawn start method cannot
    # pickle local closures.
    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(4)
    queue = ctx.Queue()
    procs = [
        ctx.Process(
            target=_concurrent_worker,
            args=(str(base_dir), barrier, queue),
        )
        for _ in range(4)
    ]
    for proc in procs:
        proc.start()
    outcomes = [queue.get(timeout=60) for _ in range(4)]
    for proc in procs:
        proc.join(30)
        assert proc.exitcode == 0

    assert all(authenticated for _, authenticated, _ in outcomes)
    assert all(source == "toml" for _, _, source in outcomes)
    toml_path = base_dir / "config" / "credentials.toml"
    assert toml_path.exists()
    text = toml_path.read_text(encoding="utf-8")
    assert text.count("[users.") == 1
    assert list(base_dir.glob("config/*.tmp")) == []
