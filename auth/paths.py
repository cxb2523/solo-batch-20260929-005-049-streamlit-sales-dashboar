"""Filesystem locations used by the auth package.

Overridable via environment variables so verify_auth.py can run each
scenario in an isolated directory without touching the real config.
"""
from __future__ import annotations

import os
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent

CONFIG_DIR = Path(os.environ.get("AUTH_CONFIG_DIR", _ROOT / "config"))
TOML_PATH = CONFIG_DIR / "credentials.toml"
PKL_PATH = Path(os.environ.get("AUTH_PKL_PATH", _ROOT / "hashed_pw.pkl"))
SECRET_PATH = CONFIG_DIR / "secret.key"
LOCK_PATH = CONFIG_DIR / "credentials.lock"


def ensure_config_dir() -> Path:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    return CONFIG_DIR
