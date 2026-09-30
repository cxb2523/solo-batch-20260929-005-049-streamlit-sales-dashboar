"""Cross-platform advisory file lock (Windows msvcrt / POSIX fcntl).

The lock file lives next to credentials.toml so that concurrent first
logins across processes serialise on the migration.
"""
from __future__ import annotations

import contextlib
import os
import time

from . import paths

try:
    import msvcrt  # type: ignore[import-not-found]
except ImportError:  # pragma: no cover - non-Windows
    msvcrt = None  # type: ignore[assignment]
    import fcntl  # type: ignore[import-not-found]


class LockTimeout(RuntimeError):
    pass


@contextlib.contextmanager
def file_lock(timeout: float = 15.0):
    """Acquire an exclusive byte-range lock on credentials.lock."""
    paths.ensure_config_dir()
    fh = paths.LOCK_PATH.open("a+b")
    try:
        if os.path.getsize(fh.name) == 0:
            fh.write(b"\x00")
            fh.flush()
        fh.seek(0)
        deadline = time.monotonic() + timeout
        while True:
            try:
                if msvcrt is not None:
                    msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                else:
                    fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except (BlockingIOError, OSError) as exc:
                if time.monotonic() >= deadline:
                    raise LockTimeout(str(exc)) from exc
                time.sleep(0.05)
        yield
    finally:
        with contextlib.suppress(OSError):
            fh.seek(0)
            if msvcrt is not None:
                msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()
