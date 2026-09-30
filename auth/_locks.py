"""Advisory file locks for the credential migration.

POSIX uses :mod:`fcntl` as required; on Windows ``msvcrt.locking`` provides
the equivalent process-level exclusive lock. The lock is only used to elect a
single migrator -- truth uniqueness additionally relies on a version number
inside credentials.toml plus atomic ``os.replace``.
"""

from __future__ import annotations

import os
from types import TracebackType
from typing import Self

try:  # POSIX
    import fcntl

    _HAVE_FCNTL = True
except ImportError:  # Windows
    fcntl = None  # type: ignore[assignment]
    import msvcrt

    _HAVE_FCNTL = False


class FileLock:
    """Exclusive whole-file lock, held for the lifetime of the context."""

    def __init__(self, path: str) -> None:
        self._path = path
        self._fh: object | None = None

    if _HAVE_FCNTL:

        def _lock(self) -> None:
            fd = self._fh.fileno()
            fcntl.flock(fd, fcntl.LOCK_EX)  # type: ignore[union-attr]

        def _unlock(self) -> None:
            fd = self._fh.fileno()
            fcntl.flock(fd, fcntl.LOCK_UN)  # type: ignore[union-attr]

    else:

        def _lock(self) -> None:
            # Lock one byte past EOF: stable for the life of the handle.
            self._fh.seek(0, os.SEEK_END)
            msvcrt.locking(self._fh.fileno(), msvcrt.LK_LOCK, 1)
            self._fh.seek(0)

        def _unlock(self) -> None:
            self._fh.seek(0, os.SEEK_END)
            try:
                msvcrt.locking(self._fh.fileno(), msvcrt.LK_UNLCK, 1)
            except OSError:
                pass
            self._fh.seek(0)

    def __enter__(self) -> Self:
        directory = os.path.dirname(os.path.abspath(self._path))
        os.makedirs(directory, exist_ok=True)
        self._fh = open(self._path, "a+b")
        try:
            self._lock()
        except OSError:
            self._fh.close()
            self._fh = None
            raise
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._fh is not None:
            try:
                self._unlock()
            finally:
                self._fh.close()
                self._fh = None
