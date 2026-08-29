"""
Shared helper for owner-only file permission enforcement, used by
core/storage.py (vault.db), sync/access_store.py (authorization store),
and sync/pqc_crypto.py (persisted signing key).

Some filesystems do not support real POSIX permission bits at all —
most commonly Windows drives mounted into WSL as DrvFs (/mnt/c, /mnt/e,
etc., unless metadata mode is enabled in /etc/wsl.conf), and FAT/exFAT
filesystems generally. On these, os.chmod() succeeds without raising but
has no real effect: every file reports a fixed mode (commonly 0o777)
regardless of what was requested. Treating that fixed, unchangeable mode
as a security violation would be both wrong (nothing was actually
exposed beyond a filesystem-wide, inherent lack of per-file permission
enforcement — the same as it would be for any file on that mount) and
would make the affected features entirely unusable for a large share of
WSL users who have their project checked out on a Windows-drive mount.

This module detects that situation once per directory, by creating a
throwaway file, chmod'ing it, and checking whether the OS reports the
requested mode back, and downgrades permission checks accordingly.
"""

import os
import stat
import tempfile
import threading

_enforcement_cache: dict[str, bool] = {}
_cache_lock = threading.Lock()


def filesystem_enforces_permissions(directory: str) -> bool:
    """
    Returns True if chmod'ing a file in `directory` to 0o600 is
    actually reflected back by stat() — i.e. the filesystem supports
    real per-file POSIX permissions. Cached per directory for the life
    of the process, since this is a filesystem-level property that
    won't change mid-run.
    """
    directory = os.path.abspath(directory)
    with _cache_lock:
        if directory in _enforcement_cache:
            return _enforcement_cache[directory]

        result = True
        try:
            fd, probe_path = tempfile.mkstemp(dir=directory, prefix=".pqvault_perm_probe_")
            try:
                os.close(fd)
                os.chmod(probe_path, 0o600)
                reported = stat.S_IMODE(os.stat(probe_path).st_mode)
                result = (reported == 0o600)
            finally:
                try:
                    os.remove(probe_path)
                except OSError:
                    pass
        except OSError:
            # Can't even probe (e.g. a read-only directory) — assume
            # enforcement is unavailable rather than risk a false
            # PermissionError on an otherwise-working setup.
            result = False

        _enforcement_cache[directory] = result
        return result


def enforce_owner_only(path: str) -> None:
    """
    Best-effort chmod to 0600. Never raises: some filesystems don't
    support it at all (see module docstring), and this is
    defense-in-depth, not the only thing standing between an attacker
    and the file's contents.
    """
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass


def check_owner_only_or_raise(path: str, context: str) -> None:
    """
    Raises PermissionError if `path` is readable or writable by group
    or other AND the containing filesystem actually supports enforcing
    that restriction. If the filesystem cannot enforce real per-file
    permissions (common on WSL DrvFs mounts and FAT/exFAT), the check
    is skipped instead of treated as a violation — there is nothing the
    caller could do differently to fix it on that filesystem, and
    hard-failing would make the feature unusable there for no actual
    security gain.
    """
    mode = stat.S_IMODE(os.stat(path).st_mode)
    if not (mode & 0o077):
        return  # already owner-only, nothing to check

    directory = os.path.dirname(os.path.abspath(path)) or "."
    if not filesystem_enforces_permissions(directory):
        return  # filesystem can't enforce this; not a meaningful exposure signal

    raise PermissionError(
        f"{context} {path!r} is readable or writable by group or other "
        f"(mode {oct(mode)}). Refusing to load — fix permissions "
        f"(chmod 600) after confirming no one else has read it, or "
        f"delete it to start over."
    )