"""Private local approval files; no signing key or credential enters argv."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from .errors import GrantError
from .grant import ApprovalRequest, Grant


def read_approval_file(path: str | Path) -> str:
    """Read an owner-only regular file through its descriptor, refusing symlinks."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r", encoding="utf-8") as source:
            info = os.fstat(source.fileno())
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600):
                raise GrantError("approval file must be an owner-only regular file with mode 0600")
            return source.read()
    except (OSError, UnicodeError) as exc:
        raise GrantError("could not read the private approval file") from exc


def write_approval_file(path: str | Path, value: ApprovalRequest | Grant) -> None:
    """Create an owner-only file; never overwrite or remove partial evidence."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as output:
            output.write(value.to_json() + "\n")
            output.flush()
            os.fsync(output.fileno())
    except (OSError, UnicodeError) as exc:
        raise GrantError("could not write approval file; a partial file may remain") from exc


def read_grants(paths: tuple[str, ...]) -> dict[str, Grant]:
    """One private grant file per disclosure fingerprint; ambiguity is an error."""
    grants = {}
    for path in paths:
        grant = Grant.from_json(read_approval_file(path))
        if grant.request_fingerprint in grants:
            raise GrantError("multiple grant files describe the same disclosure")
        grants[grant.request_fingerprint] = grant
    return grants


def prepare_approval_directory(path: str | Path) -> Path:
    """Create or validate a private local directory explicitly configured by its owner."""
    target = Path(path)
    try:
        target.mkdir(mode=0o700, parents=True, exist_ok=True)
        info = target.lstat()
        if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) != 0o700):
            raise GrantError("approval directory must be owned by the current user with mode 0700")
    except OSError as exc:
        raise GrantError("could not prepare the private approval directory") from exc
    return target
