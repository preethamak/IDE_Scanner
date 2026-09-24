"""Resolve the scanner build identity used in reports and publication gates."""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path


GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.IGNORECASE)


def scanner_build() -> str:
    """Return a verifiable scanner revision, or ``unknown``.

    CI supplies the immutable revision explicitly. A source checkout can
    resolve its own HEAD for local CLI use, while an installed package that
    is no longer inside a Git checkout remains explicitly unidentified.
    Short refs and arbitrary environment values never become metadata.
    """
    configured = os.environ.get("IDE_SCANNER_BUILD_SHA", "").strip().lower()
    if configured:
        return configured if GIT_SHA_RE.fullmatch(configured) else "unknown"

    package_root = Path(__file__).resolve().parents[2]
    try:
        completed = subprocess.run(
            ["git", "-C", str(package_root), "rev-parse", "HEAD"],
            check=True,
            capture_output=True,
            text=True,
            timeout=2,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    resolved = completed.stdout.strip().lower()
    return resolved if GIT_SHA_RE.fullmatch(resolved) else "unknown"
