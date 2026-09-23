#!/usr/bin/env python3
"""Exec a scanner command in a fresh process session.

This tiny launcher deliberately imports no scanner modules before creating the
new session. The parent scheduler can therefore use ``posix_spawn`` instead of
forking after loading native analyzers, while timeout cleanup can still kill
the scanner and its provider descendants as one process group.
"""

from __future__ import annotations

import os
import sys


def main() -> int:
    try:
        separator = sys.argv.index("--")
    except ValueError:
        print("exec_scan_worker requires a -- separator", file=sys.stderr)
        return 2
    command = sys.argv[separator + 1:]
    if not command:
        print("exec_scan_worker requires a command", file=sys.stderr)
        return 2
    if os.name == "posix":
        os.setsid()
    os.execvpe(command[0], command, os.environ.copy())
    return 127  # pragma: no cover - os.execvpe either replaces or raises


if __name__ == "__main__":
    raise SystemExit(main())
