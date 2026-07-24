from __future__ import annotations

import os
import sys
from pathlib import Path

from ide_scanner.providers.runtime import (
    SEMGREP_RULES,
    YARA_RULES,
    find_runtime_executable,
    provider_diagnostics,
)
from ide_scanner.providers import runtime


def test_provider_rules_are_owned_by_the_python_package() -> None:
    assert (SEMGREP_RULES / "vscode-security.yml").is_file()
    assert YARA_RULES.is_file()
    diagnostics = provider_diagnostics()
    assert diagnostics["semgrep"]["ruleset_hash"]
    assert diagnostics["yara"]["ruleset_hash"]


def test_runtime_executable_is_discovered_beside_python(monkeypatch, tmp_path: Path) -> None:
    environment_bin = tmp_path / "bin"
    environment_bin.mkdir()
    executable = environment_bin / ("semgrep.exe" if os.name == "nt" else "semgrep")
    executable.write_text("", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(sys, "executable", str(environment_bin / "python"))
    monkeypatch.setenv("PATH", "")

    assert find_runtime_executable("semgrep") == str(executable)


def test_provider_is_unavailable_when_bundled_rules_are_missing(monkeypatch, tmp_path: Path) -> None:
    executable = tmp_path / "semgrep"
    executable.write_text("", encoding="utf-8")
    executable.chmod(0o755)
    monkeypatch.setattr(runtime, "SEMGREP_RULES", tmp_path / "missing-rules")
    monkeypatch.setattr(runtime, "find_runtime_executable", lambda _name: str(executable))

    diagnostic = runtime.semgrep_diagnostic()

    assert diagnostic["status"] == "unavailable"
    assert diagnostic["ruleset_hash"] == ""
    assert "rules" in diagnostic["error"].lower()
