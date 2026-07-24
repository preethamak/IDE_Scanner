from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path
from types import SimpleNamespace

from ide_scanner.providers.runtime import (
    SEMGREP_RULES,
    YARA_RULES,
    find_runtime_executable,
    provider_diagnostics,
    run_bounded_process,
    semgrep_config_arguments,
    semgrep_runtime_environment,
    semgrep_timeout_seconds,
)
from ide_scanner.providers import runtime


def test_provider_rules_are_owned_by_the_python_package() -> None:
    assert (SEMGREP_RULES / "vscode-security.yml").is_file()
    assert YARA_RULES.is_file()
    diagnostics = provider_diagnostics()
    assert diagnostics["semgrep"]["ruleset_hash"]
    assert diagnostics["yara"]["ruleset_hash"]
    arguments = semgrep_config_arguments()
    assert arguments[::2] == ["--config"]
    assert all(Path(path).is_file() for path in arguments[1::2])


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


def test_semgrep_invocations_use_isolated_temporary_state() -> None:
    with semgrep_runtime_environment() as first:
        first_settings = Path(first["SEMGREP_SETTINGS_FILE"])
        first_root = first_settings.parent
        assert first_root.is_dir()
    with semgrep_runtime_environment() as second:
        second_settings = Path(second["SEMGREP_SETTINGS_FILE"])
        assert second_settings.parent != first_root

    assert not first_root.exists()
    assert not second_settings.parent.exists()


def test_semgrep_timeout_is_bounded(monkeypatch) -> None:
    monkeypatch.setenv("GUARDRAILS_SEMGREP_TIMEOUT", "1")
    assert semgrep_timeout_seconds() == 15
    monkeypatch.setenv("GUARDRAILS_SEMGREP_TIMEOUT", "9999")
    assert semgrep_timeout_seconds() == 600
    monkeypatch.setenv("GUARDRAILS_SEMGREP_TIMEOUT", "invalid")
    assert semgrep_timeout_seconds() == 90


def test_semgrep_probe_is_a_fast_offline_version_check(monkeypatch) -> None:
    observed: dict[str, object] = {}

    def fake_run(command, **kwargs):
        observed["command"] = command
        observed["timeout"] = kwargs["timeout"]
        return SimpleNamespace(returncode=0, stdout="1.171.0\n", stderr="")

    monkeypatch.setattr(runtime, "run_bounded_process", fake_run)
    diagnostic = {"status": "available", "executable": "/env/bin/semgrep"}

    runtime._probe_semgrep(diagnostic)

    assert observed["command"] == [
        "/env/bin/semgrep",
        "scan",
        "--disable-version-check",
        "--version",
    ]
    assert observed["timeout"] == 20
    assert diagnostic["version"] == "1.171.0"


def test_timeout_terminates_provider_process_group(tmp_path: Path) -> None:
    if os.name != "posix":
        return
    child_pid_file = tmp_path / "child.pid"
    child = (
        "import os,time;"
        f"open({str(child_pid_file)!r},'w').write(str(os.getpid()));"
        "time.sleep(60)"
    )
    parent = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
        "time.sleep(60)"
    )

    try:
        run_bounded_process([sys.executable, "-c", parent], timeout=0.5)
    except subprocess.TimeoutExpired:
        pass
    else:
        raise AssertionError("provider process unexpectedly completed")

    child_pid = int(child_pid_file.read_text(encoding="utf-8"))
    proc_state = Path(f"/proc/{child_pid}/stat")
    for _attempt in range(20):
        if not proc_state.exists() or proc_state.read_text(encoding="utf-8").split()[2] == "Z":
            break
        time.sleep(0.05)
    assert not proc_state.exists() or proc_state.read_text(encoding="utf-8").split()[2] == "Z"
