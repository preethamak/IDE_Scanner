from __future__ import annotations

import hashlib
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any


_PACKAGE_ROOT = Path(__file__).resolve().parents[1]
SEMGREP_RULES = _PACKAGE_ROOT / "provider_rules" / "semgrep"
YARA_RULES = _PACKAGE_ROOT / "provider_rules" / "yara" / "ide-scanner.yar"


def find_runtime_executable(name: str) -> str | None:
    """Find a provider installed beside Guardrails before consulting global PATH."""
    environment_bin = Path(sys.executable).parent
    adjacent = shutil.which(name, path=str(environment_bin))
    return adjacent or shutil.which(name)


def semgrep_environment() -> dict[str, str]:
    environment = os.environ.copy()
    temporary = Path(tempfile.gettempdir())
    environment["SEMGREP_SETTINGS_FILE"] = str(temporary / "guardrails-semgrep-settings.yml")
    environment["SEMGREP_LOG_FILE"] = str(temporary / "guardrails-semgrep.log")
    environment["SEMGREP_SEND_METRICS"] = "off"
    return environment


def provider_diagnostics(*, probe: bool = False) -> dict[str, dict[str, Any]]:
    diagnostics = {
        "semgrep": semgrep_diagnostic(),
        "yara": yara_diagnostic(),
    }
    if probe:
        _probe_semgrep(diagnostics["semgrep"])
        _probe_yara(diagnostics["yara"])
    return diagnostics


def semgrep_diagnostic() -> dict[str, Any]:
    executable = find_runtime_executable("semgrep")
    ruleset_hash = _ruleset_hash(SEMGREP_RULES)
    missing: list[str] = []
    if not executable:
        missing.append("Semgrep executable is not installed")
    if not ruleset_hash:
        missing.append("bundled Semgrep rules are unavailable")
    return {
        "provider": "semgrep",
        "status": "available" if not missing else "unavailable",
        "executable": executable or "",
        "rules_path": str(SEMGREP_RULES),
        "ruleset_hash": ruleset_hash,
        "error": "; ".join(missing),
        "required": False,
    }


def yara_diagnostic() -> dict[str, Any]:
    executable = find_runtime_executable("yara")
    python_available = importlib.util.find_spec("yara") is not None
    runtime = executable or ("yara-python" if python_available else "")
    ruleset_hash = _ruleset_hash(YARA_RULES)
    missing: list[str] = []
    if not runtime:
        missing.append("YARA runtime is not installed")
    if not ruleset_hash:
        missing.append("bundled YARA rules are unavailable")
    return {
        "provider": "yara",
        "status": "available" if not missing else "unavailable",
        "executable": runtime,
        "rules_path": str(YARA_RULES),
        "ruleset_hash": ruleset_hash,
        "error": "; ".join(missing),
        "required": False,
    }


def _probe_semgrep(status: dict[str, Any]) -> None:
    if status["status"] != "available":
        return
    try:
        result = subprocess.run(
            [
                str(status["executable"]),
                "scan",
                "--validate",
                "--config",
                str(SEMGREP_RULES),
                "--metrics",
                "off",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env=semgrep_environment(),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        status.update({"status": "failed", "error": str(exc)})
        return
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        status.update({"status": "failed", "error": detail[:500] or "Semgrep rule validation failed"})


def _probe_yara(status: dict[str, Any]) -> None:
    if status["status"] != "available":
        return
    if status["executable"] == "yara-python":
        try:
            import yara  # type: ignore[import-not-found]

            yara.compile(filepath=str(YARA_RULES))
        except Exception as exc:
            status.update({"status": "failed", "error": str(exc)})
        return
    try:
        result = subprocess.run(
            [str(status["executable"]), "--version"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        status.update({"status": "failed", "error": str(exc)})
        return
    if result.returncode != 0:
        status.update({"status": "failed", "error": result.stderr.strip()[:500] or "YARA probe failed"})


def _ruleset_hash(path: Path) -> str:
    if path.is_file():
        return hashlib.sha256(path.read_bytes()).hexdigest()
    if not path.is_dir():
        return ""
    digest = hashlib.sha256()
    found = False
    for rule in sorted(path.rglob("*")):
        if not rule.is_file():
            continue
        found = True
        digest.update(rule.relative_to(path).as_posix().encode("utf-8"))
        digest.update(rule.read_bytes())
    return digest.hexdigest() if found else ""
