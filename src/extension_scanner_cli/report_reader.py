from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any


def read_report(path: str | Path) -> dict[str, Any]:
    report_path = Path(path)
    if report_path.suffix.lower() == ".zip":
        return read_report_zip(report_path)
    data = json.loads(report_path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def read_report_zip(path: str | Path) -> dict[str, Any]:
    with zipfile.ZipFile(path) as archive:
        metadata = _read_json(archive, "metadata.json")
        summary = _read_json(archive, "summary.json")
        leaderboard = _read_json(archive, "leaderboard.json")
        posture = _read_json(archive, "posture.json")
        rules = _read_json(archive, "rules.json")
        details = {}
        for name in archive.namelist():
            if name.startswith("extensions/") and name.endswith(".json"):
                details[name] = _read_json(archive, name)
    return {
        "metadata": metadata,
        "summary": summary,
        "leaderboard": leaderboard,
        "posture": posture,
        "rules": rules,
        "details": details,
    }


def validate_report(path: str | Path) -> tuple[bool, list[str]]:
    errors: list[str] = []
    report_path = Path(path)
    if not report_path.exists():
        return False, [f"{report_path} does not exist"]
    if report_path.suffix.lower() != ".zip":
        try:
            read_report(report_path)
        except Exception as exc:  # noqa: BLE001
            errors.append(str(exc))
        return not errors, errors
    try:
        with zipfile.ZipFile(report_path) as archive:
            names = set(archive.namelist())
            for required in {"metadata.json", "summary.json", "leaderboard.json", "rules.json"}:
                if required not in names:
                    errors.append(f"missing {required}")
    except zipfile.BadZipFile:
        errors.append("not a valid zip archive")
    return not errors, errors


def _read_json(archive: zipfile.ZipFile, name: str) -> dict[str, Any]:
    try:
        data = json.loads(archive.read(name).decode("utf-8"))
    except KeyError:
        return {}
    return data if isinstance(data, dict) else {}
