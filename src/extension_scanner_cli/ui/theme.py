from __future__ import annotations

import os
import sys


RESET = "\033[0m"
STYLES = {
    "bold": "\033[1m",
    "dim": "\033[2m",
    "cyan": "\033[36m",
    "blue": "\033[34m",
    "green": "\033[32m",
    "yellow": "\033[33m",
    "orange": "\033[38;5;208m",
    "red": "\033[31m",
    "violet": "\033[35m",
    "gray": "\033[90m",
    "white": "\033[97m",
}

SEVERITY_ICON = {
    "CRITICAL": "🔴 CRITICAL",
    "HIGH": "🟠 HIGH",
    "MEDIUM": "🟡 MEDIUM",
    "LOW": "LOW",
    "INFO": "INFO",
}


def supports_color() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def color(text: object, style: str) -> str:
    value = str(text)
    code = STYLES.get(style, "")
    if not code or not supports_color():
        return value
    return f"{code}{value}{RESET}"


def badge(text: str, style: str) -> str:
    return color(f" {text.upper()} ", style)


def verdict_style(verdict: str, state: str = "") -> str:
    value = (state or verdict or "").lower()
    if "malicious" in value:
        return "red"
    if "suspicious" in value:
        return "orange"
    if "review" in value:
        return "yellow"
    if "safe" in value or "clean" in value:
        return "green"
    return "blue"


def severity_style(severity: str) -> str:
    value = severity.upper()
    if value in {"CRITICAL", "HIGH"}:
        return "red"
    if value == "MEDIUM":
        return "yellow"
    if value == "LOW":
        return "cyan"
    return "blue"


def severity_label(severity: str) -> str:
    value = severity.upper()
    return SEVERITY_ICON.get(value, value or "INFO")


def rule() -> str:
    return color("-" * 78, "gray")
