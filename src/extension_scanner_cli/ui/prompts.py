from __future__ import annotations

from typing import Sequence

from .theme import color


def prompt_text(label: str, *, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    value = input(color(f"{label}{suffix}: ", "cyan")).strip()
    return value or default


def prompt_choice(label: str, choices: Sequence[str], *, default: int = 0) -> int:
    while True:
        raw = input(color(f"{label} [{default + 1}]: ", "cyan")).strip()
        if not raw:
            return default
        if raw.isdigit():
            index = int(raw) - 1
            if 0 <= index < len(choices):
                return index
        print(color(f"Choose a number from 1 to {len(choices)}.", "yellow"))


def confirm(label: str, *, default: bool = False) -> bool:
    suffix = "Y/n" if default else "y/N"
    raw = input(color(f"{label} [{suffix}]: ", "cyan")).strip().lower()
    if not raw:
        return default
    return raw in {"y", "yes"}
