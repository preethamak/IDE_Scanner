from __future__ import annotations

from .tables import visible_len
from .theme import color


LOGO = r"""
 ███████╗██╗  ██╗████████╗███████╗███╗   ██╗███████╗██╗ ██████╗ ███╗   ██╗
 ██╔════╝╚██╗██╔╝╚══██╔══╝██╔════╝████╗  ██║██╔════╝██║██╔═══██╗████╗  ██║
 █████╗   ╚███╔╝    ██║   █████╗  ██╔██╗ ██║███████╗██║██║   ██║██╔██╗ ██║
 ██╔══╝   ██╔██╗    ██║   ██╔══╝  ██║╚██╗██║╚════██║██║██║   ██║██║╚██╗██║
 ███████╗██╔╝ ██╗   ██║   ███████╗██║ ╚████║███████║██║╚██████╔╝██║ ╚████║
 ╚══════╝╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
        ━━━━  S  C  A  N  N  E  R  ━━━━
"""


def banner(subtitle: str = "IDE extension security toolkit") -> str:
    return color(LOGO.rstrip(), "cyan") + "\n" + color(f"  v0.1.0  |  {subtitle}", "violet")


def panel(title: str, body: str = "", *, subtitle: str = "") -> str:
    content = [line.rstrip() for line in body.splitlines()] if body else []
    header = f" {title} " + (f"- {subtitle} " if subtitle else "")
    width = max(58, visible_len(header), *(visible_len(line) for line in content), 0)
    top = "╭" + "─" * (width + 2) + "╮"
    title_line = "│ " + color(header, "cyan") + " " * max(width - visible_len(header), 0) + " │"
    lines = [top, title_line, "├" + "─" * (width + 2) + "┤"]
    for line in content:
        lines.append("│ " + line + " " * max(width - visible_len(line), 0) + " │")
    lines.append("╰" + "─" * (width + 2) + "╯")
    return "\n".join(lines)


def section(title: str) -> str:
    return "\n" + color("─" * 18 + f" {title} " + "─" * 18, "cyan")
