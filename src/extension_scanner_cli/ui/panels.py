from __future__ import annotations

import textwrap

from .tables import ANSI_RE, terminal_width, truncate, visible_len
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
    if terminal_width() < 82:
        return color("Extension Scanner", "cyan") + "\n" + color(f"  v0.1.0  |  {subtitle}", "violet")
    return color(LOGO.rstrip(), "cyan") + "\n" + color(f"  v0.1.0  |  {subtitle}", "violet")


def _wrap_panel_line(line: str, width: int) -> list[str]:
    if visible_len(line) <= width:
        return [line]
    if ANSI_RE.search(line):
        return [truncate(line, width)]
    return textwrap.wrap(line, width=width, break_long_words=True, break_on_hyphens=False) or [""]


def panel(title: str, body: str = "", *, subtitle: str = "") -> str:
    raw_content = [line.rstrip() for line in body.splitlines()] if body else []
    header = f" {title} " + (f"- {subtitle} " if subtitle else "")
    max_width = max(36, terminal_width() - 4)
    content: list[str] = []
    for line in raw_content:
        content.extend(_wrap_panel_line(line, max_width))
    header = truncate(header, max_width)
    width = min(max_width, max(36, visible_len(header), *(visible_len(line) for line in content), 0))
    top = "╭" + "─" * (width + 2) + "╮"
    title_line = "│ " + color(header, "cyan") + " " * max(width - visible_len(header), 0) + " │"
    lines = [top, title_line, "├" + "─" * (width + 2) + "┤"]
    for line in content:
        lines.append("│ " + line + " " * max(width - visible_len(line), 0) + " │")
    lines.append("╰" + "─" * (width + 2) + "╯")
    return "\n".join(lines)


def section(title: str) -> str:
    width = min(terminal_width(), 96)
    label = f" {truncate(title, max(8, width - 10))} "
    side = max(0, (width - visible_len(label)) // 2)
    return "\n" + color("─" * side + label + "─" * side, "cyan")
