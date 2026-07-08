from __future__ import annotations

import re
from typing import Iterable

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def visible_len(value: object) -> int:
    return len(ANSI_RE.sub("", str(value)))


def truncate(value: object, width: int) -> str:
    text = str(value)
    plain = ANSI_RE.sub("", text)
    if len(plain) <= width:
        return text
    if width <= 1:
        return plain[:width]
    return plain[: width - 1] + "…"


def table(headers: list[str], rows: Iterable[Iterable[object]], *, max_widths: list[int] | None = None) -> str:
    row_list = [[str(cell) for cell in row] for row in rows]
    max_widths = max_widths or [28] * len(headers)
    widths: list[int] = []
    for index, header in enumerate(headers):
        values = [visible_len(row[index]) for row in row_list if index < len(row)]
        widths.append(min(max([visible_len(header), *values], default=visible_len(header)), max_widths[index]))

    def fmt_row(values: list[object]) -> str:
        cells = []
        for index, width in enumerate(widths):
            raw = truncate(values[index] if index < len(values) else "", width)
            cells.append(raw + " " * max(width - visible_len(raw), 0))
        return "| " + " | ".join(cells) + " |"

    border = "+-" + "-+-".join("-" * width for width in widths) + "-+"
    sep = "+=" + "=+=".join("=" * width for width in widths) + "=+"
    lines = [border, fmt_row(headers), sep]
    lines.extend(fmt_row(row) for row in row_list)
    lines.append(border)
    return "\n".join(lines)


def key_values(items: list[tuple[str, object]], *, key_width: int = 16) -> str:
    lines = []
    for key, value in items:
        lines.append(f"{key:<{key_width}} {value}")
    return "\n".join(lines)


def score_bar(value: int | float, *, width: int = 24) -> str:
    value = max(0, min(100, int(value or 0)))
    filled = round(width * value / 100)
    return "[" + "#" * filled + "-" * (width - filled) + f"] {value:>3}/100"
