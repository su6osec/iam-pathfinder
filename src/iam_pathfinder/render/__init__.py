"""Output formats.

``render()`` is the single dispatch point: the CLI builds one
:class:`~iam_pathfinder.render.report.Report` and asks for a format string.
Every renderer receives the same object, so all formats describe the same
analysis - only the packaging differs.
"""

from __future__ import annotations

from . import html, jsonformat, markdown, mermaid, sarif, table
from .report import Report

FORMATS: tuple[str, ...] = ("table", "json", "markdown", "sarif", "mermaid", "html")

_RENDERERS = {
    "table": table.render,
    "json": jsonformat.render,
    "markdown": markdown.render,
    "sarif": sarif.render,
    "mermaid": mermaid.render,
    "html": html.render,
}

#: File extension used by ``--out`` when the caller does not give one.
EXTENSIONS = {
    "table": ".txt",
    "json": ".json",
    "markdown": ".md",
    "sarif": ".sarif",
    "mermaid": ".mmd",
    "html": ".html",
}


def render(fmt: str, report: Report) -> str:
    try:
        renderer = _RENDERERS[fmt]
    except KeyError:
        choices = ", ".join(FORMATS)
        raise ValueError(f"unknown format {fmt!r} (choose from {choices})") from None
    return renderer(report)


__all__ = ["FORMATS", "EXTENSIONS", "Report", "render"]
