"""Terminal presentation for SPECTER: content first, sources last."""

from __future__ import annotations

import json
from typing import Any, Iterable

from rich import box
from rich.console import Console, Group
from rich.padding import Padding
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from . import __tagline__, __tool_name__, __version__, images
from .models import (
    BLOCKED,
    ERROR,
    FOUND,
    INFO,
    MANUAL,
    NOT_FOUND,
    STATUS_LABELS,
    UNKNOWN,
    Finding,
    ImageRef,
    Report,
)

ACCENT = "cyan"
MUTED = "grey62"

STATUS_STYLE = {
    FOUND: "bold green",
    NOT_FOUND: "dim",
    BLOCKED: "yellow",
    ERROR: "bold red",
    UNKNOWN: "dim cyan",
    MANUAL: "blue",
    INFO: "cyan",
}

CATEGORY_ORDER = [
    "Assessment",
    "Username",
    "Identity",
    "Email",
    "Contact",
    "Phone",
    "Social",
    "IP address",
    "Domain",
    "GitHub",
    "Breach",
    "Web",
    "News",
    "Wikipedia",
    "Wikidata",
    "Forums",
    "Filings",
    "Archive",
    "Manual",
]

LONG_KEYS = {
    "description",
    "bio",
    "about",
    "aboutMe",
    "note",
    "summary",
    "extract",
    "story_text",
    "comment_text",
    "body",
    "text",
}

PRIMARY_KEYS = (
    "name",
    "display name",
    "full name",
    "login",
    "handle",
    "host",
    "title",
    "site",
    "source",
    "company",
    "organisation",
    "organization",
    "case",
    "label",
    "identifier",
    "username",
    "email",
)

_console = Console(highlight=False, legacy_windows=False)


def init(no_color: bool = False, width: int | None = None) -> Console:
    global _console
    _console = Console(
        highlight=False,
        no_color=no_color,
        width=width,
        legacy_windows=False,
    )
    return _console


def out() -> Console:
    return _console


def banner() -> None:
    title = Text()
    title.append("S P E C T E R", style="bold white")
    subtitle = Text(f"{__tagline__}  ·  v{__version__}", style=f"italic {MUTED}")
    body = Group(
        title,
        subtitle,
        Text(""),
        Text(
            "Dossiers · avatars & images · usernames · emails · phones · IPs · "
            "domains · GitHub · breaches · web & news",
            style=MUTED,
        ),
    )
    _console.print(
        Panel(
            body,
            border_style=ACCENT,
            box=box.ROUNDED,
            padding=(1, 3),
            title="[bold cyan]OSINT CONSOLE[/]",
            subtitle="[dim]type [bold]menu[/] for options, [bold]help[/] for commands[/]",
        )
    )
    notice()


def notice() -> None:
    _console.print(
        Text.assemble(
            (
                "  Use only on yourself or on people you are explicitly authorised to "
                "investigate. ",
                "dim",
            ),
            ("You are responsible for complying with local law.", "dim italic"),
        )
    )
    _console.print()


def rule(title: str, subtitle: str | None = None) -> None:
    line = Text("  " + title, style="bold cyan")
    if subtitle:
        line.append(f"  {subtitle}", style=MUTED)
    _console.rule(line, style="grey30", align="left")


def info(message: str) -> None:
    _console.print(Text("  " + message, style=MUTED))


def success(message: str) -> None:
    _console.print(Text("  ✔ " + message, style="green"))


def warn(message: str) -> None:
    _console.print(Text("  ! " + message, style="yellow"))


def error(message: str) -> None:
    _console.print(Text("  ✖ " + message, style="bold red"))


def _link(url: str, label: str | None = None) -> Text:
    text = Text(label or url, style="blue underline")
    if url:
        text.stylize(f"link {url}")
    return text


def _value_text(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (dict, list)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except TypeError:
            return str(value)
    return str(value)


def _entry_title(finding: Finding) -> str:
    for key in PRIMARY_KEYS:
        value = finding.data.get(key)
        if value not in (None, "", [], {}):
            return str(value)
    return finding.source


# ---------------------------------------------------------------------------
# Data and collection rendering
# ---------------------------------------------------------------------------
def _collection_lines(items: list[Any], indent: int = 6) -> list[Text]:
    """Render every field of every item, without dropping information."""
    pad = " " * indent
    inner = " " * (indent + 4)
    lines: list[Text] = []
    for item in items:
        if not isinstance(item, dict):
            line = Text(pad + "• ", style=ACCENT)
            line.append(_value_text(item), style="white")
            lines.append(line)
            continue

        primary_key = next(
            (
                key
                for key in PRIMARY_KEYS
                if item.get(key) not in (None, "", [], {})
                and not isinstance(item.get(key), (dict, list))
            ),
            None,
        )
        first = Text(pad + "• ", style=ACCENT)
        first.append(
            str(item.get(primary_key)) if primary_key else "(entry)",
            style="bold white",
        )
        lines.append(first)

        inline: list[str] = []
        long_lines: list[Text] = []
        links: list[tuple[str, str]] = []
        for key, value in item.items():
            if key == primary_key or value in (None, "", [], {}):
                continue
            if isinstance(value, str) and value.startswith(("http://", "https://")):
                links.append((key, value))
            elif isinstance(value, dict):
                nested = " · ".join(
                    f"{name}: {_value_text(val)}"
                    for name, val in value.items()
                    if not isinstance(val, (dict, list))
                )
                if nested:
                    inline.append(f"{key}: {nested}")
            elif isinstance(value, list):
                if value and isinstance(value[0], dict):
                    long_lines.append(Text(inner + f"{key}:", style=MUTED))
                    long_lines.extend(_collection_lines(value, indent + 4))
                else:
                    inline.append(f"{key}: " + ", ".join(_value_text(v) for v in value))
            elif isinstance(value, str) and (key in LONG_KEYS or len(value) > 140):
                long_lines.append(Text(inner + f"{key}: {value}", style="white"))
            else:
                inline.append(f"{key}: {_value_text(value)}")

        if inline:
            lines.append(Text(inner + " · ".join(inline), style="white"))
        lines.extend(long_lines)
        for key, url in links:
            line = Text(inner + f"{key}: ", style=MUTED)
            line.append_text(_link(url))
            lines.append(line)
    return lines


def _nested_kv(mapping: dict[str, Any]) -> Table:
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=MUTED, no_wrap=True, width=16)
    grid.add_column(ratio=1, overflow="fold")
    for key, value in mapping.items():
        if value in (None, "", [], {}):
            continue
        grid.add_row(Text(str(key)), Text(_value_text(value), style="white"))
    return grid


def _bullet_list(values: list[Any]) -> Group:
    lines = []
    for value in values:
        line = Text("• ", style=ACCENT)
        line.append(_value_text(value), style="white")
        lines.append(line)
    return Group(*lines)


def _data_block(data: dict[str, Any]) -> Padding | None:
    if not data:
        return None
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=MUTED, no_wrap=True, width=18)
    grid.add_column(ratio=1, overflow="fold")
    for key, value in data.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list):
            if value and isinstance(value[0], dict):
                renderable: Any = Group(*_collection_lines(value))
            else:
                renderable = _bullet_list(value)
        elif isinstance(value, dict):
            renderable = _nested_kv(value)
        else:
            renderable = Text(_value_text(value), style="white")
        grid.add_row(Text(str(key)), renderable)
    return Padding(grid, (0, 0, 0, 4))


# ---------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------
def _preview_text(image: ImageRef, width: int = 22) -> Text | None:
    if not _console.is_terminal or _console.color_system != "truecolor":
        return None
    rows = images.cached_preview(image.url, width)
    if not rows:
        return None
    text = Text()
    for row in rows:
        for top, bottom in row:
            foreground = "#%02x%02x%02x" % top
            background = "#%02x%02x%02x" % bottom
            text.append("▀", style=f"{foreground} on {background}")
        text.append("\n")
    return text


def _image_block(finding: Finding, preview_budget: list[int]) -> None:
    if not finding.images:
        return
    for image in finding.images:
        if preview_budget[0] > 0:
            preview = _preview_text(image)
            if preview is not None:
                _console.print(Padding(preview, (0, 0, 0, 4)))
                preview_budget[0] -= 1
                if image.alt:
                    _console.print(Text("    " + image.alt, style=MUTED))
        line = Text("    image  ", style=MUTED)
        line.append(image.kind or "image", style="cyan dim")
        line.append("  ")
        line.append_text(_link(image.url))
        _console.print(line)


# ---------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------
def render_entry(
    finding: Finding,
    *,
    show_images: bool = True,
    preview_budget: list[int] | None = None,
) -> None:
    budget = preview_budget if preview_budget is not None else [8]
    headline = Text()
    headline.append("● ", style=STATUS_STYLE.get(finding.status, ACCENT))
    headline.append(finding.title or _entry_title(finding), style="bold white")
    if finding.status == INFO:
        headline.append("   info", style="cyan dim")
    if finding.confidence != "high":
        headline.append(f"   {finding.confidence} confidence", style="yellow dim")
    _console.print(headline)

    if show_images and finding.images:
        _image_block(finding, budget)

    if finding.detail:
        _console.print(Padding(Text(finding.detail, style="white"), (0, 0, 0, 4)))

    data_block = _data_block(finding.data)
    if data_block is not None:
        _console.print(data_block)

    footer = Text("    via ", style=MUTED)
    footer.append(finding.source, style=MUTED)
    if finding.url:
        footer.append("   ·   ", style="grey37")
        footer.append_text(_link(finding.url))
    if finding.elapsed_ms:
        footer.append(f"   ·   {finding.elapsed_ms} ms", style="grey37")
    _console.print(Padding(footer, (0, 0, 0, 0)))
    _console.print()


def render_findings(
    findings: list[Finding],
    *,
    verbose: bool = False,
    show_images: bool = True,
) -> None:
    primary = [f for f in findings if f.status in (FOUND, INFO)]
    manual = [f for f in findings if f.status == MANUAL]
    inactive = [f for f in findings if f.status in (NOT_FOUND, BLOCKED, ERROR, UNKNOWN)]

    grouped: dict[str, list[Finding]] = {}
    for finding in primary:
        grouped.setdefault(finding.category, []).append(finding)
    edges = list(
        dict.fromkeys(
            [finding.category for finding in findings if finding.category in CATEGORY_ORDER]
        )
    )
    keys = sorted(
        grouped,
        key=lambda category: (
            CATEGORY_ORDER.index(category) if category in CATEGORY_ORDER else len(CATEGORY_ORDER),
            category,
        ),
    )
    budget = [8]

    for category in keys:
        entries = grouped[category]
        rule(category, f"{len(entries)} dossier{'s' if len(entries) != 1 else ''}")
        for finding in entries:
            render_entry(finding, show_images=show_images, preview_budget=budget)

    if manual:
        rule("Manual verification links", f"{len(manual)} platform(s)")
        _console.print(manual_table(manual))
        _console.print()

    if inactive:
        counts: dict[str, int] = {}
        for finding in inactive:
            counts[finding.status] = counts.get(finding.status, 0) + 1
        summary = " · ".join(
            f"{STATUS_LABELS.get(status, status)}: {count}"
            for status, count in counts.items()
        )
        info(f"Sources with no dossier: {summary}.")
        if verbose:
            _console.print(status_table(inactive, title="All inactive sources"))
            _console.print()


def summary_panel(report: Report) -> Panel:
    counts = report.counts()
    grid = Table.grid(padding=(0, 2))
    grid.add_column(style=MUTED, no_wrap=True)
    grid.add_column(style="white")
    grid.add_row("Target", Text(report.target, style="bold white"))
    grid.add_row("Type", report.target_type)
    grid.add_row("Duration", f"{report.duration():.1f}s")
    grid.add_row(
        "Results",
        Text.assemble(
            (f"{counts['found']} found", "bold green"),
            ("  ·  ", "grey37"),
            (f"{counts['images']} image(s)", "magenta"),
            ("  ·  ", "grey37"),
            (f"{counts['manual']} manual links", "blue"),
            ("  ·  ", "grey37"),
            (f"{counts['blocked']} blocked", "yellow" if counts["blocked"] else MUTED),
            ("  ·  ", "grey37"),
            (f"{counts['errors']} errors", "red" if counts["errors"] else MUTED),
        ),
    )
    grid.add_row("Evidence", f"{counts['total']} entries collected")
    return Panel(
        grid,
        title="[bold cyan]Investigation summary[/]",
        border_style="grey30",
        box=box.ROUNDED,
        padding=(0, 2),
    )


def print_notes(notes: list[str]) -> None:
    if not notes:
        return
    rule("Notes")
    for note in notes:
        info(note)
    _console.print()


def assessment_panel(report: Report) -> Panel | None:
    """Headline verdict for a correlated person profile."""
    identity = report.identity or {}
    if not identity:
        return None
    band = str(identity.get("band", "unspecified")).upper()
    score = identity.get("score", 0)
    links = identity.get("links") or []
    conflicts = identity.get("conflicts") or []

    text = Text()
    text.append(f"{band}  ·  {score}/100", style="bold cyan")
    verdict = identity.get("verdict")
    if verdict:
        text.append("\n\n")
        text.append(str(verdict), style="white")
    if links:
        top = links[0]
        text.append("\n\n")
        text.append("strongest link   ", style=MUTED)
        text.append(f"{top.get('from', '?')} → {top.get('to', '?')}", style="bold white")
        text.append(f"\n                 {top.get('basis', '')}", style=MUTED)
    if conflicts:
        text.append("\n\n")
        text.append(
            f"{len(conflicts)} contradiction(s) — see Assessment below.", style="yellow"
        )
    return Panel(
        text,
        title="Identity assessment",
        title_align="left",
        border_style="cyan",
        box=box.ROUNDED,
        padding=(0, 1),
    )


def render_report(
    report: Report,
    verbose: bool = False,
    show_images: bool = True,
) -> None:
    _console.print(summary_panel(report))
    panel = assessment_panel(report)
    if panel is not None:
        _console.print(panel)
    _console.print()
    render_findings(report.findings, verbose=verbose, show_images=show_images)
    print_notes(report.notes)


# ---------------------------------------------------------------------------
# Tables for provenance-only entries and commands
# ---------------------------------------------------------------------------
def manual_table(findings: list[Finding]) -> Table:
    table = Table(
        box=box.SIMPLE_HEAD,
        pad_edge=False,
        expand=True,
        show_edge=False,
    )
    table.add_column("Platform", style="bold white", no_wrap=True, max_width=22)
    table.add_column("Profile URL", style="blue underline", overflow="fold", ratio=3)
    table.add_column("Note", style=MUTED, overflow="fold", ratio=2)
    for finding in findings:
        link = Text(finding.url or "", style="blue underline")
        if finding.url:
            link.stylize(f"link {finding.url}")
        table.add_row(Text(finding.source), link, Text(finding.detail or ""))
    return table


def status_table(findings: list[Finding], title: str | None = None) -> Table:
    table = Table(
        title=title,
        box=box.SIMPLE_HEAD,
        pad_edge=False,
        expand=True,
        show_edge=False,
        title_justify="left",
        title_style=f"bold {MUTED}",
    )
    table.add_column("Source", style=MUTED, no_wrap=True, max_width=24)
    table.add_column("Status", no_wrap=True, width=10)
    table.add_column("Detail", style=MUTED, overflow="fold", ratio=3)
    for finding in findings:
        label = STATUS_LABELS.get(finding.status, finding.status)
        table.add_row(
            Text(finding.source),
            Text(label, style=STATUS_STYLE.get(finding.status, MUTED)),
            Text(finding.detail or finding.title or finding.url or ""),
        )
    return table


def kv_table(pairs: Iterable[tuple[str, Any]], title: str | None = None) -> Table:
    table = Table(
        title=title,
        box=box.SIMPLE,
        show_header=False,
        pad_edge=False,
        expand=False,
    )
    table.add_column("Field", style=MUTED, no_wrap=True)
    table.add_column("Value", style="white", overflow="fold")
    for key, value in pairs:
        text = "—" if value in (None, "", [], {}) else str(value)
        table.add_row(Text(key), Text(text))
    return table


def print_kv(pairs: Iterable[tuple[str, Any]], title: str | None = None) -> None:
    _console.print(kv_table(pairs, title))


def dork_panel(links: list[tuple[str, str]], title: str = "Search links") -> None:
    if not links:
        return
    lines = []
    for engine, url in links:
        line = Text(f"{engine:10} ", style=MUTED)
        line.append(url, style="blue underline")
        line.stylize(f"link {url}")
        lines.append(line)
    _console.print(
        Panel(
            Group(*lines),
            title=f"[bold]{title}[/]",
            border_style="grey30",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    _console.print()


def query_panel(queries: list[str], title: str = "Suggested dorks") -> None:
    if not queries:
        return
    lines = [Text("  " + query, style="white") for query in queries]
    lines.append(Text(""))
    lines.append(
        Text(
            "  Paste any line into Google, Bing, DuckDuckGo, Yandex or a site-specific search.",
            style=MUTED,
        )
    )
    _console.print(
        Panel(
            Group(*lines),
            title=f"[bold]{title}[/]",
            border_style="grey30",
            box=box.ROUNDED,
            padding=(0, 2),
        )
    )
    _console.print()


def menu_table(options: list[tuple[str, str, str]]) -> Table:
    table = Table(
        box=box.SIMPLE,
        show_header=True,
        header_style=MUTED,
        pad_edge=False,
        expand=False,
    )
    table.add_column("#", style="bold cyan", width=3, justify="right")
    table.add_column("Module", style="bold white", width=26)
    table.add_column("What it does", style=MUTED)
    for number, name, description in options:
        table.add_row(number, name, description)
    return table
