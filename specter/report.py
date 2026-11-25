"""Report export: JSON, Markdown and a self-contained HTML page.

Exports mirror the console: every field and image is shown first, the source
and profile URL close each entry.
"""

from __future__ import annotations

import html
import json
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import images
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
    Report,
)

CATEGORY_ORDER = [
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
]


def _fmt_value(value: Any) -> str:
    if isinstance(value, bool):
        return "yes" if value else "no"
    if isinstance(value, (list, tuple, dict)):
        try:
            return json.dumps(value, ensure_ascii=False, default=str)
        except TypeError:
            return str(value)
    return str(value)


def _grouped(report: Report) -> list[tuple[str, list[Finding]]]:
    grouped: dict[str, list[Finding]] = {}
    for finding in report.findings:
        if finding.status in (FOUND, INFO):
            grouped.setdefault(finding.category, []).append(finding)
    ordered = sorted(
        grouped,
        key=lambda category: (
            CATEGORY_ORDER.index(category) if category in CATEGORY_ORDER else len(CATEGORY_ORDER),
            category,
        ),
    )
    return [(category, grouped[category]) for category in ordered]


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------
def _markdown_data(finding: Finding) -> list[str]:
    lines: list[str] = []
    for key, value in finding.data.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list) and value and isinstance(value[0], dict):
            lines.append(f"  - **{key}** ({len(value)} entries):")
            for item in value:
                fields = " · ".join(
                    f"{name}: {_fmt_value(val)}"
                    for name, val in item.items()
                    if val not in (None, "", [], {})
                )
                lines.append(f"    - {fields}")
        elif isinstance(value, dict):
            fields = " · ".join(
                f"{name}: {_fmt_value(val)}"
                for name, val in value.items()
                if val not in (None, "", [], {})
            )
            lines.append(f"  - **{key}:** {fields}")
        elif isinstance(value, list):
            lines.append(f"  - **{key}:** " + ", ".join(_fmt_value(v) for v in value))
        else:
            lines.append(f"  - **{key}:** {_fmt_value(value)}")
    return lines


def render_markdown(report: Report) -> str:
    counts = report.counts()
    lines: list[str] = []
    lines.append(f"# SPECTER report — {report.target}")
    lines.append("")
    lines.append(f"- **Target:** `{report.target}`")
    lines.append(f"- **Type:** {report.target_type}")
    lines.append(f"- **Generated:** {report.started.astimezone(timezone.utc).isoformat(timespec='seconds')}")
    lines.append(f"- **Duration:** {report.duration():.1f}s")
    lines.append(
        f"- **Results:** {counts['found']} found · {counts['images']} images · "
        f"{counts['manual']} manual links · {counts['blocked']} blocked · "
        f"{counts['errors']} errors"
    )
    if report.options:
        lines.append(f"- **Options:** `{json.dumps(report.options, default=str)}`")
    lines.append("")

    identity = report.identity or {}
    if identity:
        lines.append("## Identity assessment")
        lines.append("")
        lines.append(
            f"**{str(identity.get('band', '')).title()} match — "
            f"{identity.get('score', 0)}/100**"
        )
        lines.append("")
        lines.append(str(identity.get("verdict", "")))
        lines.append("")
        links = identity.get("links") or []
        if links:
            lines.append("| From | To | Basis | Weight |")
            lines.append("| --- | --- | --- | --- |")
            for link in links[:25]:
                cells = [
                    str(link.get("from", "")),
                    str(link.get("to", "")),
                    str(link.get("basis", "")),
                    str(link.get("weight", "")),
                ]
                lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
            lines.append("")
        for conflict in identity.get("conflicts") or []:
            lines.append(f"- **Contradiction:** {conflict}")
        if identity.get("conflicts"):
            lines.append("")
        for gap in identity.get("gaps") or []:
            lines.append(f"- {gap}")
        if identity.get("gaps"):
            lines.append("")

    grouped = _grouped(report)
    if grouped:
        lines.append("## Findings")
        lines.append("")
        for category, findings in grouped:
            lines.append(f"### {category}")
            lines.append("")
            for finding in findings:
                label = STATUS_LABELS.get(finding.status, finding.status)
                title = finding.title or finding.source
                lines.append(f"#### {title}")
                lines.append("")
                if finding.status == INFO:
                    lines.append(f"*{label}*")
                    lines.append("")
                for image in finding.images:
                    alt = image.alt or image.kind or "image"
                    lines.append(f"![{alt}]({image.url})")
                    if finding.images:
                        lines.append("")
                if finding.detail:
                    lines.append(finding.detail)
                    lines.append("")
                data_lines = _markdown_data(finding)
                if data_lines:
                    lines.extend(data_lines)
                    lines.append("")
                provenance = f"*via {finding.source}*"
                if finding.url:
                    provenance += f" — <{finding.url}>"
                if finding.confidence != "high":
                    provenance += f" · {finding.confidence} confidence"
                lines.append(provenance)
                lines.append("")

    manual = [f for f in report.findings if f.status == MANUAL]
    if manual:
        lines.append("## Manual verification links")
        lines.append("")
        for finding in manual:
            note = f" — {finding.detail}" if finding.detail else ""
            url = f" <{finding.url}>" if finding.url else ""
            lines.append(f"- **{finding.source}**{note}{url}")
        lines.append("")

    inactive = [
        f for f in report.findings if f.status in (NOT_FOUND, BLOCKED, ERROR, UNKNOWN)
    ]
    if inactive:
        lines.append("## Not confirmed / unreachable")
        lines.append("")
        for finding in inactive:
            label = STATUS_LABELS.get(finding.status, finding.status)
            detail = f" — {finding.detail}" if finding.detail else ""
            lines.append(f"- `{label}` **{finding.source}**{detail}")
        lines.append("")

    if report.notes:
        lines.append("## Notes")
        lines.append("")
        for note in report.notes:
            lines.append(f"- {note}")
        lines.append("")

    lines.append("---")
    lines.append("")
    lines.append(
        "Generated by SPECTER. Findings are collected from public sources and "
        "must be verified independently. Use only for lawful, authorized investigations."
    )
    lines.append("")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------
def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def _safe_url(url: str | None) -> str | None:
    if not url:
        return None
    try:
        parts = urlsplit(url)
    except ValueError:
        return None
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return url


def _html_value(value: Any) -> str:
    if isinstance(value, str) and value.startswith(("http://", "https://")):
        safe = _safe_url(value)
        if safe:
            return (
                f'<a class="link" href="{_h(safe)}" rel="noopener noreferrer" '
                f'target="_blank">{_h(value)}</a>'
            )
    return _h(_fmt_value(value))


def _html_data(data: dict[str, Any]) -> str:
    if not data:
        return ""
    scalars: list[tuple[str, Any]] = []
    collections: list[tuple[str, list[dict[str, Any]]]] = []
    for key, value in data.items():
        if value in (None, "", [], {}):
            continue
        if isinstance(value, list) and value and isinstance(value[0], dict):
            collections.append((key, value))
        else:
            scalars.append((key, value))

    parts: list[str] = []
    if scalars:
        parts.append('<dl class="data">')
        for key, value in scalars:
            if isinstance(value, dict):
                rendered = _h(
                    " · ".join(
                        f"{name}: {_fmt_value(val)}"
                        for name, val in value.items()
                        if val not in (None, "", [], {})
                    )
                )
            elif isinstance(value, list):
                rendered = _h(", ".join(_fmt_value(item) for item in value))
            elif isinstance(value, str) and value.startswith(("http://", "https://")):
                rendered = _html_value(value)
            else:
                rendered = _h(_fmt_value(value))
            parts.append(f"<div><dt>{_h(key)}</dt><dd>{rendered}</dd></div>")
        parts.append("</dl>")

    for key, items in collections:
        columns: list[str] = []
        for item in items:
            for column in item.keys():
                if column not in columns:
                    columns.append(column)
        parts.append(
            f'<h4 class="collection-title">{_h(key)} '
            f'<span>{len(items)} entries</span></h4>'
        )
        parts.append('<div class="table-wrap"><table class="data-table"><thead><tr>')
        for column in columns:
            parts.append(f"<th>{_h(column)}</th>")
        parts.append("</tr></thead><tbody>")
        for item in items:
            parts.append("<tr>")
            for column in columns:
                value = item.get(column)
                parts.append(f"<td>{_html_value(value) if value not in (None, '') else '—'}</td>")
            parts.append("</tr>")
        parts.append("</tbody></table></div>")
    return "\n".join(parts)


def _embed_images(report: Report, limit: int = 8) -> dict[str, str]:
    urls: list[str] = []
    for finding in report.findings:
        for image in finding.images:
            if image.url not in urls:
                urls.append(image.url)
    embedded: dict[str, str] = {}
    if not urls:
        return embedded

    def worker(url: str) -> tuple[str, str | None]:
        return url, images.to_data_uri(url)

    with ThreadPoolExecutor(max_workers=4) as executor:
        for url, data_uri in executor.map(worker, urls[:limit]):
            if data_uri:
                embedded[url] = data_uri
    return embedded


def _html_finding(
    finding: Finding,
    embedded: dict[str, str],
    *,
    embed_images: bool = True,
) -> str:
    label = STATUS_LABELS.get(finding.status, finding.status)
    status_class = finding.status.replace("_", "-")
    parts = [
        f'<article class="finding {status_class}">',
        '<div class="finding-head">',
        f'<h3>{_h(finding.title or finding.source)}</h3>',
        f'<span class="badge {status_class}">{_h(label)}</span>',
        "</div>",
    ]

    for image in finding.images[:4]:
        source = embedded.get(image.url) if embed_images else None
        src = source or _safe_url(image.url)
        if not src:
            continue
        parts.append('<figure class="image">')
        parts.append(
            f'<img src="{_h(src)}" alt="{_h(image.alt or image.kind)}" loading="lazy">'
        )
        caption = image.alt or image.kind
        parts.append(
            f'<figcaption>{_h(caption)} · '
            f'<a href="{_h(_safe_url(image.url) or image.url)}" '
            f'rel="noopener noreferrer" target="_blank">original</a></figcaption>'
        )
        parts.append("</figure>")

    if finding.detail:
        parts.append(f'<p class="detail">{_h(finding.detail)}</p>')
    parts.append(_html_data(finding.data))

    provenance = [f"<span>via <b>{_h(finding.source)}</b></span>"]
    url = _safe_url(finding.url)
    if url:
        provenance.append(
            f'<a class="link" href="{_h(url)}" rel="noopener noreferrer" '
            f'target="_blank">{_h(url)}</a>'
        )
    if finding.confidence != "high":
        provenance.append(f"<span>{_h(finding.confidence)} confidence</span>")
    if finding.elapsed_ms:
        provenance.append(f"<span>{finding.elapsed_ms} ms</span>")
    parts.append('<div class="provenance">' + "<span>·</span>".join(provenance) + "</div>")
    parts.append("</article>")
    return "\n".join(parts)


def render_html(report: Report, *, embed_images: bool = True) -> str:
    counts = report.counts()
    grouped = _grouped(report)
    manual = [f for f in report.findings if f.status == MANUAL]
    inactive = [
        f for f in report.findings if f.status in (NOT_FOUND, BLOCKED, ERROR, UNKNOWN)
    ]
    embedded = _embed_images(report) if embed_images else {}

    sections: list[str] = []
    for category, findings in grouped:
        cards = "\n".join(
            _html_finding(finding, embedded, embed_images=embed_images)
            for finding in findings
        )
        sections.append(
            f'<section class="group"><h2>{_h(category)} '
            f'<span class="count">{len(findings)}</span></h2>'
            f'<div class="grid">{cards}</div></section>'
        )

    manual_html = ""
    if manual:
        cards = "\n".join(
            _html_finding(finding, embedded, embed_images=embed_images)
            for finding in manual
        )
        manual_html = (
            f'<section class="group"><h2>Manual verification links '
            f'<span class="count">{len(manual)}</span></h2>'
            f'<div class="grid">{cards}</div></section>'
        )

    inactive_html = ""
    if inactive:
        rows = "\n".join(
            "<tr>"
            f"<td>{_h(f.source)}</td>"
            f'<td><span class="badge {f.status.replace("_", "-")}">'
            f"{_h(STATUS_LABELS.get(f.status, f.status))}</span></td>"
            f"<td>{_h(f.detail or f.title or '')}</td>"
            "</tr>"
            for f in inactive
        )
        inactive_html = (
            '<section class="group"><h2>Not confirmed / unreachable</h2>'
            '<table class="plain"><thead><tr><th>Source</th><th>Status</th>'
            f"<th>Detail</th></tr></thead><tbody>{rows}</tbody></table></section>"
        )

    notes_html = ""
    if report.notes:
        items = "".join(f"<li>{_h(note)}</li>" for note in report.notes)
        notes_html = f'<section class="group"><h2>Notes</h2><ul class="notes">{items}</ul></section>'

    identity = report.identity or {}
    assessment_html = ""
    if identity:
        links = identity.get("links") or []
        rows = "".join(
            "<tr>"
            f"<td>{_h(link.get('from', ''))}</td>"
            f"<td>{_h(link.get('to', ''))}</td>"
            f"<td>{_h(link.get('basis', ''))}</td>"
            f"<td>{_h(link.get('weight', ''))}</td>"
            "</tr>"
            for link in links[:25]
        )
        table = (
            '<div class="table-wrap"><table class="plain"><thead><tr>'
            "<th>From</th><th>To</th><th>Basis</th><th>Weight</th>"
            f"</tr></thead><tbody>{rows}</tbody></table></div>"
            if rows
            else ""
        )
        conflicts = "".join(
            f"<li>{_h(item)}</li>" for item in identity.get("conflicts") or []
        )
        gaps = "".join(f"<li>{_h(item)}</li>" for item in identity.get("gaps") or [])
        assessment_html = (
            '<section class="assessment"><h2>Identity assessment</h2>'
            f'<div class="band {(identity.get("band") or "").lower()}">'
            f'{_h(str(identity.get("band", "")).upper())} · '
            f'{_h(identity.get("score", 0))}/100</div>'
            f'<p class="verdict">{_h(identity.get("verdict", ""))}</p>'
            f"{table}"
            + (f'<ul class="notes">{conflicts}</ul>' if conflicts else "")
            + (f'<ul class="notes">{gaps}</ul>' if gaps else "")
            + "</section>"
        )

    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    title = f"SPECTER report — {report.target}"

    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="generator" content="SPECTER {report.tool_version}">
<title>{_h(title)}</title>
<style>
  :root {{
    --bg: #0b0f14; --panel: #121821; --panel-2: #0f151d;
    --text: #e6edf3; --muted: #8b98a9; --line: #1f2a37;
    --accent: #35d0e0; --green: #3fb950; --blue: #58a6ff;
    --yellow: #d29922; --red: #f85149; --purple: #bc8cff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; background: var(--bg); color: var(--text);
    font: 15px/1.6 -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  }}
  main {{ max-width: 1080px; margin: 0 auto; padding: 40px 24px 64px; }}
  header {{ border-bottom: 1px solid var(--line); padding-bottom: 24px; margin-bottom: 28px; }}
  .brand {{ color: var(--accent); font-weight: 700; letter-spacing: .38em; font-size: 12px; }}
  h1 {{ font-size: 30px; margin: 10px 0 6px; word-break: break-word; }}
  .meta {{ color: var(--muted); font-size: 13px; }}
  .stats {{ display: flex; flex-wrap: wrap; gap: 12px; margin: 22px 0 34px; }}
  .stat {{
    flex: 1 1 120px; background: var(--panel); border: 1px solid var(--line);
    border-radius: 10px; padding: 12px 16px;
  }}
  .stat b {{ display: block; font-size: 24px; color: var(--accent); }}
  .stat span {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: .08em; }}
  h2 {{ font-size: 18px; margin: 34px 0 14px; display: flex; align-items: center; gap: 10px; }}
  .count {{ color: var(--muted); font-size: 12px; font-weight: 400; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr)); gap: 14px; }}
  .finding {{
    background: var(--panel); border: 1px solid var(--line); border-left: 3px solid var(--accent);
    border-radius: 10px; padding: 14px 16px; min-width: 0;
  }}
  .finding.found {{ border-left-color: var(--green); }}
  .finding.manual {{ border-left-color: var(--blue); }}
  .finding.info {{ border-left-color: var(--accent); }}
  .finding.blocked {{ border-left-color: var(--yellow); }}
  .finding.error {{ border-left-color: var(--red); }}
  .finding-head {{ display: flex; justify-content: space-between; gap: 8px; align-items: flex-start; }}
  h3 {{ font-size: 16px; margin: 0 0 6px; color: var(--text); word-break: break-word; }}
  .detail {{ margin: 6px 0 8px; color: #c3ceda; font-size: 13px; white-space: pre-wrap; }}
  .badge {{
    font-size: 10px; text-transform: uppercase; letter-spacing: .06em;
    padding: 2px 7px; border-radius: 999px; border: 1px solid var(--line); color: var(--muted);
    white-space: nowrap;
  }}
  .badge.found {{ color: var(--green); border-color: #1f5130; }}
  .badge.manual {{ color: var(--blue); border-color: #1f3a5c; }}
  .badge.info {{ color: var(--accent); border-color: #164a52; }}
  .badge.blocked {{ color: var(--yellow); border-color: #4a3a12; }}
  .badge.error {{ color: var(--red); border-color: #5c1f1c; }}
  .image {{ margin: 4px 0 10px; }}
  .image img {{
    display: block; width: 100%; max-height: 280px; object-fit: cover;
    border-radius: 8px; border: 1px solid var(--line); background: var(--panel-2);
  }}
  .image figcaption {{ color: var(--muted); font-size: 11px; margin-top: 4px; }}
  .image figcaption a {{ color: var(--blue); }}
  .data {{ margin: 10px 0 8px; font-size: 12px; }}
  .data div {{ display: flex; gap: 8px; border-top: 1px dashed var(--line); padding: 3px 0; }}
  .data dt {{ color: var(--muted); min-width: 96px; flex: 0 0 96px; }}
  .data dd {{ margin: 0; word-break: break-word; }}
  .collection-title {{ font-size: 12px; color: var(--muted); margin: 14px 0 6px; font-weight: 600; }}
  .collection-title span {{ font-weight: 400; color: var(--muted); }}
  .table-wrap {{ overflow-x: auto; border: 1px solid var(--line); border-radius: 8px; }}
  table.data-table {{ width: 100%; border-collapse: collapse; font-size: 11px; }}
  table.data-table th, table.data-table td {{
    text-align: left; padding: 5px 8px; border-bottom: 1px solid var(--line);
    vertical-align: top; max-width: 260px; word-break: break-word;
  }}
  table.data-table th {{ color: var(--muted); font-weight: 500; white-space: nowrap; background: var(--panel-2); }}
  table.data-table tr:last-child td {{ border-bottom: 0; }}
  .provenance {{
    display: flex; flex-wrap: wrap; gap: 6px; align-items: center;
    border-top: 1px solid var(--line); margin-top: 10px; padding-top: 8px;
    color: var(--muted); font-size: 11px;
  }}
  .provenance b {{ color: var(--muted); font-weight: 600; }}
  .link {{ color: var(--blue); text-decoration: none; word-break: break-all; }}
  .link:hover {{ text-decoration: underline; }}
  table.plain {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  table.plain th, table.plain td {{ text-align: left; padding: 8px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }}
  table.plain th {{ color: var(--muted); font-weight: 500; }}
  .notes {{ color: var(--muted); font-size: 13px; }}
  .assessment {{
    background: var(--panel); border: 1px solid var(--line); border-radius: 12px;
    padding: 18px 20px; margin: 0 0 8px;
  }}
  .assessment .band {{
    font-size: 12px; letter-spacing: .12em; color: var(--accent); font-weight: 600;
  }}
  .assessment .band.strong {{ color: var(--green); }}
  .assessment .band.moderate {{ color: var(--blue); }}
  .assessment .band.weak {{ color: var(--yellow); }}
  .assessment .verdict {{ margin: 10px 0 14px; color: #c3ceda; font-size: 15px; }}
  footer {{ margin-top: 46px; border-top: 1px solid var(--line); padding-top: 18px; color: var(--muted); font-size: 12px; }}
</style>
</head>
<body>
<main>
  <header>
    <div class="brand">S P E C T E R</div>
    <h1>{_h(report.target)}</h1>
    <div class="meta">
      {_h(report.target_type)} · generated {_h(generated)} · duration {report.duration():.1f}s ·
      SPECTER {_h(report.tool_version)}
    </div>
  </header>

  <div class="stats">
    <div class="stat"><b>{counts['found']}</b><span>Findings</span></div>
    <div class="stat"><b>{counts['images']}</b><span>Images</span></div>
    <div class="stat"><b>{counts['manual']}</b><span>Manual links</span></div>
    <div class="stat"><b>{counts['blocked']}</b><span>Blocked</span></div>
    <div class="stat"><b>{counts['errors']}</b><span>Errors</span></div>
    <div class="stat"><b>{counts['total']}</b><span>Total evidence</span></div>
  </div>

  {assessment_html}
  {''.join(sections)}
  {manual_html}
  {inactive_html}
  {notes_html}

  <footer>
    Generated by SPECTER from public sources. Findings are leads, not conclusions:
    verify each one independently. Use only for lawful, authorized investigations.
  </footer>
</main>
</body>
</html>
"""


def _normalize_format(fmt: str | None) -> str | None:
    if not fmt:
        return None
    value = fmt.lower()
    if value in ("md", "markdown"):
        return "markdown"
    if value in ("json", "html", "all"):
        return value
    return None


def write_report(report: Report, path: str | Path, fmt: str | None = None) -> list[Path]:
    """Write the report. ``fmt='all'`` writes JSON, Markdown and HTML."""
    destination = Path(path).expanduser()
    normalized = _normalize_format(fmt)
    if normalized is None:
        suffix = destination.suffix.lower()
        normalized = {
            ".md": "markdown",
            ".markdown": "markdown",
            ".html": "html",
            ".htm": "html",
        }.get(suffix, "json")

    if normalized == "all":
        stem = destination.with_suffix("") if destination.suffix else destination
        targets = [
            (stem.with_suffix(".json"), "json"),
            (stem.with_suffix(".md"), "markdown"),
            (stem.with_suffix(".html"), "html"),
        ]
    else:
        expected = {"json": ".json", "markdown": ".md", "html": ".html"}[normalized]
        suffix_kind = {
            ".json": "json",
            ".md": "markdown",
            ".markdown": "markdown",
            ".html": "html",
            ".htm": "html",
        }
        current = destination.suffix.lower()
        if current not in suffix_kind or suffix_kind[current] != normalized:
            destination = destination.with_suffix(expected)
        targets = [(destination, normalized)]

    written: list[Path] = []
    for target, kind in targets:
        target.parent.mkdir(parents=True, exist_ok=True)
        if kind == "json":
            content = json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str)
        elif kind == "markdown":
            content = render_markdown(report)
        else:
            content = render_html(report)
        target.write_text(content + ("" if content.endswith("\n") else "\n"), encoding="utf-8")
        written.append(target)
    return written
