"""Tkinter desktop interface for SPECTER.

The GUI drives the same investigation pipeline as the console, using the same
free, keyless sources: no API key is required for anything it runs. Its job is
speed of use — pick a target type, pick a phone region, run, then read the
content-first dossier, open a link, copy a block or save a report.
"""

from __future__ import annotations

import queue
import threading
import time
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from . import __version__, images
from .config import Config
from .http import HttpClient
from .investigate import run_investigation
from .models import BLOCKED, ERROR, FOUND, INFO, MANUAL, NOT_FOUND, UNKNOWN, Finding, Report
from .person import PersonInput, run_person_profile, split_values
from .regions import AUTO_LABEL, choices as region_choices, label_for, region_from_label

TARGET_TYPES: tuple[tuple[str, str], ...] = (
    ("Auto-detect", "auto"),
    ("Username", "username"),
    ("Email address", "email"),
    ("Phone number", "phone"),
    ("IP address", "ip"),
    ("Domain", "domain"),
    ("Person name", "name"),
)

SEARCH_SOURCES: tuple[tuple[str, str], ...] = (
    ("web", "Web (Bing + Google + DuckDuckGo)"),
    ("crawl", "Smart crawl (top pages)"),
    ("news", "News"),
    ("wikipedia", "Wikipedia"),
    ("wikidata", "Wikidata"),
    ("hn", "Hacker News"),
    ("stack", "Stack Overflow"),
    ("sec", "SEC EDGAR"),
    ("archive", "Internet Archive"),
)
DEFAULT_SOURCES = {"web", "news", "wikipedia", "wikidata", "hn"}

BG = "#101318"
SURFACE = "#171c24"
SURFACE_ALT = "#1e242e"
TEXT = "#e8ecf1"
MUTED = "#8b97a8"
ACCENT = "#3fd0d9"
BORDER = "#2a323d"

STATUS_TAGS = {
    FOUND: "#5fd68a",
    INFO: "#7fb8e8",
    MANUAL: "#c8b46a",
    BLOCKED: "#e0915a",
    ERROR: "#e86f6f",
    NOT_FOUND: "#6d7787",
    UNKNOWN: "#6d7787",
}
STATUS_LABELS = {
    FOUND: "found",
    INFO: "info",
    MANUAL: "manual",
    BLOCKED: "blocked",
    ERROR: "error",
    NOT_FOUND: "not found",
    UNKNOWN: "unknown",
}


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested without a display)
# ---------------------------------------------------------------------------
def _field_lines(key: str, value: Any, indent: int = 2) -> list[str]:
    pad = " " * indent
    if isinstance(value, dict) and value:
        lines = [f"{pad}{key}:"]
        for sub_key, sub_value in value.items():
            lines.extend(_field_lines(str(sub_key), sub_value, indent + 4))
        return lines
    if isinstance(value, (list, tuple)):
        if not value:
            return [f"{pad}{key}: —"]
        lines = [f"{pad}{key}:"]
        for item in value:
            if isinstance(item, dict):
                rendered = " · ".join(
                    f"{inner_key}: {inner_value}"
                    for inner_key, inner_value in item.items()
                    if inner_value not in (None, "", [], {})
                )
                lines.append(f"{pad}    • {rendered or '—'}")
            elif isinstance(item, (list, tuple)):
                lines.append(f"{pad}    • " + ", ".join(str(part) for part in item))
            else:
                lines.append(f"{pad}    • {item}")
        return lines
    if value is None or value == "":
        value = "—"
    if isinstance(value, bool):
        value = "yes" if value else "no"
    return [f"{pad}{key}: {value}"]


def finding_text(finding: Finding) -> str:
    """Content first, provenance last — the same order the console uses."""
    lines: list[str] = [finding.title or finding.source]
    if finding.status not in (FOUND, INFO):
        lines.append(f"[{STATUS_LABELS.get(finding.status, finding.status)}]")
    if finding.detail:
        lines.extend(["", finding.detail])
    for key, value in finding.data.items():
        if not lines or lines[-1] != "":
            lines.append("")
        lines.extend(_field_lines(key, value))
    if finding.images:
        lines.extend(["", "IMAGES"])
        for image in finding.images:
            size = (
                f"  ({image.width}×{image.height})"
                if image.width and image.height
                else ""
            )
            lines.append(f"  {image.kind}: {image.url}{size}".replace(": ", "  ", 1))
    lines.append("")
    provenance = f"via {finding.source}"
    if finding.url:
        provenance += f"  ·  {finding.url}"
    if finding.confidence != "high":
        provenance += f"  ·  {finding.confidence} confidence"
    if finding.elapsed_ms:
        provenance += f"  ·  {finding.elapsed_ms} ms"
    lines.append(provenance)
    return "\n".join(lines)


def report_summary(report: Report) -> str:
    counts = report.counts()
    return (
        f"{counts['total']} entries · {counts['found']} found · "
        f"{counts['manual']} manual · {counts['blocked']} blocked · "
        f"{counts['errors']} errors · {counts['images']} image(s) · "
        f"{report.duration():.1f}s"
    )


# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
class SpecterApp:
    """Main window. Network work runs off the Tk thread and reports via a queue."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.queue: queue.Queue = queue.Queue()
        self.report: Report | None = None
        self.findings: list[Finding] = []
        self._rows: dict[str, Finding] = {}
        self._thumb_image: Any = None
        self._thumb_url: str | None = None
        self._running = False

        self.root = tk.Tk()
        self.root.title(f"SPECTER {__version__} — keyless OSINT workbench")
        self.root.geometry("1180x780")
        self.root.minsize(960, 640)
        self.root.configure(bg=BG)
        self._enable_hidpi()
        self._style()
        self._build()
        self.root.after(120, self._poll)
        self.root.bind("<F5>", lambda _event: self._run_current())
        self.root.bind("<Control-s>", lambda _event: self._save())
        self.root.bind("<Control-q>", lambda _event: self.root.destroy())

    # -- setup ------------------------------------------------------------
    def _enable_hidpi(self) -> None:
        try:  # pragma: no cover - Windows-only cosmetic improvement
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            pass

    def _style(self) -> None:
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", background=BG, foreground=TEXT, fieldbackground=SURFACE)
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=SURFACE, relief="flat")
        style.configure("TLabel", background=BG, foreground=TEXT)
        style.configure("Muted.TLabel", background=BG, foreground=MUTED)
        style.configure("Card.TLabel", background=SURFACE, foreground=TEXT)
        style.configure("CardMuted.TLabel", background=SURFACE, foreground=MUTED)
        style.configure("Header.TLabel", background=BG, foreground=TEXT, font=("Segoe UI Semibold", 16))
        style.configure("Accent.TLabel", background=BG, foreground=ACCENT, font=("Segoe UI Semibold", 9))
        style.configure("TButton", background=SURFACE_ALT, foreground=TEXT, borderwidth=0, focusthickness=0, padding=(10, 6))
        style.map("TButton", background=[("active", "#2a3340"), ("disabled", "#1a1f27")], foreground=[("disabled", "#5a6472")])
        style.configure("Run.TButton", background=ACCENT, foreground="#08222a", font=("Segoe UI Semibold", 10), padding=(18, 8))
        style.map("Run.TButton", background=[("active", "#5fe0e8"), ("disabled", "#2b4c50")], foreground=[("disabled", "#5a7a80")])
        style.configure("TEntry", fieldbackground=SURFACE_ALT, foreground=TEXT, insertcolor=ACCENT, bordercolor=BORDER, lightcolor=BORDER, darkcolor=BORDER, padding=6)
        style.configure("TCombobox", fieldbackground=SURFACE_ALT, background=SURFACE_ALT, foreground=TEXT, arrowcolor=TEXT, bordercolor=BORDER, padding=4)
        style.map("TCombobox", fieldbackground=[("readonly", SURFACE_ALT)], foreground=[("readonly", TEXT)])
        style.configure("TCheckbutton", background=BG, foreground=TEXT)
        style.map("TCheckbutton", background=[("active", BG)])
        style.configure("TSpinbox", fieldbackground=SURFACE_ALT, foreground=TEXT, arrowcolor=TEXT, bordercolor=BORDER)
        style.configure("Treeview", background=SURFACE, fieldbackground=SURFACE, foreground=TEXT, bordercolor=BORDER, borderwidth=0, rowheight=24)
        style.configure("Treeview.Heading", background=SURFACE_ALT, foreground=MUTED, relief="flat", font=("Segoe UI Semibold", 9))
        style.map("Treeview.Heading", background=[("active", SURFACE_ALT)])
        style.map("Treeview", background=[("selected", "#26414b")], foreground=[("selected", "#ffffff")])
        style.configure("TProgressbar", background=ACCENT, troughcolor=SURFACE_ALT, bordercolor=SURFACE_ALT)
        style.configure("TPanedwindow", background=BG)
        style.configure("Sash", background=BORDER)
        style.configure("TNotebook", background=BG, borderwidth=0, tabmargins=(0, 0, 0, 0))
        style.configure("TNotebook.Tab", background=SURFACE_ALT, foreground=MUTED, padding=(14, 6), borderwidth=0)
        style.map(
            "TNotebook.Tab",
            background=[("selected", SURFACE)],
            foreground=[("selected", ACCENT)],
        )

    def _build(self) -> None:
        header = ttk.Frame(self.root)
        header.pack(fill="x", padx=18, pady=(16, 6))
        ttk.Label(header, text="SPECTER", style="Header.TLabel").pack(side="left")
        ttk.Label(
            header,
            text=f"  v{__version__} · person investigations",
            style="Muted.TLabel",
        ).pack(side="left", padx=(4, 0))
        ttk.Label(header, text="ALL SOURCES KEYLESS", style="Accent.TLabel").pack(side="right")

        controls = ttk.Frame(self.root, style="Card.TFrame")
        controls.pack(fill="x", padx=18, pady=(4, 8))
        inner = ttk.Frame(controls, style="Card.TFrame")
        inner.pack(fill="x", padx=14, pady=12)

        self.notebook = ttk.Notebook(inner)
        self.notebook.pack(fill="x")
        single = ttk.Frame(self.notebook, style="Card.TFrame")
        self.notebook.add(single, text="Single target")
        person_tab = ttk.Frame(self.notebook, style="Card.TFrame")
        self.notebook.add(person_tab, text="Person profile (correlated)")

        row = ttk.Frame(single, style="Card.TFrame")
        row.pack(fill="x", padx=8, pady=8)
        ttk.Label(row, text="Target", style="CardMuted.TLabel").pack(side="left")
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(row, textvariable=self.target_var, font=("Consolas", 11))
        self.target_entry.pack(side="left", fill="x", expand=True, padx=(8, 10))
        self.target_entry.bind("<Return>", lambda _event: self._run())
        self.type_var = tk.StringVar(value=TARGET_TYPES[0][0])
        self.type_box = ttk.Combobox(
            row,
            textvariable=self.type_var,
            values=[label for label, _ in TARGET_TYPES],
            state="readonly",
            width=17,
        )
        self.type_box.pack(side="left", padx=(0, 10))
        self.type_box.bind("<<ComboboxSelected>>", lambda _event: self._on_type_change())
        self.run_button = ttk.Button(row, text="Run  ▸", style="Run.TButton", command=self._run)
        self.run_button.pack(side="left")
        self._build_person_tab(person_tab)

        options = ttk.Frame(inner, style="Card.TFrame")
        options.pack(fill="x", pady=(12, 0))

        ttk.Label(options, text="Phone region", style="CardMuted.TLabel").grid(row=0, column=0, sticky="w")
        self.region_var = tk.StringVar(value=label_for(self.config.get("phone_region")))
        self.region_values = [AUTO_LABEL] + [label for label, _ in region_choices()]
        self.region_box = ttk.Combobox(
            options,
            textvariable=self.region_var,
            values=self.region_values,
            state="readonly",
            width=34,
        )
        self.region_box.grid(row=0, column=1, sticky="w", padx=(8, 18))

        ttk.Label(options, text="Results per source", style="CardMuted.TLabel").grid(row=0, column=2, sticky="w")
        self.limit_var = tk.IntVar(value=8)
        ttk.Spinbox(options, from_=1, to=30, textvariable=self.limit_var, width=5).grid(
            row=0, column=3, sticky="w", padx=(8, 18)
        )

        self.subdomains_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            options,
            text="Passive subdomains (slow)",
            variable=self.subdomains_var,
        ).grid(row=0, column=4, sticky="w", padx=(0, 14))
        self.images_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(options, text="Show images", variable=self.images_var).grid(
            row=0, column=5, sticky="w"
        )

        ttk.Label(options, text="Search sources", style="CardMuted.TLabel").grid(
            row=1, column=0, sticky="w", pady=(10, 0)
        )
        sources_frame = ttk.Frame(options, style="Card.TFrame")
        sources_frame.grid(row=1, column=1, columnspan=5, sticky="w", padx=(8, 0), pady=(8, 0))
        self.source_vars: dict[str, tk.BooleanVar] = {}
        for index, (key, label) in enumerate(SEARCH_SOURCES):
            variable = tk.BooleanVar(value=key in DEFAULT_SOURCES)
            self.source_vars[key] = variable
            ttk.Checkbutton(sources_frame, text=label, variable=variable).grid(
                row=index // 4, column=index % 4, sticky="w", padx=(0, 16), pady=1
            )

        self.hint_var = tk.StringVar(
            value="Phone region is used only for numbers typed without a +country code."
        )
        ttk.Label(inner, textvariable=self.hint_var, style="CardMuted.TLabel").pack(
            fill="x", pady=(10, 0)
        )

        panes = ttk.Panedwindow(self.root, orient="vertical")
        panes.pack(fill="both", expand=True, padx=18, pady=(0, 8))

        results_frame = ttk.Frame(panes, style="Card.TFrame")
        toolbar = ttk.Frame(results_frame, style="Card.TFrame")
        toolbar.pack(fill="x", padx=10, pady=(8, 4))
        ttk.Label(toolbar, text="Results", style="CardMuted.TLabel").pack(side="left")
        ttk.Label(toolbar, text="Filter", style="CardMuted.TLabel").pack(side="left", padx=(16, 6))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self._render_tree())
        ttk.Entry(toolbar, textvariable=self.filter_var, width=26).pack(side="left")
        self.save_button = ttk.Button(toolbar, text="Save report", command=self._save)
        self.save_button.pack(side="right", padx=(6, 0))
        self.open_button = ttk.Button(toolbar, text="Open link", command=self._open_link)
        self.open_button.pack(side="right", padx=(6, 0))
        self.copy_button = ttk.Button(toolbar, text="Copy entry", command=self._copy)
        self.copy_button.pack(side="right")
        self.progress = ttk.Progressbar(toolbar, mode="indeterminate", length=120)
        self.progress.pack(side="right", padx=12)

        tree_wrap = ttk.Frame(results_frame, style="Card.TFrame")
        tree_wrap.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        columns = ("category", "status", "source", "title")
        self.tree = ttk.Treeview(tree_wrap, columns=columns, show="headings", selectmode="browse")
        for column, heading, width, anchor in (
            ("category", "Category", 130, "w"),
            ("status", "Status", 80, "w"),
            ("source", "Source", 190, "w"),
            ("title", "", 620, "w"),
        ):
            self.tree.heading(column, text=heading)
            self.tree.column(column, width=width, anchor=anchor, stretch=column == "title")
        for status, color in STATUS_TAGS.items():
            self.tree.tag_configure(status, foreground=color)
        scrollbar = ttk.Scrollbar(tree_wrap, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", lambda _event: self._show_selected())
        self.tree.bind("<Double-1>", lambda _event: self._open_link())

        detail_frame = ttk.Frame(panes, style="Card.TFrame")
        detail_top = ttk.Frame(detail_frame, style="Card.TFrame")
        detail_top.pack(fill="both", expand=True, padx=10, pady=(8, 8))
        text_wrap = ttk.Frame(detail_top, style="Card.TFrame")
        text_wrap.pack(side="left", fill="both", expand=True)
        self.detail = tk.Text(
            text_wrap,
            wrap="word",
            bg=SURFACE,
            fg=TEXT,
            insertbackground=ACCENT,
            relief="flat",
            padx=10,
            pady=8,
            font=("Consolas", 10),
            height=12,
        )
        detail_scroll = ttk.Scrollbar(text_wrap, orient="vertical", command=self.detail.yview)
        self.detail.configure(yscrollcommand=detail_scroll.set, state="disabled")
        self.detail.pack(side="left", fill="both", expand=True)
        detail_scroll.pack(side="right", fill="y")

        self.thumb = tk.Label(
            detail_top,
            text="",
            bg=SURFACE_ALT,
            fg=MUTED,
            width=30,
            height=10,
            relief="flat",
            font=("Segoe UI", 9),
        )
        self.thumb.pack(side="right", fill="y", padx=(10, 0))

        panes.add(results_frame, weight=3)
        panes.add(detail_frame, weight=2)

        footer = ttk.Frame(self.root)
        footer.pack(fill="x", padx=18, pady=(0, 12))
        self.status_var = tk.StringVar(
            value="Ready — every source is free and keyless. API keys are optional (specter config --show)."
        )
        ttk.Label(footer, textvariable=self.status_var, style="Muted.TLabel").pack(side="left")
        self.notes_label = ttk.Label(footer, text="", style="Muted.TLabel")
        self.notes_label.pack(side="right")

    # -- interactions -----------------------------------------------------
    def _on_type_change(self) -> None:
        target_type = dict((label, value) for label, value in TARGET_TYPES)[self.type_var.get()]
        if target_type == "phone":
            self.hint_var.set(
                "Region applies to local formats such as 06 12 34 56 78. "
                "Numbers starting with + are parsed as-is."
            )
        elif target_type == "auto":
            self.hint_var.set("Target type is detected from the value you type.")
        else:
            self.hint_var.set(f"Running the {target_type} modules plus a scoped search.")

    def _selected_sources(self) -> list[str]:
        return [key for key, variable in self.source_vars.items() if variable.get()]

    def _build_person_tab(self, parent: ttk.Frame) -> None:
        fields = (
            ("first", "First name"),
            ("last", "Last name"),
            ("aliases", "Aliases / nicknames"),
            ("emails", "Email addresses"),
            ("phones", "Phone numbers"),
            ("usernames", "Usernames"),
            ("domains", "Domains"),
            ("ips", "IP addresses"),
            ("location", "Location"),
            ("employer", "Employer"),
        )
        self.person_vars: dict[str, tk.StringVar] = {}
        grid = ttk.Frame(parent, style="Card.TFrame")
        grid.pack(fill="x", padx=8, pady=(8, 4))
        for index, (key, label) in enumerate(fields):
            column = (index % 2) * 2
            row_index = index // 2
            ttk.Label(grid, text=label, style="CardMuted.TLabel").grid(
                row=row_index, column=column, sticky="w", padx=(0, 6), pady=3
            )
            variable = tk.StringVar()
            self.person_vars[key] = variable
            entry = ttk.Entry(grid, textvariable=variable, width=30)
            entry.grid(row=row_index, column=column + 1, sticky="ew", padx=(0, 18), pady=3)
            entry.bind("<Return>", lambda _event: self._run_person())
        grid.columnconfigure(1, weight=1)
        grid.columnconfigure(3, weight=1)

        ttk.Label(
            parent,
            text=(
                "Comma-separate several emails, phones or handles. Everything you enter is "
                "searched at once, then correlated into one scored conclusion."
            ),
            style="CardMuted.TLabel",
            wraplength=980,
        ).pack(fill="x", padx=8)
        run_row = ttk.Frame(parent, style="Card.TFrame")
        run_row.pack(fill="x", padx=8, pady=(6, 8))
        self.person_run_button = ttk.Button(
            run_row,
            text="Run all & correlate  ▸",
            style="Run.TButton",
            command=self._run_person,
        )
        self.person_run_button.pack(side="left")

    def _run_current(self) -> None:
        if self.notebook.index("current") == 1:
            self._run_person()
        else:
            self._run()

    def _run_person(self) -> None:
        if self._running:
            return
        person = PersonInput(
            first_name=self.person_vars["first"].get(),
            last_name=self.person_vars["last"].get(),
            aliases=split_values(self.person_vars["aliases"].get()),
            emails=split_values(self.person_vars["emails"].get()),
            phones=split_values(self.person_vars["phones"].get()),
            usernames=split_values(self.person_vars["usernames"].get()),
            domains=split_values(self.person_vars["domains"].get()),
            ips=split_values(self.person_vars["ips"].get()),
            location=self.person_vars["location"].get(),
            employer=self.person_vars["employer"].get(),
        )
        if person.is_empty():
            self.status_var.set("Enter at least one identifier for the person profile.")
            return
        self._running = True
        self.run_button.configure(state="disabled")
        self.person_run_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set("Running every identifier, then correlating…")
        threading.Thread(
            target=self._person_worker,
            args=(
                person,
                self._selected_sources(),
                max(1, self.limit_var.get()),
                region_from_label(self.region_var.get()),
                self.subdomains_var.get(),
                self.images_var.get(),
            ),
            daemon=True,
        ).start()

    def _person_worker(
        self,
        person: PersonInput,
        sources: list[str],
        limit: int,
        region: str | None,
        subdomains: bool,
        include_images: bool,
    ) -> None:
        started = time.perf_counter()
        try:
            if region:
                self.config.set_runtime("phone_region", region)
            http = HttpClient(
                timeout=self.config.timeout,
                proxy=self.config.get("proxy") or None,
                retries=2,
            )
            report = run_person_profile(
                person,
                http,
                self.config,
                sources=sources or None,
                limit=limit,
                region=region,
                subdomains=subdomains,
                include_images=include_images,
            )
            report.finish()
            self.queue.put(("done", report, time.perf_counter() - started))
        except Exception as exc:  # noqa: BLE001 - surfaced in the status bar
            self.queue.put(
                ("error", f"{type(exc).__name__}: {exc}", time.perf_counter() - started)
            )

    def _run(self) -> None:
        if self._running:
            return
        target = self.target_var.get().strip()
        if not target:
            self.status_var.set("Enter a target first.")
            return
        target_type = dict((label, value) for label, value in TARGET_TYPES)[self.type_var.get()]
        sources = self._selected_sources()
        region = region_from_label(self.region_var.get())
        self._running = True
        self.run_button.configure(state="disabled")
        self.progress.start(12)
        self.status_var.set(f"Running {target_type} modules for {target}…")
        thread = threading.Thread(
            target=self._worker,
            args=(
                target,
                target_type,
                sources,
                max(1, self.limit_var.get()),
                self.subdomains_var.get(),
                region,
                self.images_var.get(),
            ),
            daemon=True,
        )
        thread.start()

    def _worker(
        self,
        target: str,
        target_type: str,
        sources: list[str],
        limit: int,
        subdomains: bool,
        region: str | None,
        include_images: bool,
    ) -> None:
        started = time.perf_counter()
        try:
            if region:
                self.config.set_runtime("phone_region", region)
            http = HttpClient(
                timeout=self.config.timeout,
                proxy=self.config.get("proxy") or None,
                retries=2,
            )
            report = run_investigation(
                target,
                target_type,
                http,
                self.config,
                sources=sources or None,
                limit=limit,
                subdomains=subdomains,
                include_images=include_images,
            )
            report.finish()
            self.queue.put(("done", report, time.perf_counter() - started))
        except Exception as exc:  # noqa: BLE001 - surfaced in the status bar
            self.queue.put(("error", f"{type(exc).__name__}: {exc}", time.perf_counter() - started))

    def _poll(self) -> None:
        try:
            while True:
                message = self.queue.get_nowait()
                kind = message[0]
                if kind == "done":
                    self._finish(message[1], message[2])
                elif kind == "error":
                    self._finish(None, message[2], message[1])
                elif kind == "thumb":
                    self._apply_thumb(message[1], message[2])
        except queue.Empty:
            pass
        self.root.after(120, self._poll)

    def _finish(self, report: Report | None, elapsed: float, error: str | None = None) -> None:
        self._running = False
        self.run_button.configure(state="normal")
        self.person_run_button.configure(state="normal")
        self.progress.stop()
        if error or report is None:
            self.status_var.set(f"Failed after {elapsed:.1f}s — {error}")
            return
        self.report = report
        self.findings = list(report.findings)
        self._render_tree()
        identity = report.identity or {}
        if identity:
            self.status_var.set(
                f"Verdict: {str(identity.get('band', '')).upper()} "
                f"{identity.get('score', 0)}/100 — {report_summary(report)}"
            )
        else:
            self.status_var.set(report_summary(report))
        self.notes_label.configure(text=f"{len(report.notes)} note(s)")
        if self.findings:
            self.tree.selection_set(self.tree.get_children()[0])

    def _render_tree(self) -> None:
        query = self.filter_var.get().strip().lower()
        self.tree.delete(*self.tree.get_children())
        self._rows.clear()
        for finding in self.findings:
            title = finding.title or finding.detail or ""
            blob = f"{finding.category} {finding.source} {finding.status} {title} {finding.detail or ''}".lower()
            if query and query not in blob:
                continue
            iid = self.tree.insert(
                "",
                "end",
                values=(
                    finding.category,
                    STATUS_LABELS.get(finding.status, finding.status),
                    finding.source,
                    title[:160],
                ),
                tags=(finding.status,),
            )
            self._rows[iid] = finding

    def _show_selected(self) -> None:
        selection = self.tree.selection()
        if not selection:
            return
        finding = self._rows.get(selection[0])
        if finding is None:
            return
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        self.detail.insert("1.0", finding_text(finding))
        self.detail.configure(state="disabled")
        self._load_thumb(finding)

    def _load_thumb(self, finding: Finding) -> None:
        url = finding.images[0].url if finding.images else None
        if url == self._thumb_url:
            return
        self._thumb_url = url
        self._thumb_image = None
        self.thumb.configure(image="", text="")
        if not url or not self.images_var.get():
            self.thumb.configure(text="no image")
            return
        self.thumb.configure(text="loading image…")
        pending_url = url

        def worker() -> None:
            fetched = images.fetch_bytes(pending_url, timeout=8)
            self.queue.put(("thumb", pending_url, fetched))

        threading.Thread(target=worker, daemon=True).start()

    def _apply_thumb(self, url: str, fetched: Any) -> None:
        if url != self._thumb_url:
            return
        if not fetched:
            self.thumb.configure(image="", text="image unavailable")
            return
        try:
            import io

            from PIL import Image, ImageTk

            with Image.open(io.BytesIO(fetched[0])) as source:
                source.seek(0)
                image = source.convert("RGB")
                image.thumbnail((260, 200))
                photo = ImageTk.PhotoImage(image)
        except Exception:  # noqa: BLE001 - previews are best-effort
            self.thumb.configure(image="", text="preview unavailable")
            return
        self._thumb_image = photo
        self.thumb.configure(image=photo, text="")

    def _open_link(self) -> None:
        selection = self.tree.selection()
        finding = self._rows.get(selection[0]) if selection else None
        if finding and finding.url:
            webbrowser.open(finding.url)
        elif finding and finding.images:
            webbrowser.open(finding.images[0].url)
        else:
            self.status_var.set("That entry has no link to open.")

    def _copy(self) -> None:
        selection = self.tree.selection()
        finding = self._rows.get(selection[0]) if selection else None
        if not finding:
            return
        self.root.clipboard_clear()
        self.root.clipboard_append(finding_text(finding))
        self.status_var.set(f"Copied '{finding.title or finding.source}' to the clipboard.")

    def _save(self) -> None:
        if self.report is None:
            self.status_var.set("Run an investigation before saving a report.")
            return
        stamp = self.report.started.strftime("%Y%m%d-%H%M%S")
        default = f"{self.report.target_type.replace(' ', '-')}-{self.report.target}-{stamp}.json"
        default = "".join(char if char.isalnum() or char in "._-" else "-" for char in default)
        path = filedialog.asksaveasfilename(
            title="Save SPECTER report",
            defaultextension=".json",
            initialfile=default,
            filetypes=[
                ("JSON", "*.json"),
                ("Markdown", "*.md"),
                ("HTML", "*.html"),
            ],
        )
        if not path:
            return
        try:
            written = self.report.save(Path(path))
        except OSError as exc:
            messagebox.showerror("SPECTER", f"Could not write the report: {exc}")
            return
        self.status_var.set("Saved " + ", ".join(str(item) for item in written))
        if messagebox.askyesno("SPECTER", "Report saved. Open the containing folder?"):
            webbrowser.open(str(Path(path).parent))

    # -- lifecycle --------------------------------------------------------
    def run(self) -> None:
        self.target_entry.focus_set()
        self.root.mainloop()

    def destroy(self) -> None:
        self.root.destroy()


def launch(config: Config | None = None) -> int:
    """Open the desktop window. Returns a process exit code."""
    try:
        app = SpecterApp(config or Config())
    except tk.TclError as exc:
        print(f"SPECTER's graphical interface needs a desktop session: {exc}")
        print("Use the console instead: specter  (or specter help)")
        return 1
    app.run()
    return 0


def main() -> int:
    return launch(Config())
