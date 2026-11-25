"""SPECTER command line interface and interactive console."""

from __future__ import annotations

import argparse
import json
import re
import shlex
import sys
from contextlib import nullcontext
from pathlib import Path
from typing import Any, Iterable

from rich import box
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from . import __tagline__, __version__
from . import console as ui
from . import images as image_util
from .config import KEYS, KEY_BY_NAME, Config
from .http import HttpClient
from .investigate import KIND_BY_TYPE, detect_target, run_investigation
from .models import ERROR, FOUND, INFO, Finding, Report
from .person import PersonInput, run_person_profile
from .modules.breaches import check_breaches
from .modules.domain import investigate_domain, normalize_domain
from .modules.email import investigate_email, validate_email
from .modules.github import investigate_github
from .modules.ip import investigate_ip
from .modules.phone import investigate_phone
from .crawl import SmartCrawler, Target, sitemap_seeds
from .modules.scrape import crawl_findings, looks_like_url
from .modules.search import ALL_SOURCES, dork_links, dork_queries, search_all, search_web
from .modules.username import investigate_username, load_sites, validate_username

MENU = [
    ("1", "Username sweep", "Check a handle across 76 platforms"),
    ("2", "Email intelligence", "Accounts, Gravatar, mail domain, breaches"),
    ("3", "Phone intelligence", "Carrier, region, line type, formats"),
    ("4", "IP address", "Geolocation, WHOIS, reverse DNS"),
    ("5", "Domain / website", "WHOIS, DNS, subdomains, HTTP fingerprint"),
    ("6", "GitHub deep dive", "Repos, orgs, activity, commit emails"),
    ("7", "Breach check", "Breaches, pastes and risk score (keyless)"),
    ("8", "Web & news search", "Dorks, news, Wikipedia, forums, filings"),
    ("9", "Full investigation", "Auto-detect target type and run everything"),
    ("10", "Settings", "API keys and configuration"),
    ("11", "Graphical interface", "Desktop workbench with region picker"),
    ("0", "Exit", "Leave the console"),
]

HELP = """[bold cyan]Commands[/]

  [white]username <handle>[/]      Sweep a handle across public platforms
  [white]email <address>[/]        Email accounts, Gravatar and mail-domain posture
  [white]phone <number>[/]         Phone metadata (use +international format)
  [white]ip <address>[/]           Geolocation, WHOIS and PTR record
  [white]domain <name>[/]          WHOIS, DNS, HTTP fingerprint, subdomains
  [white]github <username>[/]      Deep GitHub profile, repositories and commit emails
  [white]breach <email>[/]         Breach exposure, data classes and risk score
  [white]gui[/]                    Open the desktop workbench (Tkinter)
  [white]search <query>[/]         Web, news, Wikipedia, Wikidata and forum search
  [white]investigate <target>[/]   Auto-detect and run the relevant modules
  [white]scrape <url|query>[/]     Smart crawl: rank links, fetch only the relevant pages
  [white]person[/]                 Correlate a name, email, phone, handle(s) into one conclusion
  [white]keys[/]                    List optional keys, free tiers and validate them
  [white]config --show[/]          Show API keys and settings
  [white]menu[/]                   Redraw the numbered menu
  [white]clear[/]                  Clear the screen
  [white]exit[/]                   Quit

[bold cyan]Useful flags[/]

  [white]--json[/]                 Machine-readable output
  [white]-o report.html --format html[/]   Save a report (json, md, html, all)
  [white]--verbose[/]              Show every inactive source
  [white]--no-dorks[/]             Skip the search-link suggestions
  [white]--no-images[/]            Skip image fetching and previews
  [white]--only GitHub,GitLab[/]   Limit a username sweep to specific platforms

[bold cyan]Keyless by default[/]

  Every module runs without an API key. Keys only add depth: HIBP, Shodan,
  IPinfo, Numverify, Google CSE, Brave, CourtListener or a SearXNG instance.

[dim]Examples[/]
  [dim]specter username torvalds --format html -o reports/torvalds[/]
  [dim]specter email someone@example.com --json[/]
  [dim]specter investigate "Jane Doe" --source all --limit 10[/]
  [dim]specter person --first Jane --last Doe --email jane@example.com --username jdoe[/]
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _configure_stdio() -> None:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (OSError, ValueError):
                pass


def _split_list(values: Iterable[str] | None) -> list[str]:
    if not values:
        return []
    items: list[str] = []
    for value in values:
        for part in value.split(","):
            part = part.strip()
            if part:
                items.append(part)
    return items


def _slug(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return (cleaned or "target")[:48]


def default_report_path(report: Report, config: Config, extension: str = ".json") -> Path:
    stamp = report.started.strftime("%Y%m%d-%H%M%S")
    name = f"{report.target_type.replace(' ', '-')}-{_slug(report.target)}-{stamp}{extension}"
    return config.save_dir / name


def _build_http(config: Config) -> HttpClient:
    return HttpClient(
        timeout=config.timeout,
        proxy=config.get("proxy") or None,
        retries=2,
    )


def _print_dorks(target: str, kind: str) -> None:
    ui.dork_panel(dork_links(target, kind), title=f"Search {target}")
    queries = dork_queries(target, kind)
    if queries:
        ui.query_panel(queries, title="Suggested dorks — paste into any search engine")


def _finalize(
    report: Report,
    args: argparse.Namespace,
    config: Config,
    *,
    target: str,
    kind: str,
    interactive: bool = False,
) -> int:
    report.finish()

    show_images = not getattr(args, "no_images", False)
    if getattr(args, "json", False):
        print(json.dumps(report.to_dict(), indent=2, ensure_ascii=False, default=str))
    else:
        if show_images and ui.out().is_terminal:
            image_urls = [image.url for finding in report.findings for image in finding.images]
            image_util.prefetch(image_urls, width=24, limit=8)
        ui.render_report(
            report,
            verbose=getattr(args, "verbose", False),
            show_images=show_images,
        )
        if not getattr(args, "no_dorks", False):
            _print_dorks(target, kind)

    if interactive and not getattr(args, "output", None):
        try:
            answer = ui.out().input("\n  [cyan]Save this report?[/] [dim]\\[y/N][/] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = ""
        if answer in ("y", "yes"):
            args.output = str(default_report_path(report, config))

    output = getattr(args, "output", None)
    if output:
        destination = Path(output).expanduser()
        if destination.is_dir():
            destination = destination / default_report_path(report, config).name
        try:
            written = report.save(destination, getattr(args, "format", None))
        except OSError as exc:
            ui.error(f"Could not write the report: {exc}")
            return 1
        for path in written:
            message = f"Report saved to {path}"
            if getattr(args, "json", False):
                print(message, file=sys.stderr)
            else:
                ui.success(message)
    return 0


def _is_json(args: argparse.Namespace) -> bool:
    return bool(getattr(args, "json", False))


def _heading(args: argparse.Namespace, title: str, subtitle: str | None = None) -> None:
    if not _is_json(args):
        ui.rule(title, subtitle)


def _fail(args: argparse.Namespace, message: str, code: int = 2) -> int:
    if _is_json(args):
        print(json.dumps({"error": message}))
    else:
        ui.error(message)
    return code


def _spinner(message: str, args: argparse.Namespace | None = None):
    if args is not None and _is_json(args):
        return nullcontext()
    return ui.out().status(f"[cyan]{message}[/]", spinner="dots")


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------
def cmd_username(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    try:
        username = validate_username(args.target)
    except ValueError as exc:
        return _fail(args, str(exc))

    only = _split_list(getattr(args, "only", None))
    exclude = _split_list(getattr(args, "exclude", None))
    sites = load_sites()
    if only:
        sites = [site for site in sites if site["name"].lower() in {n.lower() for n in only}]
    if exclude:
        sites = [site for site in sites if site["name"].lower() not in {n.lower() for n in exclude}]

    _heading(args, "Username sweep", f"{username} · {len(sites)} platforms")
    report = Report(
        target=username,
        target_type="username",
        options={"platforms": len(sites), "only": only or None, "exclude": exclude or None},
    )
    found = {"count": 0}

    if ui.out().is_terminal and not _is_json(args):
        progress = Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[bold]{task.description}"),
            BarColumn(bar_width=32, style="grey30", complete_style="cyan"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            console=ui.out(),
            transient=True,
        )
        with progress:
            task = progress.add_task(f"Scanning · 0 found", total=len(sites))

            def on_result(finding) -> None:
                if finding.status == FOUND:
                    found["count"] += 1
                progress.update(
                    task,
                    advance=1,
                    description=f"Scanning · {found['count']} found",
                )

            findings = investigate_username(
                username,
                http,
                config,
                only=only or None,
                exclude=exclude or None,
                workers=getattr(args, "workers", None),
                on_result=on_result,
            )
    else:
        with _spinner(f"Scanning {len(sites)} platforms…", args):
            findings = investigate_username(
                username,
                http,
                config,
                only=only or None,
                exclude=exclude or None,
                workers=getattr(args, "workers", None),
            )

    report.extend(findings)
    return _finalize(report, args, config, target=username, kind="username", interactive=interactive)


def cmd_email(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    try:
        email = validate_email(args.target)
    except ValueError as exc:
        return _fail(args, str(exc))

    _heading(args, "Email intelligence", email)
    report = Report(target=email, target_type="email address")
    with _spinner("Checking accounts, Gravatar and mail domain…", args):
        findings = investigate_email(
            email,
            http,
            config,
            include_breaches=not getattr(args, "no_breaches", False),
            include_probes=not getattr(args, "no_probes", False),
        )
    report.extend(findings)
    if not getattr(args, "no_breaches", False):
        report.notes.append(
            "Breach exposure is checked keylessly via XposedOrNot; an optional "
            "HIBP_API_KEY adds Have I Been Pwned's verified records."
        )
    report.notes.append(
        "Sign-up probes only read public validation responses; no email is sent and "
        "the target is not notified."
    )
    return _finalize(report, args, config, target=email, kind="email", interactive=interactive)


def cmd_phone(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    _heading(args, "Phone intelligence", args.target)
    report = Report(target=args.target, target_type="phone number")
    with _spinner("Parsing number and metadata…", args):
        findings = investigate_phone(
            args.target, http, config, region=getattr(args, "region", None)
        )
    report.extend(findings)
    report.notes.append(
        "Carrier data is derived from libphonenumber prefix metadata; ported numbers "
        "may differ. No SMS or call is made."
    )
    return _finalize(report, args, config, target=args.target, kind="phone", interactive=interactive)


def cmd_ip(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    _heading(args, "IP address intelligence", args.target)
    report = Report(target=args.target, target_type="IP address")
    with _spinner("Geolocating and querying WHOIS…", args):
        findings = investigate_ip(args.target, http, config)
    report.extend(findings)
    report.notes.append(
        "IP geolocation is approximate and identifies the network, not a person. "
        "Mobile, VPN and carrier-grade NAT addresses are especially imprecise."
    )
    return _finalize(report, args, config, target=args.target, kind="ip", interactive=interactive)


def cmd_domain(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    try:
        domain = normalize_domain(args.target)
    except ValueError as exc:
        return _fail(args, str(exc))
    _heading(args, "Domain intelligence", domain)
    report = Report(
        target=domain,
        target_type="domain",
        options={"subdomains": bool(getattr(args, "subdomains", False))},
    )
    with _spinner("Collecting WHOIS, DNS and HTTP data…", args):
        findings = investigate_domain(
            domain, http, config, include_subdomains=bool(getattr(args, "subdomains", False))
        )
    report.extend(findings)
    if not getattr(args, "subdomains", False):
        report.notes.append("Subdomain enumeration skipped; add --subdomains to enable passive discovery.")
    return _finalize(report, args, config, target=domain, kind="domain", interactive=interactive)


def cmd_github(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    username = args.target.strip().lstrip("@")
    _heading(args, "GitHub deep dive", username)
    report = Report(target=username, target_type="GitHub account")
    with _spinner("Reading profile, organisations, repositories and activity…", args):
        findings = investigate_github(
            username, http, config, repo_limit=getattr(args, "repo_limit", 100)
        )
    report.extend(findings)
    if not config.get("github_token"):
        report.notes.append(
            "Unauthenticated GitHub API calls are limited to 60/hour. Set GITHUB_TOKEN "
            "for full coverage."
        )
    return _finalize(report, args, config, target=username, kind="username", interactive=interactive)


def cmd_breach(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    try:
        email = validate_email(args.target)
    except ValueError as exc:
        return _fail(args, str(exc))
    _heading(args, "Breach check", email)
    report = Report(target=email, target_type="email address")
    with _spinner("Querying Have I Been Pwned…", args):
        findings = check_breaches(email, http, config, explain_missing_key=True)
    report.extend(findings)
    return _finalize(report, args, config, target=email, kind="email", interactive=interactive)


def cmd_search(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    query = args.target.strip()
    if not query:
        return _fail(args, "Search query cannot be empty.")
    kind = getattr(args, "type", None) or detect_target(query)
    sources = _split_list(getattr(args, "source", None))
    if not sources:
        sources = ["web", "news", "wikipedia", "wikidata", "hn"]
        if kind == "name":
            sources.append("sec")
    _heading(args, "Search", f"{query} · {', '.join(sources)}")

    report = Report(
        target=query,
        target_type=f"search ({kind})",
        options={"sources": sources, "limit": getattr(args, "limit", 8)},
    )
    with _spinner("Searching public sources…", args):
        findings = search_all(
            query,
            http,
            config,
            sources=sources,
            limit=getattr(args, "limit", 8),
            kind=kind,
            include_images=not getattr(args, "no_images", False),
        )
    report.extend(findings)
    report.notes.append(
        "Web results are merged from three keyless engines (Bing, Google and "
        "DuckDuckGo) and scored by cross-engine agreement. Google often returns "
        "its JavaScript wall; that is reported as blocked. Optional SEARXNG_URL, "
        "GOOGLE_API_KEY + GOOGLE_CSE_ID or BRAVE_API_KEY add more engines."
    )
    return _finalize(report, args, config, target=query, kind=kind, interactive=interactive)


def cmd_investigate(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    target = args.target.strip()
    try:
        target_type = args.type if getattr(args, "type", "auto") != "auto" else detect_target(target)
    except ValueError as exc:
        return _fail(args, str(exc))

    _heading(args, "Full investigation", f"{target} · {target_type}")
    sources = _split_list(getattr(args, "source", None)) or None
    with _spinner("Running the relevant modules…", args):
        report = run_investigation(
            target,
            target_type,
            http,
            config,
            sources=sources,
            limit=getattr(args, "limit", 8),
            subdomains=bool(getattr(args, "subdomains", False)),
            include_images=not getattr(args, "no_images", False),
        )
    kind = KIND_BY_TYPE.get(target_type, "name")
    return _finalize(
        report, args, config, target=report.target, kind=kind, interactive=interactive
    )


def cmd_scrape(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    target = args.target.strip()
    if not target:
        return _fail(args, "Give a URL to start from, or a query to seed the crawl with.")
    is_url = looks_like_url(target)
    kind = getattr(args, "type", None) or ("domain" if is_url else "name")
    _heading(args, "Smart crawl", target)

    seeds = [(seed.strip(), "") for seed in (getattr(args, "seed", None) or []) if seed.strip()]
    if is_url:
        seeds.insert(0, (target if "://" in target else f"https://{target}", ""))

    report = Report(
        target=target,
        target_type="smart crawl",
        options={
            "pages": args.pages,
            "depth": args.depth,
            "min_score": args.min_score,
            "seeds": [seed for seed, _ in seeds],
        },
    )
    with _spinner("Ranking links against the target and crawling the best pages…", args):
        if is_url:
            crawler = SmartCrawler(http, budget=max(1, args.pages))
            extra = sitemap_seeds(crawler.fetcher, target, Target.from_query(target, args.term), limit=args.pages)
            if extra:
                seeds.extend(extra)
                report.notes.append(
                    f"{len(extra)} page(s) came from the site's own sitemap, scored "
                    "against the target so only plausible pages are queued."
                )
        else:
            results = search_web(
                target, http, config, limit=max(1, args.limit), include_images=False
            )
            seeds.extend((finding.url, finding.title or "") for finding in results if finding.url)
            if seeds:
                report.notes.append(
                    f"{len(seeds)} seed(s) came from a web search; only pages whose text "
                    "or links mention the target terms are fetched."
                )
            else:
                # Search engines block often; Wikipedia still answers without a key.
                fallback = search_all(
                    target,
                    http,
                    config,
                    sources=("wikipedia",),
                    limit=max(1, min(args.limit, 4)),
                    kind=kind,
                    include_images=False,
                )
                seeds.extend((f.url, f.title or "") for f in fallback if f.url)
                if seeds:
                    report.notes.append(
                        "The web engines returned nothing usable, so the crawl was "
                        "seeded from Wikipedia's search instead — these are candidate "
                        "pages for the name, not confirmed identities."
                    )
        if not seeds:
            report.add(
                Finding(
                    source="Crawl",
                    category="Web",
                    status=INFO,
                    detail="No seed URL: the web search returned nothing to start from.",
                )
            )
        else:
            report.extend(
                crawl_findings(
                    target,
                    seeds,
                    http,
                    config,
                    terms=_split_list(getattr(args, "term", None)),
                    budget=max(1, args.pages),
                    depth=max(0, args.depth),
                    min_score=args.min_score,
                    region=getattr(args, "region", None),
                )
            )
    return _finalize(report, args, config, target=target, kind=kind, interactive=interactive)


def cmd_person(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    person = PersonInput(
        first_name=args.first or "",
        last_name=args.last or "",
        name=args.name or "",
        aliases=_split_list(getattr(args, "alias", None)),
        emails=_split_list(getattr(args, "email", None)),
        phones=_split_list(getattr(args, "phone", None)),
        usernames=_split_list(getattr(args, "username", None)),
        domains=_split_list(getattr(args, "domain", None)),
        ips=_split_list(getattr(args, "ip", None)),
        location=args.location or "",
        employer=args.employer or "",
        birth_year=getattr(args, "birth_year", "") or "",
    )
    if person.is_empty():
        return _fail(
            args,
            "Supply at least one identifier: --name, --email, --username, --phone, "
            "--domain or --ip.",
        )
    _heading(args, "Person profile", person.full_name or "multi-identifier target")
    with _spinner("Running every identifier and correlating the evidence…", args):
        report = run_person_profile(
            person,
            http,
            config,
            sources=_split_list(getattr(args, "source", None)) or None,
            limit=getattr(args, "limit", 8),
            region=getattr(args, "region", None),
            subdomains=bool(getattr(args, "subdomains", False)),
            include_images=not getattr(args, "no_images", False),
        )
    return _finalize(
        report, args, config, target=report.target, kind="name", interactive=interactive
    )


def cmd_keys(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    from .keys import env_example, inventory

    if getattr(args, "env_file", False):
        target = Path(".env.example")
        if target.exists() and not getattr(args, "force", False):
            ui.warn(".env.example already exists — rerun with --force to overwrite it.")
            return 1
        target.write_text(env_example(), encoding="utf-8")
        ui.success(f"Wrote {target}. Copy it to .env and fill in the keys you obtain.")
        ui.info("SPECTER loads .env from the working directory; real environment variables still win.")
        return 0

    rows = inventory(config, http, check=bool(getattr(args, "check", False)))
    colours = {
        "valid": "green",
        "set": "cyan",
        "missing": "dim",
        "invalid": "red",
        "unreachable": "yellow",
    }
    table = Table(
        title="Optional API keys — nothing here is required",
        box=box.SIMPLE_HEAD,
        header_style="bold",
        show_lines=False,
        expand=True,
    )
    table.add_column("Key")
    table.add_column("Environment variable", no_wrap=True)
    table.add_column("Status")
    table.add_column("Free tier and where to get it")
    for row in rows:
        colour = colours.get(row.state, "white")
        where = row.free or ""
        if row.signup:
            where = f"{where}\n{row.signup}".strip()
        table.add_row(
            row.label,
            row.env,
            f"[{colour}]{row.state}[/] · {row.detail}",
            where,
        )
    ui.out().print(table)
    missing = [row for row in rows if row.state == "missing"]
    if missing and not getattr(args, "check", False):
        ui.info(
            f"{len(missing)} of {len(rows)} optional keys are unset. Run 'specter keys --check' "
            "to validate the ones you have, or 'specter keys --env-file' for a fill-in file."
        )
    ui.info("Add a key with: specter config --set github_token=... (or put it in .env).")
    return 0


def cmd_config(args: argparse.Namespace, config: Config, http: HttpClient, interactive: bool = False) -> int:
    if getattr(args, "set", None):
        assignment = args.set
        if "=" not in assignment:
            ui.error("Use --set key=value (for example --set hibp_api_key=ABC123).")
            return 2
        key, value = assignment.split("=", 1)
        key = key.strip().lower()
        general = {"timeout", "workers", "phone_region", "save_dir", "color", "proxy"}
        if key not in KEY_BY_NAME and key not in general:
            ui.error(
                f"Unknown setting '{key}'. Valid keys: "
                f"{', '.join(sorted(set(KEY_BY_NAME) | general))}."
            )
            return 2
        path = config.set(key, value.strip())
        ui.success(f"Saved {key} to {path}")
        spec = KEY_BY_NAME.get(key)
        if spec:
            ui.info(f"Environment variable {spec.env} overrides the saved value when set.")
        return 0

    if getattr(args, "get", None):
        key = args.get.strip().lower()
        if key not in KEY_BY_NAME and key not in ("timeout", "workers", "phone_region", "save_dir"):
            ui.error(f"Unknown setting '{key}'.")
            return 2
        value = config.get(key)
        if key in KEY_BY_NAME and not getattr(args, "reveal", False):
            value = config.masked(key)
        print(value)
        return 0

    table = Table(
        box=box.SIMPLE_HEAD,
        show_edge=False,
        pad_edge=False,
        expand=True,
        title=f"Configuration · {config.path}",
        title_justify="left",
    )
    table.add_column("Setting", style="bold white", no_wrap=True)
    table.add_column("Value", no_wrap=True)
    table.add_column("Environment variable", style="cyan", no_wrap=True)
    table.add_column("Purpose", style="grey62", overflow="fold")
    for spec in KEYS:
        table.add_row(
            Text(spec.label),
            Text(config.masked(spec.key)),
            Text(spec.env),
            Text(spec.help),
        )
    for key in ("timeout", "workers", "phone_region", "save_dir"):
        table.add_row(Text(key), Text(str(config.get(key))), Text("—"), Text("Runtime setting"))
    ui.out().print(table)
    ui.info(
        "Keys are optional. Environment variables take precedence over the config file."
    )
    ui.info(
        "Keyless sources cover every module: platform sweep, breach index (XposedOrNot), "
        "web and news (Bing + Google + DuckDuckGo), Wikipedia, Wikidata, RDAP/WHOIS, DNS, "
        "GitHub and IP geolocation."
    )
    ui.info("Set one with: specter config --set hibp_api_key=YOUR_KEY")
    return 0


HANDLERS = {
    "username": cmd_username,
    "email": cmd_email,
    "phone": cmd_phone,
    "ip": cmd_ip,
    "domain": cmd_domain,
    "github": cmd_github,
    "breach": cmd_breach,
    "breaches": cmd_breach,
    "search": cmd_search,
    "investigate": cmd_investigate,
    "scrape": cmd_scrape,
    "person": cmd_person,
    "keys": cmd_keys,
    "config": cmd_config,
}


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------
def _output_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("-o", "--output", help="Write a report to this path")
    parser.add_argument(
        "--format",
        choices=["json", "md", "markdown", "html", "all"],
        help="Report format (inferred from the output extension otherwise)",
    )
    parser.add_argument("--json", action="store_true", help="Print machine-readable JSON")
    parser.add_argument("--verbose", action="store_true", help="Show inactive sources too")
    parser.add_argument("--no-dorks", action="store_true", help="Skip suggested search links")
    parser.add_argument(
        "--no-images", action="store_true", help="Do not fetch or render images"
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="specter",
        description=(
            f"SPECTER v{__version__} — {__tagline__}. "
            "Console OSINT toolkit for lawful person investigations."
        ),
        epilog="Run without arguments for the interactive console, or 'specter help' commands.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--config", help="Path to a JSON configuration file")
    parser.add_argument("--no-color", action="store_true", help="Disable colors")
    parser.add_argument("--timeout", type=int, help="HTTP timeout in seconds")
    parser.add_argument("--workers", type=int, help="Concurrent username checks")
    parser.add_argument("--proxy", help="HTTP(S) proxy URL")
    parser.add_argument("--version", action="version", version=f"SPECTER {__version__}")

    subparsers = parser.add_subparsers(dest="command")

    p = subparsers.add_parser("username", help="Sweep a username across public platforms")
    p.add_argument("target")
    p.add_argument("--only", action="append", help="Only these platforms (comma separated)")
    p.add_argument("--exclude", action="append", help="Skip these platforms")
    p.add_argument("--workers", type=int, help="Concurrent platform checks")
    _output_options(p)

    p = subparsers.add_parser("email", help="Email account and domain intelligence")
    p.add_argument("target")
    p.add_argument("--no-breaches", action="store_true", help="Skip HIBP lookups")
    p.add_argument("--no-probes", action="store_true", help="Skip sign-up validation probes")
    _output_options(p)

    p = subparsers.add_parser("phone", help="Phone number metadata")
    p.add_argument("target")
    p.add_argument("--region", help="Default region for numbers without a country code")
    _output_options(p)

    p = subparsers.add_parser("ip", help="IP address intelligence")
    p.add_argument("target")
    _output_options(p)

    p = subparsers.add_parser("domain", help="Domain WHOIS, DNS and HTTP intelligence")
    p.add_argument("target")
    p.add_argument("--subdomains", action="store_true", help="Passive subdomain discovery")
    _output_options(p)

    p = subparsers.add_parser("github", help="Deep GitHub profile investigation")
    p.add_argument("target")
    p.add_argument("--repo-limit", type=int, default=100, help="Repositories to request (max 100)")
    _output_options(p)

    p = subparsers.add_parser("breach", aliases=["breaches"], help="HIBP breach lookup")
    p.add_argument("target")
    _output_options(p)

    p = subparsers.add_parser("search", help="Search the web, news and public records")
    p.add_argument("target")
    p.add_argument(
        "--type",
        choices=["name", "email", "username", "phone", "domain", "ip"],
        help="Dork profile to use",
    )
    p.add_argument(
        "--source",
        action="append",
        choices=list(ALL_SOURCES) + ["all"],
        help="Sources to query (repeatable)",
    )
    p.add_argument("--limit", type=int, default=8, help="Results per source")
    _output_options(p)

    p = subparsers.add_parser("investigate", help="Auto-detect the target and run everything")
    p.add_argument("target")
    p.add_argument(
        "--type",
        default="auto",
        choices=["auto", "username", "email", "phone", "ip", "domain", "name"],
    )
    p.add_argument("--source", action="append", choices=list(ALL_SOURCES) + ["all"])
    p.add_argument("--limit", type=int, default=8, help="Results per search source")
    p.add_argument("--subdomains", action="store_true")
    _output_options(p)

    p = subparsers.add_parser(
        "scrape", help="Smart, budgeted crawl of the pages that mention a target"
    )
    p.add_argument("target", help="URL to start from, or a query/name to seed with")
    p.add_argument("--seed", action="append", help="Extra starting URL (repeatable)")
    p.add_argument("--term", action="append", help="Extra term to score pages against")
    p.add_argument("--pages", type=int, default=8, help="Page budget (default 8)")
    p.add_argument("--depth", type=int, default=2, help="Link depth from each seed (default 2)")
    p.add_argument("--min-score", type=float, default=1.6, help="Relevance floor for a link")
    p.add_argument(
        "--type",
        choices=["name", "email", "username", "phone", "domain", "ip"],
        help="Dork profile used when the target is a query",
    )
    p.add_argument("--limit", type=int, default=6, help="Search results used as seeds")
    p.add_argument("--region", help="Region for phone-number extraction (ISO code)")
    _output_options(p)

    p = subparsers.add_parser(
        "person", help="Correlate a multi-identifier person profile into one conclusion"
    )
    p.add_argument("--first", help="First name")
    p.add_argument("--last", help="Last name")
    p.add_argument("--name", help="Full name (instead of --first/--last)")
    p.add_argument("--alias", action="append", help="Alias or nickname (repeatable)")
    p.add_argument("--email", action="append", help="Email address (repeatable)")
    p.add_argument("--phone", action="append", help="Phone number (repeatable)")
    p.add_argument("--username", action="append", help="Username or handle (repeatable)")
    p.add_argument("--domain", action="append", help="Domain the person owns or uses")
    p.add_argument("--ip", action="append", help="IP address to include")
    p.add_argument("--location", help="City or country the person is associated with")
    p.add_argument("--employer", help="Employer or organisation")
    p.add_argument("--birth-year", help="Birth year, to discount namesakes")
    p.add_argument("--region", help="Phone parsing region (ISO code, e.g. FR)")
    p.add_argument("--subdomains", action="store_true")
    p.add_argument("--limit", type=int, default=8, help="Results per search source")
    _output_options(p)

    p = subparsers.add_parser(
        "keys", help="List optional API keys, their free tiers and validate them"
    )
    p.add_argument("--check", action="store_true", help="Validate each configured key live")
    p.add_argument("--env-file", action="store_true", help="Write a fill-in .env.example")
    p.add_argument("--force", action="store_true", help="Overwrite an existing .env.example")

    p = subparsers.add_parser("config", help="Show or change settings and API keys")
    p.add_argument("--show", action="store_true", help="Show all settings")
    p.add_argument("--set", metavar="KEY=VALUE", help="Save a setting")
    p.add_argument("--get", metavar="KEY", help="Print one setting")
    p.add_argument("--reveal", action="store_true", help="Show secret values unmasked")

    subparsers.add_parser("gui", help="Open the desktop workbench (Tkinter)")
    subparsers.add_parser("menu", help="Open the interactive console")
    subparsers.add_parser("help", help="Show this help message")

    return parser


def _apply_runtime_config(config: Config, args: argparse.Namespace) -> None:
    overrides = {
        "timeout": getattr(args, "timeout", None),
        "workers": getattr(args, "workers", None),
        "proxy": getattr(args, "proxy", None),
    }
    for key, value in overrides.items():
        if value not in (None, ""):
            config.set_runtime(key, value)


# ---------------------------------------------------------------------------
# Interactive console
# ---------------------------------------------------------------------------
def _run_from_interactive(parser: argparse.ArgumentParser, tokens: list[str], config: Config, http: HttpClient) -> int:
    try:
        args = parser.parse_args(tokens)
    except SystemExit:
        return 2
    if not args.command:
        ui.menu_table(MENU)
        return 0
    handler = HANDLERS.get(args.command)
    if not handler:
        ui.error(f"No handler for '{args.command}'.")
        return 2
    _apply_runtime_config(config, args)
    return handler(args, config, http, interactive=True)


def interactive(config: Config, http: HttpClient) -> int:
    parser = build_parser()
    ui.banner()
    ui.out().print(ui.menu_table(MENU))
    ui.info("Type a number, or a command such as: username torvalds · help · exit")

    prompt_for = {
        "1": "Username or handle",
        "2": "Email address",
        "3": "Phone number (+international)",
        "4": "IP address",
        "5": "Domain",
        "6": "GitHub username",
        "7": "Email address",
        "8": "Search query",
        "9": "Target (name, email, phone, IP, domain or username)",
    }

    while True:
        try:
            raw = ui.out().input("\n[bold cyan]specter ›[/] ").strip()
        except (EOFError, KeyboardInterrupt):
            ui.out().print()
            ui.info("Session closed.")
            return 0

        if not raw:
            continue
        if raw.lower() in ("exit", "quit", "q", "0"):
            ui.info("Session closed.")
            return 0
        if raw.lower() == "menu":
            ui.out().print(ui.menu_table(MENU))
            continue
        if raw.lower() == "help":
            ui.out().print(Panel(Text.from_markup(HELP), border_style="grey30", box=box.ROUNDED))
            continue
        if raw.lower() == "clear":
            ui.out().clear()
            ui.banner()
            ui.out().print(ui.menu_table(MENU))
            continue
        if raw == "10":
            cmd_config(
                argparse.Namespace(set=None, get=None, reveal=False, show=True),
                config,
                http,
                interactive=True,
            )
            continue
        if raw == "11":
            from .gui import launch

            launch(config)
            ui.banner()
            continue

        if raw in prompt_for:
            try:
                target = ui.out().input(f"  [cyan]{prompt_for[raw]}[/]: ").strip()
            except (EOFError, KeyboardInterrupt):
                ui.out().print()
                continue
            if not target:
                ui.warn("Nothing entered.")
                continue
            command = {
                "1": "username",
                "2": "email",
                "3": "phone",
                "4": "ip",
                "5": "domain",
                "6": "github",
                "7": "breach",
                "8": "search",
                "9": "investigate",
            }[raw]
            _run_from_interactive(parser, [command, target], config, http)
            continue

        try:
            tokens = shlex.split(raw)
        except ValueError as exc:
            ui.error(f"Could not parse the command: {exc}")
            continue

        command = tokens[0].lower()
        if command == "settings":
            cmd_config(
                argparse.Namespace(set=None, get=None, reveal=False, show=True),
                config,
                http,
                interactive=True,
            )
            continue
        if command not in HANDLERS:
            ui.error(f"Unknown command '{command}'. Type help for the command list.")
            continue
        _run_from_interactive(parser, tokens, config, http)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    _configure_stdio()
    parser = build_parser()
    args = parser.parse_args(argv)

    config = Config(getattr(args, "config", None))
    _apply_runtime_config(config, args)
    ui.init(no_color=bool(getattr(args, "no_color", False)))

    command = getattr(args, "command", None)
    if command is None:
        if sys.stdin.isatty():
            return interactive(config, _build_http(config))
        parser.print_help()
        return 0
    if command == "menu":
        return interactive(config, _build_http(config))
    if command == "help":
        parser.print_help()
        return 0
    if command == "gui":
        from .gui import launch

        return launch(config)

    handler = HANDLERS.get(command)
    if not handler:
        parser.print_help()
        return 2

    http = _build_http(config)
    try:
        return handler(args, config, http)
    except KeyboardInterrupt:
        ui.warn("Interrupted.")
        return 130
    except Exception as exc:  # noqa: BLE001 - CLI boundary
        if getattr(args, "verbose", False):
            raise
        ui.error(f"{type(exc).__name__}: {exc}")
        return 1
