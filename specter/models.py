"""Data models shared by all SPECTER modules."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__

# Finding statuses
FOUND = "found"
NOT_FOUND = "not_found"
BLOCKED = "blocked"
ERROR = "error"
UNKNOWN = "unknown"
MANUAL = "manual"
INFO = "info"

STATUS_LABELS = {
    FOUND: "FOUND",
    NOT_FOUND: "not found",
    BLOCKED: "blocked",
    ERROR: "error",
    UNKNOWN: "unknown",
    MANUAL: "manual link",
    INFO: "info",
}


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def iso(value: datetime | None) -> str | None:
    return value.isoformat(timespec="seconds") if value else None


@dataclass
class ImageRef:
    """A relevant image discovered alongside a finding."""

    url: str
    alt: str = ""
    kind: str = "profile"  # profile | thumbnail | logo | map
    page_url: str | None = None
    width: int | None = None
    height: int | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"url": self.url, "kind": self.kind}
        if self.alt:
            out["alt"] = self.alt
        if self.page_url:
            out["page_url"] = self.page_url
        if self.width:
            out["width"] = self.width
        if self.height:
            out["height"] = self.height
        return out


@dataclass
class Finding:
    """A single piece of evidence returned by a module."""

    source: str
    category: str
    status: str
    url: str | None = None
    title: str | None = None
    detail: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    images: list[ImageRef] = field(default_factory=list)
    confidence: str = "high"
    elapsed_ms: int | None = None

    def to_dict(self) -> dict[str, Any]:
        # Content first, provenance last.
        out: dict[str, Any] = {}
        if self.title:
            out["title"] = self.title
        if self.detail:
            out["detail"] = self.detail
        if self.data:
            out["data"] = self.data
        if self.images:
            out["images"] = [image.to_dict() for image in self.images]
        out["source"] = self.source
        out["category"] = self.category
        out["status"] = self.status
        out["confidence"] = self.confidence
        if self.url:
            out["url"] = self.url
        if self.elapsed_ms is not None:
            out["elapsed_ms"] = self.elapsed_ms
        return out


@dataclass
class Report:
    """An investigation report containing every finding for one target."""

    target: str
    target_type: str
    findings: list[Finding] = field(default_factory=list)
    started: datetime = field(default_factory=utcnow)
    finished: datetime | None = None
    tool_version: str = __version__
    options: dict[str, Any] = field(default_factory=dict)
    notes: list[str] = field(default_factory=list)
    # Correlation result for multi-identifier person profiles (score, band,
    # verdict, links, conflicts). Empty for single-target investigations.
    identity: dict[str, Any] = field(default_factory=dict)

    def add(self, finding: Finding) -> Finding:
        self.findings.append(finding)
        return finding

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    def finish(self) -> "Report":
        self.finished = utcnow()
        return self

    def duration(self) -> float:
        end = self.finished or utcnow()
        return max(0.0, (end - self.started).total_seconds())

    def counts(self) -> dict[str, int]:
        counts = Counter(f.status for f in self.findings)
        return {
            "total": len(self.findings),
            "found": counts.get(FOUND, 0),
            "manual": counts.get(MANUAL, 0),
            "blocked": counts.get(BLOCKED, 0),
            "errors": counts.get(ERROR, 0),
            "not_found": counts.get(NOT_FOUND, 0),
            "infos": counts.get(INFO, 0),
            "images": sum(len(f.images) for f in self.findings),
        }

    def found(self) -> list[Finding]:
        return [f for f in self.findings if f.status == FOUND]

    def categories(self) -> dict[str, list[Finding]]:
        grouped: dict[str, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.category, []).append(finding)
        return grouped

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": "SPECTER",
            "version": self.tool_version,
            "target": self.target,
            "target_type": self.target_type,
            "started": iso(self.started),
            "finished": iso(self.finished),
            "duration_seconds": round(self.duration(), 2),
            "counts": self.counts(),
            "options": self.options,
            "identity": self.identity,
            "notes": self.notes,
            "findings": [f.to_dict() for f in self.findings],
        }

    def save(self, path: str | Path, fmt: str | None = None) -> list[Path]:
        """Write the report to disk. Returns the list of written files."""
        from .report import write_report

        return write_report(self, path, fmt)
