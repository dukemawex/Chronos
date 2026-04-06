"""
Core analysis engine.

Orchestrates log parsing, runs all threat hunters, de-duplicates findings,
and returns a structured result ready for report generation.
"""

from __future__ import annotations

import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Dict, List, Optional

from chronos.parsers import (
    LogEvent,
    parse_cloudtrail,
    parse_network,
    parse_ssh_auth,
)
from chronos.hunters import ALL_HUNTERS, Finding
from chronos.hunters.apt import APT_HUNTERS

# Severity ordering for sorting
_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class AnalysisResult:
    """Holds the full output of a Chronos analysis run."""

    def __init__(
        self,
        events: List[LogEvent],
        findings: List[Finding],
        log_sources: List[str],
        analysis_time: datetime,
    ):
        self.events = events
        self.findings = sorted(
            findings, key=lambda f: _SEVERITY_ORDER.get(f["severity"], 99)
        )
        self.log_sources = log_sources
        self.analysis_time = analysis_time

    @property
    def event_count(self) -> int:
        return len(self.events)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "CRITICAL")

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f["severity"] == "HIGH")

    @property
    def unique_ips(self) -> List[str]:
        ips = {e.get("src_ip") for e in self.events if e.get("src_ip")}
        return sorted(ips)

    @property
    def time_range(self):
        if not self.events:
            return None, None
        timestamps = [e["timestamp"] for e in self.events]
        return min(timestamps), max(timestamps)


def _detect_log_type(lines: List[str]) -> str:
    """
    Heuristically determine the log format from the first non-empty lines.
    Returns one of: "ssh", "cloudtrail", "network".
    """
    sample = "\n".join(line for line in lines[:20] if line.strip())

    if '"eventVersion"' in sample or '"eventName"' in sample or '"Records"' in sample:
        return "cloudtrail"

    import re
    if re.search(r'\[\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}', sample):
        return "network"

    # CSV flow: timestamp,ip,ip,...
    if re.match(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', sample):
        if sample.count(",") > 3:
            return "network"

    # Default to SSH/auth syslog
    return "ssh"


def load_log_file(path: str, log_type: Optional[str] = None) -> List[LogEvent]:
    """
    Read a log file and return parsed ``LogEvent`` dicts.

    If *log_type* is not provided, the type is auto-detected.
    """
    with open(path, "r", errors="replace") as fh:
        lines = fh.readlines()

    if log_type is None:
        log_type = _detect_log_type(lines)

    if log_type in ("ssh", "auth"):
        return parse_ssh_auth(lines)
    elif log_type == "cloudtrail":
        return parse_cloudtrail(lines)
    elif log_type == "network":
        return parse_network(lines)
    else:
        raise ValueError(f"Unknown log type: {log_type!r}")


def analyse(
    log_files: List[str],
    log_types: Optional[Dict[str, str]] = None,
) -> AnalysisResult:
    """
    Run the full threat-hunting analysis pipeline.

    Parameters
    ----------
    log_files:
        List of file paths to analyse.
    log_types:
        Optional mapping of ``{path: log_type}`` to override auto-detection.
    """
    if log_types is None:
        log_types = {}

    all_events: List[LogEvent] = []
    sources: List[str] = []

    for path in log_files:
        log_type = log_types.get(path)
        events = load_log_file(path, log_type=log_type)
        all_events.extend(events)
        sources.append(os.path.basename(path))

    # Sort all events chronologically
    all_events.sort(key=lambda e: e["timestamp"])

    # Run every registered hunter (base + APT)
    findings: List[Finding] = []
    for hunter in ALL_HUNTERS + APT_HUNTERS:
        findings.extend(hunter(all_events))

    return AnalysisResult(
        events=all_events,
        findings=findings,
        log_sources=sources,
        analysis_time=datetime.now(timezone.utc),
    )
