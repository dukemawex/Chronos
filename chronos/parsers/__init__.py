"""
Log parsers for SSH/Auth, CloudTrail, and Network log formats.

Each parser converts raw log lines into a normalised list of ``LogEvent``
dicts with at least the following keys:

    source      – log type identifier ("ssh", "auth", "cloudtrail", "network")
    timestamp   – datetime object (UTC)
    raw         – the original log line (str)

Additional keys depend on the log type (see individual parsers below).
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from typing import List, Optional

LogEvent = dict  # type alias for readability


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc(dt: datetime) -> datetime:
    """Ensure *dt* is timezone-aware (UTC)."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt


# ---------------------------------------------------------------------------
# SSH / Auth log parser  (syslog-style lines)
# ---------------------------------------------------------------------------

# Example lines:
#   Apr  3 06:17:22 host sshd[12345]: Failed password for invalid user admin from 1.2.3.4 port 54321 ssh2
#   Apr  3 06:17:25 host sshd[12345]: Accepted publickey for bob from 10.0.0.5 port 22 ssh2
#   Apr  3 07:01:44 host useradd[9999]: new user: name=attacker, UID=1001, GID=1001, ...
#   Apr  3 07:01:44 host sudo: alice : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash

_SYSLOG_TS_PATTERN = re.compile(
    r"^(?P<month>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
)
_SYSLOG_TS_YEAR = datetime.now(timezone.utc).year  # assume current year

_SSH_FAILED = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<src_ip>[\d.a-fA-F:]+) port (?P<port>\d+)"
)
_SSH_ACCEPTED = re.compile(
    r"Accepted (?:password|publickey) for (?P<user>\S+) from (?P<src_ip>[\d.a-fA-F:]+) port (?P<port>\d+)"
)
_SSH_DISCONNECT = re.compile(
    r"Disconnected from (?:invalid user )?(?P<user>\S+)?\s*(?P<src_ip>[\d.a-fA-F:]+) port (?P<port>\d+)"
)
_USER_CREATED = re.compile(r"new user: name=(?P<user>\S+?)[,\s]")
_SUDO_CMD = re.compile(r"sudo:.*USER=(?P<target_user>\S+).*COMMAND=(?P<command>.+)$")


def _parse_syslog_ts(line: str) -> Optional[datetime]:
    m = _SYSLOG_TS_PATTERN.match(line)
    if not m:
        return None
    try:
        ts_str = f"{m.group('month')} {m.group('day')} {_SYSLOG_TS_YEAR} {m.group('time')}"
        return _utc(datetime.strptime(ts_str, "%b %d %Y %H:%M:%S"))
    except ValueError:
        return None


def parse_ssh_auth(lines: List[str]) -> List[LogEvent]:
    events: List[LogEvent] = []
    for raw in lines:
        raw = raw.rstrip()
        if not raw:
            continue
        ts = _parse_syslog_ts(raw)
        if ts is None:
            continue

        event: LogEvent = {"source": "ssh", "timestamp": ts, "raw": raw}

        if m := _SSH_FAILED.search(raw):
            event.update(
                {
                    "event_type": "failed_login",
                    "user": m.group("user"),
                    "src_ip": m.group("src_ip"),
                    "port": int(m.group("port")),
                }
            )
        elif m := _SSH_ACCEPTED.search(raw):
            event.update(
                {
                    "event_type": "successful_login",
                    "user": m.group("user"),
                    "src_ip": m.group("src_ip"),
                    "port": int(m.group("port")),
                }
            )
        elif m := _SSH_DISCONNECT.search(raw):
            event.update(
                {
                    "event_type": "disconnect",
                    "user": m.group("user"),
                    "src_ip": m.group("src_ip"),
                    "port": int(m.group("port")),
                }
            )
        elif m := _USER_CREATED.search(raw):
            event.update(
                {
                    "source": "auth",
                    "event_type": "user_created",
                    "user": m.group("user"),
                }
            )
        elif _SUDO_CMD.search(raw):
            m = _SUDO_CMD.search(raw)
            event.update(
                {
                    "source": "auth",
                    "event_type": "sudo_command",
                    "target_user": m.group("target_user"),
                    "command": m.group("command").strip(),
                }
            )
        else:
            event["event_type"] = "generic"

        events.append(event)
    return events


# ---------------------------------------------------------------------------
# CloudTrail parser  (JSON Lines or JSON array)
# ---------------------------------------------------------------------------

def parse_cloudtrail(lines: List[str]) -> List[LogEvent]:
    """Parse AWS CloudTrail JSON log lines.

    Accepts either JSON-Lines (one record per line) or a single JSON array /
    object with a ``Records`` key as produced by CloudTrail S3 exports.
    """
    raw_text = "\n".join(lines)
    records: list = []

    # Try JSON-Lines first
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict) and "Records" in obj:
                records.extend(obj["Records"])
            elif isinstance(obj, list):
                records.extend(obj)
            else:
                records.append(obj)
        except json.JSONDecodeError:
            pass

    # Fallback: entire file as one JSON object
    if not records:
        try:
            obj = json.loads(raw_text)
            if isinstance(obj, dict) and "Records" in obj:
                records = obj["Records"]
            elif isinstance(obj, list):
                records = obj
        except json.JSONDecodeError:
            pass

    events: List[LogEvent] = []
    for rec in records:
        ts_str = rec.get("eventTime", "")
        try:
            ts = _utc(datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ"))
        except (ValueError, TypeError):
            continue

        event: LogEvent = {
            "source": "cloudtrail",
            "timestamp": ts,
            "raw": json.dumps(rec),
            "event_type": rec.get("eventName", "unknown"),
            "user": (rec.get("userIdentity") or {}).get("userName") or
                    (rec.get("userIdentity") or {}).get("arn", ""),
            "src_ip": rec.get("sourceIPAddress", ""),
            "aws_region": rec.get("awsRegion", ""),
            "event_source": rec.get("eventSource", ""),
            "request_parameters": rec.get("requestParameters") or {},
            "response_elements": rec.get("responseElements") or {},
            "error_code": rec.get("errorCode", ""),
        }
        events.append(event)
    return events


# ---------------------------------------------------------------------------
# Network log parser  (common Apache / nginx combined log or CSV-style flow)
# ---------------------------------------------------------------------------

# Combined log format:
#   1.2.3.4 - - [03/Apr/2026:06:17:22 +0000] "GET /admin HTTP/1.1" 403 512
_COMBINED_LOG = re.compile(
    r'(?P<src_ip>[\d.a-fA-F:]+)\s+-\s+-\s+\[(?P<ts>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)[^"]*"\s+(?P<status>\d{3})\s+(?P<bytes>\d+|-)'
)
_COMBINED_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"

# CSV flow format: timestamp,src_ip,dst_ip,src_port,dst_port,protocol,bytes,flags
_CSV_FLOW = re.compile(
    r"^(?P<ts>[\d\-T:Z+]+),(?P<src_ip>[^,]+),(?P<dst_ip>[^,]+),(?P<src_port>\d+),(?P<dst_port>\d+),(?P<protocol>[^,]+),(?P<bytes>\d+)(?:,(?P<flags>[^,\s]*))?$"
)


def parse_network(lines: List[str]) -> List[LogEvent]:
    events: List[LogEvent] = []
    for raw in lines:
        raw = raw.rstrip()
        if not raw or raw.startswith("#"):
            continue

        if m := _COMBINED_LOG.match(raw):
            try:
                ts = _utc(datetime.strptime(m.group("ts"), _COMBINED_TS_FMT))
            except ValueError:
                continue
            events.append(
                {
                    "source": "network",
                    "timestamp": ts,
                    "raw": raw,
                    "event_type": "http_request",
                    "src_ip": m.group("src_ip"),
                    "method": m.group("method"),
                    "path": m.group("path"),
                    "status": int(m.group("status")),
                    "bytes": int(m.group("bytes")) if m.group("bytes") != "-" else 0,
                }
            )
        elif m := _CSV_FLOW.match(raw):
            ts_str = m.group("ts")
            try:
                ts = _utc(datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%SZ"))
            except ValueError:
                try:
                    ts = _utc(datetime.strptime(ts_str, "%Y-%m-%dT%H:%M:%S+00:00"))
                except ValueError:
                    continue
            events.append(
                {
                    "source": "network",
                    "timestamp": ts,
                    "raw": raw,
                    "event_type": "flow",
                    "src_ip": m.group("src_ip"),
                    "dst_ip": m.group("dst_ip"),
                    "src_port": int(m.group("src_port")),
                    "dst_port": int(m.group("dst_port")),
                    "protocol": m.group("protocol"),
                    "bytes": int(m.group("bytes")),
                    "flags": m.group("flags") or "",
                }
            )
    return events
