"""
APT (Advanced Persistent Threat) hunters for multi-day log correlation.

These hunters focus on *subtle*, low-noise signals that are characteristic of
skilled adversaries:

  1. New-IP Successful Login → IAM Policy Change (within 30 min)
  2. New-IP Successful Login → S3 Enumeration (within 30 min)
  3. "Silent Hacker" – attacker reusing a legitimate developer's CLI / user-agent
  4. Multi-day Lateral Movement – escalating access across the 7-day window

Each hunter returns a list of ``APTFinding`` dicts that extend the base
``Finding`` schema with:

    confidence   – int 0-100 (raw contribution before aggregation)
    indicators   – list of atomic indicator dicts {"type", "value", "weight"}
    apt_stage    – MITRE ATT&CK tactic label
"""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import timedelta
from typing import Dict, List, Optional, Set, Tuple

from chronos.parsers import LogEvent

APTFinding = dict  # type alias

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_IAM_EVENTS: Set[str] = {
    "AttachUserPolicy",
    "DetachUserPolicy",
    "PutUserPolicy",
    "DeleteUserPolicy",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "PutRolePolicy",
    "CreatePolicy",
    "CreatePolicyVersion",
    "SetDefaultPolicyVersion",
    "AddUserToGroup",
    "RemoveUserFromGroup",
    "CreateGroup",
    "UpdateAssumeRolePolicy",
    "CreateRole",
    "UpdateRole",
    "CreateUser",
    "CreateAccessKey",
    "CreateLoginProfile",
    "UpdateLoginProfile",
}

_S3_ENUM_EVENTS: Set[str] = {
    "ListBuckets",
    "ListObjects",
    "ListObjectsV2",
    "ListObjectVersions",
    "GetBucketAcl",
    "GetBucketPolicy",
    "GetBucketPolicyStatus",
    "GetBucketPublicAccessBlock",
    "HeadBucket",
}

_S3_EXFIL_EVENTS: Set[str] = {
    "GetObject",
    "CopyObject",
    "GetObjectAcl",
}

# Window in which a suspicious action after login raises an alert
_POST_LOGIN_WINDOW_SECONDS = 1800  # 30 minutes

# Baseline window for "known IPs" (anything older than this is considered new)
_BASELINE_DAYS = 7


# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _build_ip_baseline(
    events: List[LogEvent],
    cutoff_ts,
) -> Dict[str, Set[str]]:
    """
    Return {user -> set(known_ips)} seen in successful logins *before* cutoff_ts.
    Used to identify first-seen IPs in the analysis window.
    """
    baseline: Dict[str, Set[str]] = defaultdict(set)
    for e in events:
        if e.get("event_type") == "successful_login" and e["timestamp"] < cutoff_ts:
            baseline[e.get("user", "")].add(e.get("src_ip", ""))
    return baseline


def _extract_user_agent(raw: str) -> Optional[str]:
    """Extract userAgent field from a CloudTrail JSON raw string."""
    m = re.search(r'"userAgent"\s*:\s*"([^"]+)"', raw)
    return m.group(1) if m else None


def _bucket_name(e: LogEvent) -> str:
    params = e.get("request_parameters", {})
    if isinstance(params, dict):
        return str(params.get("bucketName", params.get("bucketName", "unknown")))
    return "unknown"


# ---------------------------------------------------------------------------
# 1. New-IP Login → IAM Change Hunter
# ---------------------------------------------------------------------------

def hunt_new_ip_iam_change(events: List[LogEvent]) -> List[APTFinding]:
    """
    Detect: successful login from a *first-seen* IP immediately followed by
    IAM policy changes – a hallmark of credential-based initial access and
    privilege escalation.
    """
    findings: List[APTFinding] = []

    if not events:
        return findings

    window_start = min(e["timestamp"] for e in events)
    cutoff = window_start  # everything in this dataset is "in-window"
    baseline = _build_ip_baseline(events, cutoff)

    # Collect successful logins per user with their IP
    logins = [e for e in events if e.get("event_type") == "successful_login"]
    iam_changes = [e for e in events if e.get("event_type") in _IAM_EVENTS]

    for login in logins:
        user = login.get("user", "?")
        src_ip = login.get("src_ip", "?")

        # Only flag IPs *not* present in the prior baseline for this user
        if src_ip in baseline.get(user, set()):
            continue

        # Look for IAM events by the same user within the post-login window
        post_window_end = login["timestamp"] + timedelta(seconds=_POST_LOGIN_WINDOW_SECONDS)
        related_iam = [
            e for e in iam_changes
            if e["timestamp"] >= login["timestamp"]
            and e["timestamp"] <= post_window_end
            and (e.get("user", "") == user or user in e.get("raw", ""))
        ]

        if not related_iam:
            continue

        # Build timeline
        all_evidence = [login] + related_iam
        all_evidence.sort(key=lambda e: e["timestamp"])
        timeline = []
        for e in all_evidence:
            if e is login:
                timeline.append(
                    (e["timestamp"], f"[INITIAL ACCESS] Successful login by '{user}' from NEW IP {src_ip}")
                )
            else:
                timeline.append(
                    (e["timestamp"], f"[PRIVILEGE ESCALATION] {e.get('event_type')} by '{user}'")
                )

        # Confidence: more IAM changes = more confident, new IP = high weight
        confidence = min(60 + len(related_iam) * 8, 90)

        findings.append(
            {
                "title": f"APT: New-IP Login → IAM Policy Change by '{user}'",
                "severity": "CRITICAL",
                "apt_stage": "Initial Access → Privilege Escalation",
                "hypothesis": (
                    f"User '{user}' authenticated from a previously-unseen IP address "
                    f"({src_ip}) and immediately performed {len(related_iam)} IAM "
                    f"policy change(s): "
                    + ", ".join(e.get("event_type", "?") for e in related_iam)
                    + ". This is a strong indicator of compromised credentials being used "
                    "to establish persistence or escalate privileges."
                ),
                "evidence": [e["raw"] for e in all_evidence],
                "timeline": timeline,
                "confidence": confidence,
                "indicators": [
                    {"type": "new_src_ip", "value": src_ip, "weight": 30},
                    {"type": "iam_change_count", "value": len(related_iam), "weight": 20},
                    {
                        "type": "iam_event_types",
                        "value": [e.get("event_type") for e in related_iam],
                        "weight": 15,
                    },
                ],
                "mitigations": [
                    f"Immediately revoke all active sessions and access keys for '{user}'.",
                    f"Investigate the origin and ownership of IP {src_ip}.",
                    "Review and revert all IAM changes made during this session.",
                    "Enable AWS IAM Access Analyzer to detect overly permissive policies.",
                    "Enforce IP-based conditional access policies in IAM.",
                ],
            }
        )

    return findings


# ---------------------------------------------------------------------------
# 2. New-IP Login → S3 Enumeration / Exfiltration Hunter
# ---------------------------------------------------------------------------

def hunt_new_ip_s3_enum(events: List[LogEvent]) -> List[APTFinding]:
    """
    Detect: successful login from a *first-seen* IP followed by S3 bucket
    enumeration or bulk data access – classic reconnaissance and exfiltration.
    """
    findings: List[APTFinding] = []

    if not events:
        return findings

    window_start = min(e["timestamp"] for e in events)
    baseline = _build_ip_baseline(events, window_start)

    logins = [e for e in events if e.get("event_type") == "successful_login"]
    s3_events = [
        e for e in events
        if e.get("event_type") in _S3_ENUM_EVENTS | _S3_EXFIL_EVENTS
    ]

    for login in logins:
        user = login.get("user", "?")
        src_ip = login.get("src_ip", "?")

        if src_ip in baseline.get(user, set()):
            continue

        post_window_end = login["timestamp"] + timedelta(seconds=_POST_LOGIN_WINDOW_SECONDS)
        related_s3 = [
            e for e in s3_events
            if e["timestamp"] >= login["timestamp"]
            and e["timestamp"] <= post_window_end
            and (e.get("user", "") == user or user in e.get("raw", ""))
        ]

        if not related_s3:
            continue

        enum_events = [e for e in related_s3 if e.get("event_type") in _S3_ENUM_EVENTS]
        exfil_events = [e for e in related_s3 if e.get("event_type") in _S3_EXFIL_EVENTS]
        buckets_accessed = {_bucket_name(e) for e in related_s3}

        all_evidence = [login] + related_s3
        all_evidence.sort(key=lambda e: e["timestamp"])

        timeline = [(login["timestamp"], f"[INITIAL ACCESS] Successful login by '{user}' from NEW IP {src_ip}")]
        for e in related_s3:
            stage = "EXFILTRATION" if e.get("event_type") in _S3_EXFIL_EVENTS else "RECONNAISSANCE"
            timeline.append(
                (e["timestamp"], f"[{stage}] {e.get('event_type')} on bucket '{_bucket_name(e)}'")
            )

        # Exfil events are much more alarming
        confidence = min(50 + len(enum_events) * 5 + len(exfil_events) * 15, 92)

        findings.append(
            {
                "title": f"APT: New-IP Login → S3 {'Exfiltration' if exfil_events else 'Enumeration'} by '{user}'",
                "severity": "CRITICAL" if exfil_events else "HIGH",
                "apt_stage": "Initial Access → Reconnaissance"
                + (" → Exfiltration" if exfil_events else ""),
                "hypothesis": (
                    f"User '{user}' logged in from an unknown IP ({src_ip}) and "
                    f"immediately enumerated {len(buckets_accessed)} S3 bucket(s) "
                    f"({', '.join(sorted(buckets_accessed))})"
                    + (
                        f", then retrieved {len(exfil_events)} object(s). "
                        "This sequence matches a Data Exfiltration pattern."
                        if exfil_events
                        else ". This is consistent with Reconnaissance prior to exfiltration."
                    )
                ),
                "evidence": [e["raw"] for e in all_evidence],
                "timeline": timeline,
                "confidence": confidence,
                "indicators": [
                    {"type": "new_src_ip", "value": src_ip, "weight": 30},
                    {"type": "buckets_accessed", "value": sorted(buckets_accessed), "weight": 20},
                    {"type": "s3_enum_count", "value": len(enum_events), "weight": 10},
                    {"type": "s3_exfil_count", "value": len(exfil_events), "weight": 25},
                ],
                "mitigations": [
                    f"Immediately revoke all active sessions and access keys for '{user}'.",
                    f"Block or quarantine IP {src_ip}.",
                    "Enable S3 server-access logging and review data accessed.",
                    "Apply S3 Block Public Access and review all bucket policies.",
                    "Engage a forensics team to determine whether data was exfiltrated.",
                ],
            }
        )

    return findings


# ---------------------------------------------------------------------------
# 3. "Silent Hacker" – Developer Impersonation Hunter
# ---------------------------------------------------------------------------

# Common developer CLI user-agents in CloudTrail
_DEV_UA_PATTERNS = [
    re.compile(r"aws-cli/", re.IGNORECASE),
    re.compile(r"Boto3/", re.IGNORECASE),
    re.compile(r"terraform", re.IGNORECASE),
    re.compile(r"pulumi", re.IGNORECASE),
    re.compile(r"aws-sdk", re.IGNORECASE),
    re.compile(r"aws-amplify", re.IGNORECASE),
]


def _is_dev_ua(ua: str) -> bool:
    return any(p.search(ua) for p in _DEV_UA_PATTERNS)


def hunt_silent_hacker(events: List[LogEvent]) -> List[APTFinding]:
    """
    Detect an attacker mimicking a legitimate developer by reusing the same
    CLI user-agent string but from a new/unusual source IP.

    Signals:
      - A developer's CLI user-agent used for *sensitive* operations (IAM
        changes, S3 policy writes) from an IP that is absent from the
        *routine* baseline (normal reads / lists by the same user + UA).
      - The developer's routine work (GetObject, ListBuckets, etc.) establishes
        the trusted-IP baseline; any sensitive op from an IP outside that
        baseline is flagged.
    """
    findings: List[APTFinding] = []

    ct_events = [e for e in events if e["source"] == "cloudtrail"]
    if not ct_events:
        return findings

    # Operations that are clearly administrative / privilege-modifying
    _SENSITIVE_OPS: Set[str] = _IAM_EVENTS | {
        "PutBucketPolicy",
        "DeleteBucketPolicy",
        "PutBucketAcl",
        "PutBucketPublicAccessBlock",
        "DeletePublicAccessBlock",
    }
    # Operations that represent normal developer work and establish the IP baseline
    _ROUTINE_OPS: Set[str] = _S3_ENUM_EVENTS | _S3_EXFIL_EVENTS | {
        "GetUser",
        "ListUsers",
        "DescribeInstances",
        "GetCallerIdentity",
        "HeadObject",
        "PutObject",
    }

    # {(user, ua) -> list of sensitive events}
    sensitive_by_key: Dict[Tuple[str, str], List[LogEvent]] = defaultdict(list)
    # {(user, ua) -> set of routine IPs (the trusted baseline)}
    routine_ips_by_key: Dict[Tuple[str, str], Set[str]] = defaultdict(set)

    for e in ct_events:
        ua = _extract_user_agent(e.get("raw", "")) or ""
        if not ua or not _is_dev_ua(ua):
            continue
        user = e.get("user", "?")
        ip = e.get("src_ip", "")
        event_type = e.get("event_type", "")
        key = (user, ua)

        if event_type in _SENSITIVE_OPS:
            sensitive_by_key[key].append(e)
        if event_type in _ROUTINE_OPS:
            routine_ips_by_key[key].add(ip)

    # Flag (user, ua) pairs where sensitive ops come from IPs outside the routine baseline
    for (user, ua), sensitive_events in sensitive_by_key.items():
        routine_ips = routine_ips_by_key.get((user, ua), set())
        sensitive_ips = {e.get("src_ip", "") for e in sensitive_events}
        # IPs that ONLY appear in sensitive ops, never in routine ops
        anomalous_ips = sensitive_ips - routine_ips
        if not anomalous_ips:
            continue

        timeline = []
        for e in sorted(sensitive_events, key=lambda x: x["timestamp"]):
            ip = e.get("src_ip", "?")
            marker = " ⚠ [ANOMALOUS IP]" if ip in anomalous_ips else ""
            timeline.append(
                (
                    e["timestamp"],
                    f"[SILENT HACKER?] {e.get('event_type')} via '{ua}' from {ip}{marker}",
                )
            )

        ua_short = ua[:60] + ("…" if len(ua) > 60 else "")
        confidence = min(45 + len(anomalous_ips) * 15 + len(sensitive_events) * 5, 88)

        findings.append(
            {
                "title": f"APT: Silent Hacker – '{user}' Developer CLI from Anomalous IP(s)",
                "severity": "HIGH",
                "apt_stage": "Defense Evasion → Collection",
                "hypothesis": (
                    f"Sensitive AWS operations were performed by '{user}' using the developer "
                    f"tool '{ua_short}', but from IP(s) {', '.join(sorted(anomalous_ips))} "
                    "that have no prior association with routine activity. An attacker "
                    "may have obtained credentials and is deliberately reusing the victim's "
                    "CLI user-agent to blend into normal developer activity and evade "
                    "behavioural detection."
                ),
                "evidence": [e["raw"] for e in sorted(sensitive_events, key=lambda x: x["timestamp"])],
                "timeline": timeline,
                "confidence": confidence,
                "indicators": [
                    {"type": "mimicked_user_agent", "value": ua, "weight": 25},
                    {"type": "anomalous_ips", "value": sorted(anomalous_ips), "weight": 30},
                    {"type": "sensitive_op_count", "value": len(sensitive_events), "weight": 20},
                ],
                "mitigations": [
                    f"Verify with '{user}' whether they performed these operations.",
                    f"Immediately rotate credentials / access keys for '{user}'.",
                    "Implement anomalous CloudTrail alerting based on IP + UA combinations.",
                    "Require MFA for all CLI/API access to sensitive services.",
                    "Deploy AWS GuardDuty to detect anomalous IAM and S3 usage patterns.",
                ],
            }
        )

    return findings


# ---------------------------------------------------------------------------
# 4. Multi-Day Lateral Movement Hunter
# ---------------------------------------------------------------------------

_LATERAL_MOVEMENT_EVENTS: Set[str] = {
    "AssumeRole",
    "SwitchRole",
    "GetFederationToken",
    "GetSessionToken",
    "CreateServiceLinkedRole",
}

_MULTI_DAY_THRESHOLD = 3  # distinct days of suspicious activity


def hunt_multi_day_lateral_movement(events: List[LogEvent]) -> List[APTFinding]:
    """
    Detect an adversary operating across multiple days – a classic APT
    characteristic.  Flags users who perform privilege-sensitive API calls
    across 3+ distinct calendar days within the analysis window.
    """
    findings: List[APTFinding] = []

    sensitive_events = [
        e for e in events
        if e.get("event_type") in _IAM_EVENTS | _LATERAL_MOVEMENT_EVENTS
    ]

    # Group by user → {date -> [events]}
    user_day_events: Dict[str, Dict[str, List[LogEvent]]] = defaultdict(lambda: defaultdict(list))
    for e in sensitive_events:
        user = e.get("user", "?")
        day = e["timestamp"].strftime("%Y-%m-%d")
        user_day_events[user][day].append(e)

    for user, day_map in user_day_events.items():
        if len(day_map) < _MULTI_DAY_THRESHOLD:
            continue

        all_user_events = []
        for day_events in day_map.values():
            all_user_events.extend(day_events)
        all_user_events.sort(key=lambda e: e["timestamp"])

        days_active = sorted(day_map.keys())
        first_day_events = day_map[days_active[0]]
        last_day_events = day_map[days_active[-1]]

        # Check for escalating severity: later days should have more sensitive ops
        first_event_types = {e.get("event_type") for e in first_day_events}
        last_event_types = {e.get("event_type") for e in last_day_events}
        new_ops = last_event_types - first_event_types

        timeline = []
        for e in all_user_events:
            timeline.append(
                (
                    e["timestamp"],
                    f"[LATERAL MOVEMENT – Day {e['timestamp'].strftime('%Y-%m-%d')}] "
                    f"{e.get('event_type')} by '{user}' from {e.get('src_ip','?')}",
                )
            )

        confidence = min(40 + len(days_active) * 10 + len(new_ops) * 5, 85)

        findings.append(
            {
                "title": f"APT: Multi-Day Lateral Movement by '{user}' ({len(days_active)} days)",
                "severity": "HIGH",
                "apt_stage": "Lateral Movement → Persistence",
                "hypothesis": (
                    f"User '{user}' performed privileged API calls across {len(days_active)} "
                    f"distinct days ({', '.join(days_active)}). The expanding set of operation "
                    f"types ({', '.join(sorted(new_ops)) if new_ops else 'stable'}) on later "
                    "days suggests progressive exploration of the environment — a hallmark of "
                    "an Advanced Persistent Threat actor methodically mapping cloud resources."
                ),
                "evidence": [e["raw"] for e in all_user_events],
                "timeline": timeline,
                "confidence": confidence,
                "indicators": [
                    {"type": "active_days", "value": days_active, "weight": 30},
                    {"type": "total_sensitive_ops", "value": len(all_user_events), "weight": 15},
                    {"type": "new_op_types_on_last_day", "value": sorted(new_ops), "weight": 20},
                ],
                "mitigations": [
                    f"Audit all API activity by '{user}' across the full {len(days_active)}-day window.",
                    "Check for any roles assumed or users created by this account.",
                    "Revoke long-lived access keys and enforce session-based credentials.",
                    "Enable AWS CloudTrail Insights and anomaly detection.",
                    "Review VPC Flow Logs for lateral movement between services.",
                ],
            }
        )

    return findings


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

APT_HUNTERS = [
    hunt_new_ip_iam_change,
    hunt_new_ip_s3_enum,
    hunt_silent_hacker,
    hunt_multi_day_lateral_movement,
]
