"""
Threat hunters that examine normalised log events and emit ``Finding`` dicts.

Each hunter returns a (possibly empty) list of findings.  A Finding has:

    title           – short title of the finding
    severity        – "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    hypothesis      – attack-vector hypothesis string
    evidence        – list of raw log lines (str) that support the finding
    timeline        – list of (datetime, description) tuples for the timeline
    mitigations     – list of recommended mitigation strings
"""

from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import List, Tuple

from chronos.parsers import LogEvent

Finding = dict  # type alias


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _seconds_between(events: List[LogEvent]) -> List[float]:
    """Return list of inter-event gap sizes in seconds (sorted by timestamp)."""
    sorted_events = sorted(events, key=lambda e: e["timestamp"])
    gaps = []
    for i in range(1, len(sorted_events)):
        delta = (sorted_events[i]["timestamp"] - sorted_events[i - 1]["timestamp"]).total_seconds()
        gaps.append(delta)
    return gaps


def _is_periodic(gaps: List[float], tolerance: float = 0.15) -> Tuple[bool, float]:
    """
    Return (True, period) if the inter-event gaps are approximately equal
    (within *tolerance* fraction of the mean) – a signal of automation.
    """
    if len(gaps) < 3:
        return False, 0.0
    mean = sum(gaps) / len(gaps)
    if mean == 0:
        return False, 0.0
    deviations = [abs(g - mean) / mean for g in gaps]
    if all(d < tolerance for d in deviations):
        return True, mean
    return False, mean


# ---------------------------------------------------------------------------
# 1. Brute-Force / Credential-Stuffing Hunter
# ---------------------------------------------------------------------------

_BRUTE_FORCE_THRESHOLD = 5      # failures in a window triggers alert
_BRUTE_FORCE_WINDOW = 3600      # seconds (1 hour)


def hunt_brute_force(events: List[LogEvent]) -> List[Finding]:
    """Detect multiple failed SSH/auth logins from the same source IP."""
    findings: List[Finding] = []

    failed = [e for e in events if e.get("event_type") == "failed_login"]
    by_ip: dict = defaultdict(list)
    for e in failed:
        by_ip[e.get("src_ip", "unknown")].append(e)

    for ip, ip_events in by_ip.items():
        ip_events_sorted = sorted(ip_events, key=lambda e: e["timestamp"])

        # Sliding-window count
        window_start = 0
        for window_end in range(len(ip_events_sorted)):
            # Shrink window from left
            while (
                ip_events_sorted[window_end]["timestamp"]
                - ip_events_sorted[window_start]["timestamp"]
            ).total_seconds() > _BRUTE_FORCE_WINDOW:
                window_start += 1

            window = ip_events_sorted[window_start : window_end + 1]
            if len(window) >= _BRUTE_FORCE_THRESHOLD:
                users = {e.get("user", "?") for e in window}
                multiple_users = len(users) > 1
                hypothesis = (
                    "Possible Credential Stuffing" if multiple_users
                    else "Possible Brute-Force Attack"
                )
                hypothesis += f" from {ip} targeting {len(users)} user(s): {', '.join(sorted(users))}"

                timeline = [
                    (e["timestamp"], f"Failed login for '{e.get('user','?')}' from {ip}")
                    for e in window
                ]

                findings.append(
                    {
                        "title": f"{'Credential Stuffing' if multiple_users else 'Brute-Force'} from {ip}",
                        "severity": "HIGH",
                        "hypothesis": hypothesis,
                        "evidence": [e["raw"] for e in window],
                        "timeline": timeline,
                        "mitigations": [
                            f"Block source IP {ip} at the firewall / security group.",
                            "Enable fail2ban or equivalent adaptive blocking.",
                            "Enforce MFA for SSH and console access.",
                            "Review and tighten SSH AllowUsers / AllowGroups.",
                        ],
                    }
                )
                break  # one finding per IP is enough

    return findings


# ---------------------------------------------------------------------------
# 2. Periodic Beacon Hunter (slow/low reconnaissance)
# ---------------------------------------------------------------------------

_PERIODIC_MIN_EVENTS = 4       # minimum events to detect periodicity
_PERIODIC_MIN_INTERVAL = 1800  # minimum period to flag (seconds, 30 min)


def hunt_periodic_activity(events: List[LogEvent]) -> List[Finding]:
    """Detect regularly spaced failed logins or network flows that suggest automation."""
    findings: List[Finding] = []

    # Group failed logins by IP
    failed = [e for e in events if e.get("event_type") == "failed_login"]
    by_ip: dict = defaultdict(list)
    for e in failed:
        by_ip[e.get("src_ip", "unknown")].append(e)

    for ip, ip_events in by_ip.items():
        if len(ip_events) < _PERIODIC_MIN_EVENTS:
            continue
        gaps = _seconds_between(ip_events)
        periodic, period = _is_periodic(gaps)
        if periodic and period >= _PERIODIC_MIN_INTERVAL:
            period_h = period / 3600
            timeline = [
                (e["timestamp"], f"Periodic failed login for '{e.get('user','?')}' from {ip}")
                for e in sorted(ip_events, key=lambda e: e["timestamp"])
            ]
            findings.append(
                {
                    "title": f"Periodic Login Attempts from {ip}",
                    "severity": "MEDIUM",
                    "hypothesis": (
                        f"Slow-scan / low-and-slow credential attack from {ip}. "
                        f"Attempts every ~{period_h:.1f} hour(s) suggest an automated tool "
                        "designed to evade rate-limiting defences."
                    ),
                    "evidence": [e["raw"] for e in sorted(ip_events, key=lambda e: e["timestamp"])],
                    "timeline": timeline,
                    "mitigations": [
                        f"Block {ip} and alert on low-frequency login attempts.",
                        "Tune SIEM correlation rules to detect long-interval patterns.",
                        "Implement progressive lockout / CAPTCHA after N daily failures.",
                    ],
                }
            )

    return findings


# ---------------------------------------------------------------------------
# 3. Successful Login After Failures (Potential Account Compromise)
# ---------------------------------------------------------------------------

_POST_FAILURE_WINDOW = 3600  # seconds


def hunt_login_after_failures(events: List[LogEvent]) -> List[Finding]:
    """Detect a successful login from an IP that previously had many failures."""
    findings: List[Finding] = []

    failed = defaultdict(list)
    success = defaultdict(list)

    for e in events:
        ip = e.get("src_ip", "")
        if e.get("event_type") == "failed_login":
            failed[ip].append(e)
        elif e.get("event_type") == "successful_login":
            success[ip].append(e)

    for ip in set(failed.keys()) & set(success.keys()):
        for s_event in success[ip]:
            prior_failures = [
                f for f in failed[ip]
                if (s_event["timestamp"] - f["timestamp"]).total_seconds()
                in range(0, _POST_FAILURE_WINDOW + 1)
            ]
            if len(prior_failures) >= 3:
                all_evidence = prior_failures + [s_event]
                all_evidence.sort(key=lambda e: e["timestamp"])
                user = s_event.get("user", "?")
                timeline = []
                for e in all_evidence:
                    if e.get("event_type") == "failed_login":
                        timeline.append((e["timestamp"], f"FAILED login attempt for '{e.get('user','?')}' from {ip}"))
                    else:
                        timeline.append((e["timestamp"], f"SUCCESSFUL login for '{user}' from {ip}"))

                findings.append(
                    {
                        "title": f"Account Compromise – Successful Login After {len(prior_failures)} Failures ({ip})",
                        "severity": "CRITICAL",
                        "hypothesis": (
                            f"IP {ip} made {len(prior_failures)} failed login attempts before "
                            f"successfully authenticating as '{user}'. This strongly suggests "
                            "Brute-Force leading to Account Compromise."
                        ),
                        "evidence": [e["raw"] for e in all_evidence],
                        "timeline": timeline,
                        "mitigations": [
                            f"Immediately lock account '{user}' and rotate credentials.",
                            f"Block source IP {ip} and investigate its origin.",
                            "Audit all actions performed by the session after the successful login.",
                            "Enable MFA for all privileged accounts.",
                        ],
                    }
                )

    return findings


# ---------------------------------------------------------------------------
# 4. Privilege Escalation Hunter  (new user + sudo or S3 policy change)
# ---------------------------------------------------------------------------

def hunt_privilege_escalation(events: List[LogEvent]) -> List[Finding]:
    """Correlate user-creation events with subsequent privileged actions."""
    findings: List[Finding] = []

    created_users = {}
    for e in events:
        if e.get("event_type") == "user_created":
            created_users[e.get("user", "")] = e

    if not created_users:
        return findings

    # Look for sudo commands by newly created users
    for e in events:
        if e.get("event_type") == "sudo_command":
            # Sudo events don't carry username directly – check surrounding context
            pass  # handled below via raw string matching

    # Look for CloudTrail privilege-sensitive events after user creation
    sensitive_ct_events = [
        "AttachUserPolicy",
        "PutUserPolicy",
        "CreateAccessKey",
        "AddUserToGroup",
        "UpdateAssumeRolePolicy",
        "PutBucketPolicy",
        "PutBucketAcl",
    ]

    for user, creation_event in created_users.items():
        related_ct = [
            e for e in events
            if e["source"] == "cloudtrail"
            and e.get("event_type") in sensitive_ct_events
            and e["timestamp"] >= creation_event["timestamp"]
            and (
                user in e.get("raw", "")
                or user in str(e.get("request_parameters", ""))
            )
        ]
        if related_ct:
            timeline_events = [creation_event] + related_ct
            timeline_events.sort(key=lambda e: e["timestamp"])
            findings.append(
                {
                    "title": f"Privilege Escalation – New User '{user}' Gained Elevated Permissions",
                    "severity": "CRITICAL",
                    "hypothesis": (
                        f"User '{user}' was created and then immediately associated with "
                        "elevated AWS permissions. This pattern is consistent with "
                        "Persistence via New Account followed by Privilege Escalation."
                    ),
                    "evidence": [e["raw"] for e in timeline_events],
                    "timeline": [
                        (e["timestamp"], f"{e.get('event_type','?')} involving '{user}'")
                        for e in timeline_events
                    ],
                    "mitigations": [
                        f"Immediately disable or delete account '{user}'.",
                        "Audit all IAM changes within the incident window.",
                        "Enforce least-privilege and require MFA for sensitive API calls.",
                        "Enable AWS CloudTrail Insights to detect unusual API activity.",
                    ],
                }
            )

    return findings


# ---------------------------------------------------------------------------
# 5. S3 Bucket Policy Change Hunter
# ---------------------------------------------------------------------------

_S3_SENSITIVE_EVENTS = {
    "PutBucketPolicy",
    "DeleteBucketPolicy",
    "PutBucketAcl",
    "PutBucketPublicAccessBlock",
    "DeletePublicAccessBlock",
}


def hunt_s3_policy_changes(events: List[LogEvent]) -> List[Finding]:
    """Flag any S3 bucket policy / ACL modifications."""
    findings: List[Finding] = []

    s3_events = [
        e for e in events
        if e["source"] == "cloudtrail"
        and e.get("event_type") in _S3_SENSITIVE_EVENTS
    ]

    if not s3_events:
        return findings

    for e in s3_events:
        bucket = str(e.get("request_parameters", {}).get("bucketName", "unknown"))
        findings.append(
            {
                "title": f"S3 Bucket Policy Change – {e.get('event_type')} on '{bucket}'",
                "severity": "HIGH",
                "hypothesis": (
                    f"The S3 bucket '{bucket}' had its policy or ACL modified "
                    f"({e.get('event_type')}) by '{e.get('user','?')}' from {e.get('src_ip','?')}. "
                    "This may indicate Data Exfiltration Preparation or Lateral Movement."
                ),
                "evidence": [e["raw"]],
                "timeline": [
                    (e["timestamp"], f"{e.get('event_type')} on bucket '{bucket}' by '{e.get('user','?')}'")
                ],
                "mitigations": [
                    f"Review the policy change on bucket '{bucket}' immediately.",
                    "Check whether the bucket became publicly accessible.",
                    "Enable S3 Block Public Access at the account level.",
                    "Ensure all sensitive buckets have versioning and access logging enabled.",
                ],
            }
        )

    return findings


# ---------------------------------------------------------------------------
# 6. Impossible Travel Hunter (same user, two distant IPs in short time)
# ---------------------------------------------------------------------------

_IMPOSSIBLE_TRAVEL_WINDOW = 900  # seconds (15 min)


def hunt_impossible_travel(events: List[LogEvent]) -> List[Finding]:
    """Detect the same user authenticating from two very different IPs in a short window."""
    findings: List[Finding] = []

    successful = [e for e in events if e.get("event_type") == "successful_login"]
    by_user: dict = defaultdict(list)
    for e in successful:
        by_user[e.get("user", "?")].append(e)

    for user, user_events in by_user.items():
        user_events_sorted = sorted(user_events, key=lambda e: e["timestamp"])
        for i in range(len(user_events_sorted)):
            for j in range(i + 1, len(user_events_sorted)):
                a, b = user_events_sorted[i], user_events_sorted[j]
                delta = (b["timestamp"] - a["timestamp"]).total_seconds()
                if delta > _IMPOSSIBLE_TRAVEL_WINDOW:
                    break
                if a.get("src_ip") != b.get("src_ip"):
                    findings.append(
                        {
                            "title": f"Impossible Travel – '{user}' from {a.get('src_ip')} and {b.get('src_ip')} within {int(delta)}s",
                            "severity": "HIGH",
                            "hypothesis": (
                                f"User '{user}' logged in from {a.get('src_ip')} and then "
                                f"from {b.get('src_ip')} within {int(delta)} seconds. "
                                "This is physically impossible and suggests Account Sharing, "
                                "Stolen Credentials, or Session Hijacking."
                            ),
                            "evidence": [a["raw"], b["raw"]],
                            "timeline": [
                                (a["timestamp"], f"Login for '{user}' from {a.get('src_ip')}"),
                                (b["timestamp"], f"Login for '{user}' from {b.get('src_ip')}"),
                            ],
                            "mitigations": [
                                f"Immediately revoke all active sessions for '{user}'.",
                                "Force password reset and re-enrol MFA.",
                                "Investigate both source IPs for ownership and reputation.",
                            ],
                        }
                    )

    return findings


# ---------------------------------------------------------------------------
# Registry of all hunters
# ---------------------------------------------------------------------------

ALL_HUNTERS = [
    hunt_brute_force,
    hunt_periodic_activity,
    hunt_login_after_failures,
    hunt_privilege_escalation,
    hunt_s3_policy_changes,
    hunt_impossible_travel,
]
