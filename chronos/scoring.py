"""
Confidence scoring for Chronos findings.

Each finding produced by a hunter carries a raw ``confidence`` value (0-100).
This module aggregates multiple findings into a single overall **Threat Score**
and classifies the severity tier of the incident.

Scoring model
-------------
* APT findings with ``confidence`` already carry their own score.
* Base-tier findings (brute-force, S3 change, etc.) are assigned a default
  confidence based on their severity.
* The overall threat score is the weighted mean of the top-N findings,
  capped at 100.

Tier labels
-----------
  90-100  CONFIRMED COMPROMISE
  75-89   HIGHLY LIKELY THREAT
  55-74   PROBABLE THREAT
  35-54   SUSPICIOUS ACTIVITY
  0-34    INFORMATIONAL
"""

from __future__ import annotations

from typing import List

# Default confidence values for base hunters that don't carry their own
_SEVERITY_DEFAULT_CONFIDENCE = {
    "CRITICAL": 75,
    "HIGH": 55,
    "MEDIUM": 35,
    "LOW": 15,
    "INFO": 5,
}

# How many top findings contribute to the aggregate score
_TOP_N = 5


def _finding_confidence(finding: dict) -> int:
    """Return the confidence value for a single finding."""
    if "confidence" in finding:
        return int(finding["confidence"])
    return _SEVERITY_DEFAULT_CONFIDENCE.get(finding.get("severity", "INFO"), 5)


def score_findings(findings: List[dict]) -> int:
    """
    Compute an overall Threat Score (0-100) from a list of findings.

    The score is a weighted average of the top-N individual confidence values,
    where the highest-confidence finding carries double weight.
    """
    if not findings:
        return 0

    scores = sorted([_finding_confidence(f) for f in findings], reverse=True)
    top = scores[:_TOP_N]

    if not top:
        return 0

    # Double-weight the top finding
    weighted_sum = top[0] * 2 + sum(top[1:])
    weight_total = 2 + len(top) - 1
    raw = weighted_sum / weight_total

    return min(100, int(round(raw)))


def threat_tier(score: int) -> str:
    """Convert a numeric threat score into a human-readable tier label."""
    if score >= 90:
        return "CONFIRMED COMPROMISE"
    elif score >= 75:
        return "HIGHLY LIKELY THREAT"
    elif score >= 55:
        return "PROBABLE THREAT"
    elif score >= 35:
        return "SUSPICIOUS ACTIVITY"
    else:
        return "INFORMATIONAL"


def annotate_findings(findings: List[dict]) -> List[dict]:
    """Return findings with a ``confidence`` key set (in-place annotation)."""
    for f in findings:
        if "confidence" not in f:
            f["confidence"] = _SEVERITY_DEFAULT_CONFIDENCE.get(
                f.get("severity", "INFO"), 5
            )
    return findings
