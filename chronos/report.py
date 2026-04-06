"""
Threat Intelligence Report and Security Brief generator.

Produces a Markdown document from a completed ``AnalysisResult``.

Two report modes:
  - ``render_security_brief``       – original Tier 3 SOC Security Brief format
  - ``render_threat_intel_report``  – L3 IR Specialist Threat Intelligence Report
    with Confidence Score, APT attribution, and Remediation Plan.
"""

from __future__ import annotations

import textwrap
from datetime import datetime, timezone
from typing import List

from chronos.scoring import annotate_findings, score_findings, threat_tier

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

_SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
    "INFO": "⚪",
}

_SCORE_BAR_WIDTH = 20


def _score_bar(score: int) -> str:
    """Render a simple ASCII progress bar for the confidence score."""
    filled = round(score / 100 * _SCORE_BAR_WIDTH)
    bar = "█" * filled + "░" * (_SCORE_BAR_WIDTH - filled)
    return f"`[{bar}]` **{score}/100**"


def _fmt_ts(ts) -> str:
    if ts is None:
        return "N/A"
    if hasattr(ts, "strftime"):
        return ts.strftime("%Y-%m-%d %H:%M:%S UTC")
    return str(ts)


def _dedent(text: str) -> str:
    return textwrap.dedent(text).strip()


def _evidence_block(lines: List[str], max_lines: int = 20) -> str:
    shown = lines[:max_lines]
    truncated = len(lines) - max_lines
    block = "\n".join(shown)
    if truncated > 0:
        block += f"\n… ({truncated} additional lines truncated)"
    return f"```\n{block}\n```"


def _mitigations_list(mitigations: List[str]) -> str:
    return "\n".join(f"- {m}" for m in mitigations)


# ---------------------------------------------------------------------------
# Security Brief  (Tier 3 SOC format)
# ---------------------------------------------------------------------------

def render_security_brief(result) -> str:
    """Render a Security Brief markdown document from an ``AnalysisResult``."""
    annotate_findings(result.findings)
    threat_score = score_findings(result.findings)
    tier = threat_tier(threat_score)
    t_start, t_end = result.time_range
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    lines: List[str] = []

    # ── Header ──────────────────────────────────────────────────────────────
    lines += [
        "# 🛡️ Chronos Security Brief",
        "",
        f"**Generated:** {now}  ",
        f"**Log Sources:** {', '.join(result.log_sources) or 'N/A'}  ",
        f"**Analysis Window:** {_fmt_ts(t_start)} → {_fmt_ts(t_end)}  ",
        f"**Events Analysed:** {result.event_count:,}  ",
        f"**Findings:** {result.finding_count}  ",
        "",
        "---",
        "",
    ]

    # ── Executive Summary ───────────────────────────────────────────────────
    lines += [
        "## Executive Summary",
        "",
        f"> **Threat Score:** {_score_bar(threat_score)}  ",
        f"> **Assessment:** {tier}",
        "",
    ]

    if not result.findings:
        lines += [
            "No significant threat indicators were identified in the provided log data.",
            "",
        ]
    else:
        critical = result.critical_count
        high = result.high_count
        total = result.finding_count
        lines += [
            f"Chronos identified **{total} finding(s)** across the analysed log sources: "
            f"**{critical} CRITICAL**, **{high} HIGH**, and "
            f"**{total - critical - high} MEDIUM/LOW/INFO**.  ",
            "",
            "Key findings include:",
            "",
        ]
        for f in result.findings[:5]:
            emoji = _SEVERITY_EMOJI.get(f["severity"], "⚪")
            lines.append(f"- {emoji} **{f['title']}**")
        if total > 5:
            lines.append(f"- … and {total - 5} additional finding(s)")
        lines.append("")

    lines += ["---", ""]

    # ── Timeline of Activity ────────────────────────────────────────────────
    lines += ["## Timeline of Activity", ""]

    all_timeline: list = []
    for f in result.findings:
        for ts, desc in f.get("timeline", []):
            all_timeline.append((ts, desc, f["severity"]))

    if all_timeline:
        all_timeline.sort(key=lambda x: x[0])
        lines.append("| Timestamp (UTC) | Event | Severity |")
        lines.append("|---|---|---|")
        for ts, desc, sev in all_timeline:
            emoji = _SEVERITY_EMOJI.get(sev, "⚪")
            lines.append(f"| `{_fmt_ts(ts)}` | {desc} | {emoji} {sev} |")
    else:
        lines.append("_No significant events to display._")

    lines += ["", "---", ""]

    # ── Evidence Blocks ─────────────────────────────────────────────────────
    lines += ["## Evidence Blocks", ""]

    for idx, f in enumerate(result.findings, 1):
        emoji = _SEVERITY_EMOJI.get(f["severity"], "⚪")
        lines += [
            f"### Finding {idx}: {emoji} {f['title']}",
            "",
            f"**Severity:** {f['severity']}  ",
            f"**Confidence:** {f.get('confidence', 'N/A')}/100  ",
            "",
            f"**Hypothesis:** {f['hypothesis']}",
            "",
            "**Raw Evidence:**",
            "",
            _evidence_block(f.get("evidence", [])),
            "",
        ]

    lines += ["---", ""]

    # ── Recommended Mitigations ─────────────────────────────────────────────
    lines += ["## Recommended Mitigations", ""]

    seen_mitigations: set = set()
    for f in result.findings:
        for m in f.get("mitigations", []):
            if m not in seen_mitigations:
                seen_mitigations.add(m)
                lines.append(f"- {m}")

    if not seen_mitigations:
        lines.append("_No mitigations required._")

    lines += ["", "---", ""]
    lines += [
        "_Report generated by [Chronos](https://github.com/dukemawex/Chronos) – "
        "Autonomous Threat Hunting Engine._",
    ]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Threat Intelligence Report  (L3 IR Specialist format)
# ---------------------------------------------------------------------------

def render_threat_intel_report(result) -> str:
    """
    Render a Threat Intelligence Report markdown document.

    This is the enhanced L3 Incident Response output with:
      - Overall Confidence Score
      - Threat Tier classification
      - APT stage mapping
      - Per-finding indicator tables
      - Structured Remediation Plan
    """
    annotate_findings(result.findings)
    threat_score = score_findings(result.findings)
    tier = threat_tier(threat_score)
    t_start, t_end = result.time_range
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Separate APT findings (have apt_stage) from base findings
    apt_findings = [f for f in result.findings if "apt_stage" in f]
    base_findings = [f for f in result.findings if "apt_stage" not in f]

    lines: List[str] = []

    # ── Cover Page ───────────────────────────────────────────────────────────
    lines += [
        "# 🔍 Chronos Threat Intelligence Report",
        "",
        "> **Classification:** TLP:AMBER — Restricted to incident response team",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| **Report Date** | {now} |",
        f"| **Analyst Role** | L3 Incident Response Specialist |",
        f"| **Log Sources** | {', '.join(result.log_sources) or 'N/A'} |",
        f"| **Analysis Window** | {_fmt_ts(t_start)} → {_fmt_ts(t_end)} |",
        f"| **Events Analysed** | {result.event_count:,} |",
        f"| **Total Findings** | {result.finding_count} |",
        "",
        "---",
        "",
    ]

    # ── Threat Score Dashboard ───────────────────────────────────────────────
    lines += [
        "## 📊 Threat Score Dashboard",
        "",
        f"### Overall Confidence Score: {_score_bar(threat_score)}",
        "",
        f"**Threat Tier: `{tier}`**",
        "",
    ]

    tier_descriptions = {
        "CONFIRMED COMPROMISE": (
            "Evidence strongly supports an active or recent breach. "
            "Invoke your Incident Response Plan immediately."
        ),
        "HIGHLY LIKELY THREAT": (
            "Multiple correlated indicators point to a threat actor with high confidence. "
            "Escalate to CISO and begin containment."
        ),
        "PROBABLE THREAT": (
            "Suspicious patterns found across multiple log sources. "
            "Initiate investigation and prepare containment actions."
        ),
        "SUSPICIOUS ACTIVITY": (
            "Anomalous activity detected that warrants investigation. "
            "Monitor closely and gather additional evidence."
        ),
        "INFORMATIONAL": (
            "Low-confidence signals only. Continue monitoring and baseline tuning."
        ),
    }
    lines += [
        f"_{tier_descriptions.get(tier, '')}_",
        "",
        "### Finding Breakdown",
        "",
        "| Severity | Count | Examples |",
        "|---|---|---|",
    ]

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        sev_findings = [f for f in result.findings if f["severity"] == sev]
        if sev_findings:
            emoji = _SEVERITY_EMOJI[sev]
            examples = "; ".join(f["title"] for f in sev_findings[:2])
            if len(sev_findings) > 2:
                examples += f" (+{len(sev_findings) - 2} more)"
            lines.append(f"| {emoji} {sev} | {len(sev_findings)} | {examples} |")

    lines += ["", "---", ""]

    # ── APT Analysis ─────────────────────────────────────────────────────────
    lines += ["## 🎯 APT Analysis", ""]

    if apt_findings:
        # Map stages
        stage_map: dict = {}
        for f in apt_findings:
            stage = f.get("apt_stage", "Unknown")
            stage_map.setdefault(stage, []).append(f)

        lines += [
            "### MITRE ATT&CK Stage Mapping",
            "",
            "| Stage | Findings | Max Confidence |",
            "|---|---|---|",
        ]
        for stage, stage_findings in stage_map.items():
            max_conf = max(f.get("confidence", 0) for f in stage_findings)
            titles = ", ".join(f["title"] for f in stage_findings[:2])
            lines.append(f"| `{stage}` | {len(stage_findings)} | {max_conf}/100 |")

        lines += ["", "### Detailed APT Findings", ""]

        for idx, f in enumerate(apt_findings, 1):
            emoji = _SEVERITY_EMOJI.get(f["severity"], "⚪")
            lines += [
                f"#### APT Finding {idx}: {emoji} {f['title']}",
                "",
                f"| | |",
                f"|---|---|",
                f"| **Severity** | {f['severity']} |",
                f"| **Confidence Score** | {_score_bar(f.get('confidence', 0))} |",
                f"| **ATT&CK Stage** | `{f.get('apt_stage', 'N/A')}` |",
                "",
                f"**Hypothesis:**",
                "",
                f"> {f['hypothesis']}",
                "",
            ]

            # Indicator table
            indicators = f.get("indicators", [])
            if indicators:
                lines += [
                    "**Indicators of Compromise:**",
                    "",
                    "| Indicator Type | Value | Weight |",
                    "|---|---|---|",
                ]
                for ind in indicators:
                    val = ind["value"]
                    if isinstance(val, list):
                        val = ", ".join(str(v) for v in val[:5])
                        if len(ind["value"]) > 5:
                            val += "…"
                    lines.append(f"| `{ind['type']}` | {val} | {ind['weight']} |")
                lines.append("")

            # Timeline
            timeline = f.get("timeline", [])
            if timeline:
                lines += [
                    "**Attack Timeline:**",
                    "",
                    "| Timestamp (UTC) | Event |",
                    "|---|---|",
                ]
                for ts, desc in timeline:
                    lines.append(f"| `{_fmt_ts(ts)}` | {desc} |")
                lines.append("")

            # Evidence
            lines += [
                "**Evidence:**",
                "",
                _evidence_block(f.get("evidence", [])),
                "",
            ]
    else:
        lines += [
            "_No APT-specific patterns detected in the current analysis window._",
            "",
            "This may indicate:  ",
            "- The attacker has not yet performed post-access actions, **or**  ",
            "- The log window is insufficient for multi-day correlation, **or**  ",
            "- The environment is not actively targeted.",
            "",
        ]

    lines += ["---", ""]

    # ── Base Findings ────────────────────────────────────────────────────────
    if base_findings:
        lines += ["## 🔎 Supporting Findings", ""]
        for idx, f in enumerate(base_findings, 1):
            emoji = _SEVERITY_EMOJI.get(f["severity"], "⚪")
            lines += [
                f"### Finding {idx}: {emoji} {f['title']}",
                "",
                f"**Severity:** {f['severity']} | **Confidence:** {f.get('confidence', 'N/A')}/100",
                "",
                f"**Hypothesis:** {f['hypothesis']}",
                "",
                "**Evidence:**",
                "",
                _evidence_block(f.get("evidence", [])),
                "",
            ]
        lines += ["---", ""]

    # ── Full Timeline ────────────────────────────────────────────────────────
    lines += ["## 📅 Unified Attack Timeline", ""]

    all_timeline: list = []
    for f in result.findings:
        stage = f.get("apt_stage", "—")
        for ts, desc in f.get("timeline", []):
            all_timeline.append((ts, stage, desc, f["severity"]))

    if all_timeline:
        all_timeline.sort(key=lambda x: x[0])
        lines += [
            "| Timestamp (UTC) | ATT&CK Stage | Event | Severity |",
            "|---|---|---|---|",
        ]
        for ts, stage, desc, sev in all_timeline:
            emoji = _SEVERITY_EMOJI.get(sev, "⚪")
            lines.append(f"| `{_fmt_ts(ts)}` | `{stage}` | {desc} | {emoji} {sev} |")
    else:
        lines.append("_No events to display._")

    lines += ["", "---", ""]

    # ── Remediation Plan ─────────────────────────────────────────────────────
    lines += [
        "## 🛠️ Remediation Plan",
        "",
        "The following actions are ordered by priority (highest first).",
        "",
    ]

    # Bucket mitigations by severity
    priority_buckets: dict = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    seen: set = set()
    for f in result.findings:
        sev = f.get("severity", "LOW")
        bucket = priority_buckets.get(sev, priority_buckets["LOW"])
        for m in f.get("mitigations", []):
            if m not in seen:
                seen.add(m)
                bucket.append(m)

    priority_labels = {
        "CRITICAL": "🔴 Immediate (within 1 hour)",
        "HIGH": "🟠 Urgent (within 24 hours)",
        "MEDIUM": "🟡 Short-term (within 1 week)",
        "LOW": "🔵 Long-term (ongoing)",
    }

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        items = priority_buckets[sev]
        if items:
            lines += [f"### {priority_labels[sev]}", ""]
            for item in items:
                lines.append(f"- [ ] {item}")
            lines.append("")

    lines += ["---", ""]

    # ── Footer ───────────────────────────────────────────────────────────────
    lines += [
        "## 📋 Report Metadata",
        "",
        "| Field | Value |",
        "|---|---|",
        f"| Engine | Chronos v1.0.0 |",
        f"| Hunters Active | {len(result.log_sources)} log source(s) |",
        f"| Unique IPs Observed | {len(result.unique_ips)} |",
        f"| Overall Threat Score | {threat_score}/100 — {tier} |",
        "",
        "---",
        "",
        "_This report was generated automatically by "
        "[Chronos](https://github.com/dukemawex/Chronos). "
        "All findings should be validated by a qualified security analyst "
        "before remediation actions are taken._",
    ]

    return "\n".join(lines)
