"""Tests for confidence scoring and report rendering."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest

from chronos.scoring import score_findings, threat_tier, annotate_findings
from chronos.report import render_security_brief, render_threat_intel_report
from chronos.analyzer import AnalysisResult


def _finding(severity="HIGH", confidence=None, title="Test Finding", apt_stage=None,
             mitigations=None):
    f = {
        "title": title,
        "severity": severity,
        "hypothesis": "Test hypothesis.",
        "evidence": ["log line 1", "log line 2"],
        "timeline": [(datetime(2026, 4, 1, 12, 0, 0, tzinfo=timezone.utc), "Event")],
        "mitigations": mitigations if mitigations is not None else ["Do something.", "Do another thing."],
    }
    if confidence is not None:
        f["confidence"] = confidence
    if apt_stage is not None:
        f["apt_stage"] = apt_stage
    return f


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

class TestScoring:
    def test_empty_findings_zero(self):
        assert score_findings([]) == 0

    def test_single_critical_finding(self):
        findings = [_finding("CRITICAL", confidence=80)]
        score = score_findings(findings)
        assert score > 0

    def test_score_capped_at_100(self):
        findings = [_finding("CRITICAL", confidence=100)] * 10
        assert score_findings(findings) <= 100

    def test_higher_confidence_gives_higher_score(self):
        low = score_findings([_finding(confidence=20)])
        high = score_findings([_finding(confidence=80)])
        assert high > low

    def test_annotate_fills_missing_confidence(self):
        f = _finding("CRITICAL")
        assert "confidence" not in f
        annotate_findings([f])
        assert "confidence" in f
        assert f["confidence"] == 75  # CRITICAL default

    def test_annotate_does_not_overwrite(self):
        f = _finding("CRITICAL", confidence=42)
        annotate_findings([f])
        assert f["confidence"] == 42


class TestThreatTier:
    def test_confirmed_compromise(self):
        assert threat_tier(95) == "CONFIRMED COMPROMISE"

    def test_highly_likely(self):
        assert threat_tier(80) == "HIGHLY LIKELY THREAT"

    def test_probable(self):
        assert threat_tier(60) == "PROBABLE THREAT"

    def test_suspicious(self):
        assert threat_tier(40) == "SUSPICIOUS ACTIVITY"

    def test_informational(self):
        assert threat_tier(20) == "INFORMATIONAL"

    def test_boundary_values(self):
        assert threat_tier(90) == "CONFIRMED COMPROMISE"
        assert threat_tier(89) == "HIGHLY LIKELY THREAT"
        assert threat_tier(75) == "HIGHLY LIKELY THREAT"
        assert threat_tier(74) == "PROBABLE THREAT"


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------

def _make_result(findings=None):
    events = [
        {
            "source": "ssh",
            "event_type": "failed_login",
            "user": "alice",
            "src_ip": "1.2.3.4",
            "timestamp": datetime(2026, 4, 1, 10, 0, 0, tzinfo=timezone.utc),
            "raw": "Failed password for alice from 1.2.3.4 port 22 ssh2",
        }
    ]
    return AnalysisResult(
        events=events,
        findings=findings or [],
        log_sources=["auth.log", "cloudtrail.json"],
        analysis_time=datetime(2026, 4, 6, 12, 0, 0, tzinfo=timezone.utc),
    )


class TestRenderSecurityBrief:
    def test_contains_header(self):
        report = render_security_brief(_make_result())
        assert "# 🛡️ Chronos Security Brief" in report

    def test_contains_all_sections(self):
        report = render_security_brief(_make_result([_finding()]))
        assert "## Executive Summary" in report
        assert "## Timeline of Activity" in report
        assert "## Evidence Blocks" in report
        assert "## Recommended Mitigations" in report

    def test_finding_appears_in_report(self):
        f = _finding(title="My Special Finding")
        report = render_security_brief(_make_result([f]))
        assert "My Special Finding" in report

    def test_empty_findings_handled(self):
        report = render_security_brief(_make_result([]))
        assert "No significant threat indicators" in report

    def test_log_sources_listed(self):
        report = render_security_brief(_make_result())
        assert "auth.log" in report
        assert "cloudtrail.json" in report


class TestRenderThreatIntelReport:
    def test_contains_header(self):
        report = render_threat_intel_report(_make_result())
        assert "# 🔍 Chronos Threat Intelligence Report" in report

    def test_contains_all_sections(self):
        report = render_threat_intel_report(_make_result([_finding()]))
        assert "## 📊 Threat Score Dashboard" in report
        assert "## 🎯 APT Analysis" in report
        assert "## 📅 Unified Attack Timeline" in report
        assert "## 🛠️ Remediation Plan" in report

    def test_confidence_score_displayed(self):
        f = _finding(confidence=77)
        report = render_threat_intel_report(_make_result([f]))
        assert "77/100" in report

    def test_apt_finding_in_apt_section(self):
        f = _finding(apt_stage="Initial Access → Exfiltration", title="APT Test")
        report = render_threat_intel_report(_make_result([f]))
        assert "APT Test" in report
        assert "Initial Access → Exfiltration" in report

    def test_remediation_plan_priority_buckets(self):
        findings = [
            _finding("CRITICAL", title="Critical One"),
            _finding("HIGH", title="High One",
                     mitigations=["Block the source IP immediately.", "Rotate all credentials."]),
        ]
        report = render_threat_intel_report(_make_result(findings))
        assert "Immediate" in report
        assert "Urgent" in report

    def test_tlp_amber_classification(self):
        report = render_threat_intel_report(_make_result())
        assert "TLP:AMBER" in report
