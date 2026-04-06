"""Integration tests – run the full pipeline on sample logs."""
from __future__ import annotations

import os
import pytest

from chronos.analyzer import analyse
from chronos.report import render_threat_intel_report, render_security_brief
from chronos.scoring import score_findings, threat_tier

SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_logs")
AUTH_LOG = os.path.join(SAMPLE_DIR, "auth.log")
CT_LOG = os.path.join(SAMPLE_DIR, "cloudtrail.json")


@pytest.mark.skipif(
    not os.path.exists(AUTH_LOG) or not os.path.exists(CT_LOG),
    reason="Sample log files not present",
)
class TestFullPipeline:
    def setup_method(self):
        self.result = analyse([AUTH_LOG, CT_LOG])

    def test_events_parsed(self):
        assert self.result.event_count > 0

    def test_findings_generated(self):
        assert self.result.finding_count > 0

    def test_apt_findings_present(self):
        apt_findings = [f for f in self.result.findings if "apt_stage" in f]
        assert len(apt_findings) > 0, "Expected at least one APT finding in sample logs"

    def test_critical_finding_present(self):
        assert self.result.critical_count > 0, "Expected CRITICAL findings in sample logs"

    def test_threat_score_above_threshold(self):
        score = score_findings(self.result.findings)
        assert score >= 55, f"Expected threat score >= 55, got {score}"

    def test_threat_intel_report_renders(self):
        report = render_threat_intel_report(self.result)
        assert "# 🔍 Chronos Threat Intelligence Report" in report
        assert "alice" in report  # compromised user should appear

    def test_security_brief_renders(self):
        report = render_security_brief(self.result)
        assert "# 🛡️ Chronos Security Brief" in report

    def test_report_contains_remediation(self):
        report = render_threat_intel_report(self.result)
        assert "## 🛠️ Remediation Plan" in report
        assert "- [ ]" in report  # at least one checkbox
