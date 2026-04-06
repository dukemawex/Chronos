"""Tests for APT hunters."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from chronos.hunters.apt import (
    hunt_new_ip_iam_change,
    hunt_new_ip_s3_enum,
    hunt_silent_hacker,
    hunt_multi_day_lateral_movement,
)


def _ts(day=1, hour=0, minute=0, second=0):
    return datetime(2026, 4, day, hour, minute, second, tzinfo=timezone.utc)


def _ct(event_type, user="alice", ip="1.2.3.4", day=1, hour=0, minute=0,
        ua="aws-cli/2.0 Python/3.11", params=None):
    rec = {
        "eventName": event_type,
        "userIdentity": {"userName": user, "arn": f"arn:aws:iam::123:user/{user}"},
        "sourceIPAddress": ip,
        "userAgent": ua,
        "requestParameters": params or {},
    }
    return {
        "source": "cloudtrail",
        "event_type": event_type,
        "user": user,
        "src_ip": ip,
        "timestamp": _ts(day, hour, minute),
        "raw": json.dumps(rec),
        "request_parameters": params or {},
        "response_elements": {},
        "error_code": "",
    }


def _login(ip="1.2.3.4", user="alice", day=1, hour=0, minute=0):
    return {
        "source": "ssh",
        "event_type": "successful_login",
        "user": user,
        "src_ip": ip,
        "timestamp": _ts(day, hour, minute),
        "raw": f"Accepted publickey for {user} from {ip} port 22 ssh2",
    }


# ---------------------------------------------------------------------------
# New-IP Login → IAM Change
# ---------------------------------------------------------------------------

class TestHuntNewIPIAMChange:
    def test_detects_new_ip_iam(self):
        events = [
            _login(ip="99.99.99.99"),  # new IP (nothing in baseline for alice)
            _ct("AttachUserPolicy", user="alice", ip="99.99.99.99", minute=5),
        ]
        findings = hunt_new_ip_iam_change(events)
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"
        assert "alice" in findings[0]["title"]

    def test_no_finding_when_no_iam_follows(self):
        events = [
            _login(ip="99.99.99.99"),
            _ct("GetObject", user="alice", ip="99.99.99.99", minute=5),
        ]
        assert hunt_new_ip_iam_change(events) == []

    def test_no_finding_outside_window(self):
        events = [
            _login(ip="99.99.99.99", hour=0),
            _ct("AttachUserPolicy", user="alice", ip="99.99.99.99", hour=2),  # 2h later
        ]
        assert hunt_new_ip_iam_change(events) == []

    def test_confidence_increases_with_more_iam_events(self):
        events = [_login(ip="99.99.99.99")]
        for i in range(5):
            events.append(_ct("CreateAccessKey", user="alice", ip="99.99.99.99", minute=i+1))
        findings = hunt_new_ip_iam_change(events)
        assert findings[0]["confidence"] > 60


# ---------------------------------------------------------------------------
# New-IP Login → S3 Enumeration
# ---------------------------------------------------------------------------

class TestHuntNewIPS3Enum:
    def test_detects_s3_enum(self):
        events = [
            _login(ip="88.88.88.88"),
            _ct("ListBuckets", user="alice", ip="88.88.88.88", minute=3),
            _ct("ListObjects", user="alice", ip="88.88.88.88", minute=4,
                params={"bucketName": "prod-data"}),
        ]
        findings = hunt_new_ip_s3_enum(events)
        assert len(findings) == 1
        assert "alice" in findings[0]["title"]

    def test_exfiltration_severity_critical(self):
        events = [
            _login(ip="88.88.88.88"),
            _ct("GetObject", user="alice", ip="88.88.88.88", minute=5,
                params={"bucketName": "prod-data"}),
        ]
        findings = hunt_new_ip_s3_enum(events)
        assert findings[0]["severity"] == "CRITICAL"
        assert "Exfiltration" in findings[0]["title"]

    def test_enumeration_severity_high(self):
        events = [
            _login(ip="88.88.88.88"),
            _ct("ListBuckets", user="alice", ip="88.88.88.88", minute=3),
        ]
        findings = hunt_new_ip_s3_enum(events)
        assert findings[0]["severity"] == "HIGH"


# ---------------------------------------------------------------------------
# Silent Hacker
# ---------------------------------------------------------------------------

class TestHuntSilentHacker:
    _DEV_UA = "aws-cli/2.15.0 Python/3.11.8 Linux/5.15.0 botocore/2.15.0"

    def test_detects_silent_hacker(self):
        # Routine ops from known IP, sensitive ops from anomalous IP – same UA
        routine = [
            _ct("GetObject", user="alice", ip="10.0.0.1", ua=self._DEV_UA, minute=i)
            for i in range(3)
        ]
        sensitive = [
            _ct("CreateAccessKey", user="alice", ip="200.200.200.200",
                ua=self._DEV_UA, minute=30),
            _ct("PutBucketPolicy", user="alice", ip="200.200.200.200",
                ua=self._DEV_UA, minute=31),
        ]
        findings = hunt_silent_hacker(routine + sensitive)
        assert len(findings) == 1
        assert "200.200.200.200" in findings[0]["hypothesis"]

    def test_no_finding_when_ips_consistent(self):
        # Sensitive ops from the same IP as routine ops
        events = [
            _ct("GetObject", user="alice", ip="10.0.0.1", ua=self._DEV_UA, minute=i)
            for i in range(3)
        ] + [
            _ct("CreateAccessKey", user="alice", ip="10.0.0.1", ua=self._DEV_UA, minute=10),
        ]
        assert hunt_silent_hacker(events) == []

    def test_no_finding_for_non_dev_ua(self):
        # Non-developer UA performing sensitive ops
        events = [
            _ct("CreateAccessKey", user="alice", ip="200.200.200.200",
                ua="curl/7.84.0", minute=5),
        ]
        assert hunt_silent_hacker(events) == []


# ---------------------------------------------------------------------------
# Multi-Day Lateral Movement
# ---------------------------------------------------------------------------

class TestHuntMultiDayLateralMovement:
    def test_detects_multi_day(self):
        events = [
            _ct("CreateUser",   user="alice", day=1, hour=9),
            _ct("AttachUserPolicy", user="alice", day=2, hour=10),
            _ct("AssumeRole",   user="alice", day=3, hour=11),
        ]
        findings = hunt_multi_day_lateral_movement(events)
        assert len(findings) == 1
        assert "alice" in findings[0]["title"]
        assert findings[0]["severity"] == "HIGH"

    def test_no_finding_single_day(self):
        events = [
            _ct("CreateUser", user="alice", day=1, hour=9),
            _ct("AttachUserPolicy", user="alice", day=1, hour=10),
        ]
        assert hunt_multi_day_lateral_movement(events) == []

    def test_no_finding_two_days(self):
        events = [
            _ct("CreateUser", user="alice", day=1, hour=9),
            _ct("AttachUserPolicy", user="alice", day=2, hour=10),
        ]
        assert hunt_multi_day_lateral_movement(events) == []
