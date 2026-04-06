"""Tests for base threat hunters."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from chronos.hunters import (
    hunt_brute_force,
    hunt_periodic_activity,
    hunt_login_after_failures,
    hunt_privilege_escalation,
    hunt_s3_policy_changes,
    hunt_impossible_travel,
)


def _ts(day=1, hour=0, minute=0, second=0):
    return datetime(2026, 4, day, hour, minute, second, tzinfo=timezone.utc)


def _failed(ip="1.2.3.4", user="alice", day=1, hour=0, minute=0):
    return {
        "source": "ssh",
        "event_type": "failed_login",
        "user": user,
        "src_ip": ip,
        "timestamp": _ts(day, hour, minute),
        "raw": f"Failed login {user} from {ip}",
    }


def _success(ip="1.2.3.4", user="alice", day=1, hour=1, minute=0):
    return {
        "source": "ssh",
        "event_type": "successful_login",
        "user": user,
        "src_ip": ip,
        "timestamp": _ts(day, hour, minute),
        "raw": f"Successful login {user} from {ip}",
    }


def _ct(event_type, user="alice", ip="1.2.3.4", day=1, hour=0, minute=30, params=None):
    import json
    rec = {
        "eventName": event_type,
        "userIdentity": {"userName": user, "arn": f"arn:aws:iam::123:user/{user}"},
        "sourceIPAddress": ip,
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


# ---------------------------------------------------------------------------
# Brute Force
# ---------------------------------------------------------------------------

class TestHuntBruteForce:
    def test_detects_brute_force(self):
        events = [_failed(minute=i) for i in range(6)]
        findings = hunt_brute_force(events)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"
        assert "1.2.3.4" in findings[0]["title"]

    def test_no_finding_below_threshold(self):
        events = [_failed(minute=i) for i in range(4)]
        assert hunt_brute_force(events) == []

    def test_credential_stuffing_multiple_users(self):
        events = [_failed(user=f"user{i}", minute=i) for i in range(6)]
        findings = hunt_brute_force(events)
        assert len(findings) == 1
        assert "Credential Stuffing" in findings[0]["title"]

    def test_different_ips_separate_findings(self):
        events = (
            [_failed(ip="1.1.1.1", minute=i) for i in range(6)]
            + [_failed(ip="2.2.2.2", minute=i) for i in range(6)]
        )
        findings = hunt_brute_force(events)
        ips = {f["title"] for f in findings}
        assert len(findings) == 2


# ---------------------------------------------------------------------------
# Periodic Activity
# ---------------------------------------------------------------------------

class TestHuntPeriodicActivity:
    def test_detects_periodic(self):
        # Every 2 hours (7200s) – above the 1800s minimum
        events = [_failed(hour=h) for h in [0, 2, 4, 6, 8]]
        findings = hunt_periodic_activity(events)
        assert len(findings) == 1
        assert "Periodic" in findings[0]["title"]

    def test_no_finding_for_random_intervals(self):
        events = [
            _failed(hour=0, minute=0),
            _failed(hour=0, minute=5),
            _failed(hour=2, minute=0),
            _failed(hour=5, minute=30),
        ]
        assert hunt_periodic_activity(events) == []

    def test_minimum_events_required(self):
        # Only 3 events – below the 4-event minimum
        events = [_failed(hour=h) for h in [0, 2, 4]]
        assert hunt_periodic_activity(events) == []


# ---------------------------------------------------------------------------
# Login After Failures
# ---------------------------------------------------------------------------

class TestHuntLoginAfterFailures:
    def test_detects_compromise(self):
        events = [_failed(minute=i) for i in range(5)] + [_success()]
        findings = hunt_login_after_failures(events)
        assert len(findings) == 1
        assert findings[0]["severity"] == "CRITICAL"

    def test_no_finding_without_prior_failures(self):
        events = [_success()]
        assert hunt_login_after_failures(events) == []

    def test_no_finding_below_failure_threshold(self):
        events = [_failed(minute=i) for i in range(2)] + [_success()]
        assert hunt_login_after_failures(events) == []


# ---------------------------------------------------------------------------
# Privilege Escalation
# ---------------------------------------------------------------------------

class TestHuntPrivilegeEscalation:
    def test_detects_priv_esc(self):
        creation = {
            "source": "auth",
            "event_type": "user_created",
            "user": "ghostuser",
            "timestamp": _ts(1, 0, 0),
            "raw": "new user: name=ghostuser",
        }
        iam = _ct("AttachUserPolicy", user="alice", day=1, hour=0, minute=5,
                  params={"userName": "ghostuser"})
        findings = hunt_privilege_escalation([creation, iam])
        assert len(findings) == 1
        assert "ghostuser" in findings[0]["title"]
        assert findings[0]["severity"] == "CRITICAL"

    def test_no_finding_without_user_creation(self):
        iam = _ct("AttachUserPolicy")
        assert hunt_privilege_escalation([iam]) == []


# ---------------------------------------------------------------------------
# S3 Policy Changes
# ---------------------------------------------------------------------------

class TestHuntS3PolicyChanges:
    def test_detects_put_bucket_policy(self):
        event = _ct("PutBucketPolicy", params={"bucketName": "sensitive-bucket"})
        findings = hunt_s3_policy_changes([event])
        assert len(findings) == 1
        assert "sensitive-bucket" in findings[0]["title"]
        assert findings[0]["severity"] == "HIGH"

    def test_detects_delete_bucket_policy(self):
        event = _ct("DeleteBucketPolicy", params={"bucketName": "audit-logs"})
        findings = hunt_s3_policy_changes([event])
        assert len(findings) == 1

    def test_no_finding_for_benign_s3_ops(self):
        event = _ct("GetObject")
        assert hunt_s3_policy_changes([event]) == []


# ---------------------------------------------------------------------------
# Impossible Travel
# ---------------------------------------------------------------------------

class TestHuntImpossibleTravel:
    def test_detects_impossible_travel(self):
        events = [
            _success(ip="1.1.1.1", hour=10, minute=0),
            _success(ip="2.2.2.2", hour=10, minute=5),  # 5 min later, different IP
        ]
        findings = hunt_impossible_travel(events)
        assert len(findings) == 1
        assert findings[0]["severity"] == "HIGH"

    def test_no_finding_same_ip(self):
        events = [
            _success(ip="1.1.1.1", hour=10, minute=0),
            _success(ip="1.1.1.1", hour=10, minute=5),
        ]
        assert hunt_impossible_travel(events) == []

    def test_no_finding_outside_window(self):
        events = [
            _success(ip="1.1.1.1", day=1, hour=0),
            _success(ip="2.2.2.2", day=1, hour=8),  # 8h gap — well beyond 15min window
        ]
        assert hunt_impossible_travel(events) == []
