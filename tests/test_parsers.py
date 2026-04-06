"""Tests for log parsers."""
from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest

from chronos.parsers import parse_ssh_auth, parse_cloudtrail, parse_network


# ---------------------------------------------------------------------------
# SSH / Auth parser
# ---------------------------------------------------------------------------

class TestParseSSHAuth:
    def test_failed_login(self):
        lines = [
            "Apr  3 06:17:22 host sshd[1]: Failed password for alice from 1.2.3.4 port 22 ssh2"
        ]
        events = parse_ssh_auth(lines)
        assert len(events) == 1
        e = events[0]
        assert e["event_type"] == "failed_login"
        assert e["user"] == "alice"
        assert e["src_ip"] == "1.2.3.4"
        assert e["port"] == 22
        assert e["source"] == "ssh"
        assert isinstance(e["timestamp"], datetime)

    def test_successful_login(self):
        lines = [
            "Apr  3 06:17:25 host sshd[1]: Accepted publickey for bob from 10.0.0.5 port 22 ssh2"
        ]
        events = parse_ssh_auth(lines)
        assert len(events) == 1
        e = events[0]
        assert e["event_type"] == "successful_login"
        assert e["user"] == "bob"
        assert e["src_ip"] == "10.0.0.5"

    def test_user_created(self):
        lines = [
            "Apr  3 07:00:00 host useradd[9]: new user: name=attacker, UID=1001, GID=1001"
        ]
        events = parse_ssh_auth(lines)
        assert len(events) == 1
        e = events[0]
        assert e["event_type"] == "user_created"
        assert e["user"] == "attacker"
        assert e["source"] == "auth"

    def test_sudo_command(self):
        lines = [
            "Apr  3 07:05:00 host sudo: alice : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash"
        ]
        events = parse_ssh_auth(lines)
        assert len(events) == 1
        e = events[0]
        assert e["event_type"] == "sudo_command"
        assert e["target_user"] == "root"
        assert "/bin/bash" in e["command"]

    def test_invalid_user(self):
        lines = [
            "Apr  3 06:17:22 host sshd[1]: Failed password for invalid user admin from 5.5.5.5 port 22 ssh2"
        ]
        events = parse_ssh_auth(lines)
        assert events[0]["user"] == "admin"
        assert events[0]["src_ip"] == "5.5.5.5"

    def test_empty_lines_skipped(self):
        lines = ["", "   ", "\n"]
        assert parse_ssh_auth(lines) == []

    def test_multiple_events(self):
        lines = [
            "Apr  3 06:00:00 host sshd[1]: Failed password for alice from 1.1.1.1 port 22 ssh2",
            "Apr  3 06:00:05 host sshd[1]: Failed password for alice from 1.1.1.1 port 22 ssh2",
            "Apr  3 06:00:10 host sshd[1]: Accepted password for alice from 1.1.1.1 port 22 ssh2",
        ]
        events = parse_ssh_auth(lines)
        assert len(events) == 3
        assert events[0]["event_type"] == "failed_login"
        assert events[2]["event_type"] == "successful_login"


# ---------------------------------------------------------------------------
# CloudTrail parser
# ---------------------------------------------------------------------------

class TestParseCloudtrail:
    def _make_record(self, event_name="GetObject", user="alice", src_ip="1.2.3.4",
                     ts="2026-04-03T14:22:00Z"):
        return {
            "eventVersion": "1.08",
            "userIdentity": {"type": "IAMUser", "userName": user,
                             "arn": f"arn:aws:iam::123:user/{user}"},
            "eventTime": ts,
            "eventSource": "s3.amazonaws.com",
            "eventName": event_name,
            "awsRegion": "us-east-1",
            "sourceIPAddress": src_ip,
            "userAgent": "aws-cli/2.0",
            "requestParameters": {"bucketName": "my-bucket"},
            "responseElements": {},
            "errorCode": "",
        }

    def test_json_records_wrapper(self):
        records = [self._make_record(), self._make_record(event_name="ListBuckets")]
        raw = json.dumps({"Records": records})
        events = parse_cloudtrail(raw.splitlines())
        assert len(events) == 2
        assert events[0]["event_type"] == "GetObject"
        assert events[1]["event_type"] == "ListBuckets"

    def test_json_lines(self):
        r1 = json.dumps(self._make_record())
        r2 = json.dumps(self._make_record(event_name="PutBucketPolicy"))
        events = parse_cloudtrail([r1, r2])
        assert len(events) == 2

    def test_timestamp_parsed(self):
        rec = self._make_record(ts="2026-04-03T14:22:00Z")
        events = parse_cloudtrail([json.dumps(rec)])
        assert events[0]["timestamp"] == datetime(2026, 4, 3, 14, 22, 0, tzinfo=timezone.utc)

    def test_src_ip_extracted(self):
        events = parse_cloudtrail([json.dumps(self._make_record(src_ip="99.99.99.99"))])
        assert events[0]["src_ip"] == "99.99.99.99"

    def test_user_extracted(self):
        events = parse_cloudtrail([json.dumps(self._make_record(user="bob"))])
        assert events[0]["user"] == "bob"

    def test_invalid_json_skipped(self):
        events = parse_cloudtrail(["not json at all", "{}"])
        # {} is valid JSON but has no eventTime so it will be skipped
        assert events == []

    def test_empty_input(self):
        assert parse_cloudtrail([]) == []


# ---------------------------------------------------------------------------
# Network parser
# ---------------------------------------------------------------------------

class TestParseNetwork:
    def test_combined_log(self):
        line = '1.2.3.4 - - [03/Apr/2026:06:17:22 +0000] "GET /admin HTTP/1.1" 403 512'
        events = parse_network([line])
        assert len(events) == 1
        e = events[0]
        assert e["event_type"] == "http_request"
        assert e["src_ip"] == "1.2.3.4"
        assert e["method"] == "GET"
        assert e["path"] == "/admin"
        assert e["status"] == 403
        assert e["bytes"] == 512

    def test_csv_flow(self):
        line = "2026-04-03T06:17:22Z,10.0.0.1,10.0.0.2,12345,443,TCP,4096,SYN"
        events = parse_network([line])
        assert len(events) == 1
        e = events[0]
        assert e["event_type"] == "flow"
        assert e["src_ip"] == "10.0.0.1"
        assert e["dst_port"] == 443
        assert e["bytes"] == 4096

    def test_comment_line_skipped(self):
        assert parse_network(["# This is a comment"]) == []

    def test_empty_input(self):
        assert parse_network([]) == []
