# Chronos

**Autonomous Threat Hunting & Incident Response Engine**

Chronos ingests SSH, Auth, CloudTrail, and Network logs, performs multi-day
temporal analysis and cross-log correlation, and emits either a **Security
Brief** (Tier 3 SOC) or a **Threat Intelligence Report** (L3 IR Specialist)
as Markdown.

---

## Features

| Capability | Details |
|---|---|
| **Log Parsers** | SSH/Auth (syslog), AWS CloudTrail (JSON / JSON-Lines), Network (Combined Log, CSV Flow) |
| **Base Hunters** | Brute-force, Credential stuffing, Periodic low-and-slow attacks, Successful login after failures, Privilege escalation (user creation → IAM), S3 policy changes, Impossible travel |
| **APT Hunters** | New-IP login → IAM policy change, New-IP login → S3 enumeration / exfiltration, Silent hacker (developer CLI impersonation), Multi-day lateral movement |
| **Confidence Scoring** | Per-finding score (0–100) + overall Threat Score with tier label |
| **Reports** | Security Brief · Threat Intelligence Report (TLP:AMBER, Remediation Plan) |

---

## Quick Start

```bash
# Install (no third-party dependencies required)
pip install pytest   # for running tests only

# Run on sample logs (Threat Intelligence Report – default)
python chronos_cli.py sample_logs/auth.log sample_logs/cloudtrail.json

# Write report to a file
python chronos_cli.py sample_logs/auth.log sample_logs/cloudtrail.json \
    --output report.md

# Security Brief format
python chronos_cli.py sample_logs/auth.log sample_logs/cloudtrail.json \
    --report security-brief

# Explicit log-type override
python chronos_cli.py auth.log cloudtrail.json \
    --type ssh --type cloudtrail
```

---

## Report Formats

### Threat Intelligence Report (`--report threat-intel`, default)

Designed for L3 Incident Responders. Sections:

1. **Threat Score Dashboard** — Overall Confidence Score (0–100) and Threat Tier
2. **APT Analysis** — MITRE ATT&CK stage mapping, per-finding indicator tables,
   attack timeline, and raw evidence blocks
3. **Supporting Findings** — Base-tier detections (brute-force, S3 changes, etc.)
4. **Unified Attack Timeline** — All events across all findings, sorted chronologically
5. **Remediation Plan** — Prioritised action checklist (Immediate / Urgent / Short-term / Long-term)

### Security Brief (`--report security-brief`)

Designed for Tier 3 SOC Analysts. Sections:

1. **Executive Summary**
2. **Timeline of Activity**
3. **Evidence Blocks**
4. **Recommended Mitigations**

---

## APT Detection: The "GHOST" Scenario

The `sample_logs/` directory contains a synthetic 7-day dataset demonstrating
a full APT kill-chain:

| Day | Activity | Hunter |
|---|---|---|
| 1–3 | Slow-scan failed logins every 6h from `198.51.100.42` | Periodic activity |
| 4 | Successful login from new IP → `CreateUser` + `AttachUserPolicy` | New-IP→IAM, Priv-esc |
| 5 | Same developer CLI UA, new IP `203.0.113.9` → `CreateAccessKey` + `PutBucketPolicy` | Silent Hacker |
| 6 | `AssumeRole` → `AttachRolePolicy` → `CreateLoginProfile` (3rd day) | Multi-day lateral movement |
| 7 | Bulk `GetObject` from `prod-data` and `audit-logs` | New-IP→S3 exfiltration |

---

## Architecture

```
chronos/
├── __init__.py          # package metadata
├── parsers/
│   └── __init__.py      # SSH/Auth, CloudTrail, Network parsers
├── hunters/
│   ├── __init__.py      # base threat hunters
│   └── apt.py           # APT hunters (multi-day, silent hacker, new-IP)
├── analyzer.py          # orchestration pipeline
├── scoring.py           # confidence scoring & threat tier
└── report.py            # Markdown report generators

chronos_cli.py           # CLI entry point
sample_logs/             # synthetic 7-day log dataset
tests/                   # pytest test suite (80 tests)
```

---

## Running Tests

```bash
python -m pytest tests/ -v
```

---

## Threat Score Tiers

| Score | Tier |
|---|---|
| 90–100 | 🔴 CONFIRMED COMPROMISE |
| 75–89  | 🟠 HIGHLY LIKELY THREAT |
| 55–74  | 🟡 PROBABLE THREAT |
| 35–54  | 🟡 SUSPICIOUS ACTIVITY |
| 0–34   | ⚪ INFORMATIONAL |
