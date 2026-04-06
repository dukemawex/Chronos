#!/usr/bin/env python3
"""
chronos_cli – Command-line interface for the Chronos Threat Hunting Engine.

Usage examples
--------------
# Auto-detect log types, produce a Threat Intelligence Report:
  python chronos_cli.py auth.log cloudtrail.json --report threat-intel

# Specify log types explicitly:
  python chronos_cli.py auth.log --type ssh cloudtrail.json --type cloudtrail

# Write the report to a file instead of stdout:
  python chronos_cli.py logs/*.log --output report.md

# Security Brief mode (original Tier 3 SOC format):
  python chronos_cli.py auth.log cloudtrail.json --report security-brief
"""

from __future__ import annotations

import argparse
import sys
from typing import Dict, Optional

from chronos.analyzer import analyse
from chronos.report import render_security_brief, render_threat_intel_report


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="chronos",
        description="Chronos – Autonomous Threat Hunting Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument(
        "log_files",
        nargs="+",
        metavar="LOG_FILE",
        help="One or more log files to analyse (SSH/Auth, CloudTrail, Network).",
    )
    p.add_argument(
        "--type",
        action="append",
        dest="types",
        metavar="TYPE",
        choices=["ssh", "auth", "cloudtrail", "network"],
        help=(
            "Override the auto-detected log type for the corresponding file "
            "(specify once per file in the same order as LOG_FILE arguments). "
            "Choices: ssh, auth, cloudtrail, network."
        ),
    )
    p.add_argument(
        "--report",
        default="threat-intel",
        choices=["threat-intel", "security-brief"],
        help=(
            "Report format to generate. "
            "'threat-intel' (default) – L3 IR Specialist Threat Intelligence Report "
            "with Confidence Score and Remediation Plan. "
            "'security-brief' – Tier 3 SOC Security Brief."
        ),
    )
    p.add_argument(
        "--output",
        "-o",
        default=None,
        metavar="FILE",
        help="Write the report to FILE instead of stdout.",
    )
    p.add_argument(
        "--version",
        action="version",
        version="Chronos 1.0.0",
    )
    return p


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    # Map files → explicit types (if provided)
    log_types: Optional[Dict[str, str]] = None
    if args.types:
        if len(args.types) != len(args.log_files):
            parser.error(
                f"Number of --type flags ({len(args.types)}) must match "
                f"number of log files ({len(args.log_files)})."
            )
        log_types = dict(zip(args.log_files, args.types))

    # Run analysis
    try:
        result = analyse(args.log_files, log_types=log_types)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1

    # Render report
    if args.report == "threat-intel":
        report = render_threat_intel_report(result)
    else:
        report = render_security_brief(result)

    # Output
    if args.output:
        with open(args.output, "w") as fh:
            fh.write(report)
        print(f"Report written to {args.output}", file=sys.stderr)
    else:
        print(report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
