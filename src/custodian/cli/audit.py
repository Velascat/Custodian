# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from custodian.cli.runner import run_repo_audit

_SEVERITY_LABELS = {"high": "HIGH", "medium": "MED ", "low": "LOW "}


def _human_summary(result) -> str:
    lines = [
        f"Custodian audit — repo: {result.repo_key or '(unset)'}",
        f"  patterns: {len(result.patterns)}",
        f"  findings: {result.total_findings}",
    ]
    noisy = {
        code: pat for code, pat in result.patterns.items()
        if pat.get("count", 0) > 0
    }
    if noisy:
        lines.append("")
        for code, pat in noisy.items():
            sev = _SEVERITY_LABELS.get(pat.get("severity", "medium"), "MED ")
            lines.append(
                f"  [{sev}] [{code}] {pat['description']} — {pat['count']} finding(s)"
            )
            for sample in pat.get("samples", [])[:3]:
                lines.append(f"        {sample}")
    return "\n".join(lines)


def main():
    """
    custodian-audit                           → cwd, default config (human + JSON)
    custodian-audit --repo /path/to/repo      → that repo
    custodian-audit --json                    → JSON only (machine-readable)
    custodian-audit --only C1,OC7            → run only those detector IDs
    custodian-audit --min-severity high       → run only HIGH-severity detectors
    custodian-audit --fail-on-findings        → exit 1 if any findings
    """
    parser = argparse.ArgumentParser(description="Run a Custodian audit on a repo")
    parser.add_argument("--repo", type=Path, default=Path.cwd(),
                        help="Repository root containing .custodian.yaml (default: cwd)")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON only, no human summary header")
    parser.add_argument("--only", metavar="CODES",
                        help="Comma-separated detector IDs to run (e.g. C1,OC7). "
                             "All others are skipped.")
    parser.add_argument("--min-severity", metavar="LEVEL", choices=["high", "medium", "low"],
                        help="Only run detectors at this severity or higher "
                             "(high > medium > low). Default: low (run all).")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit with code 1 if any findings are present")
    args = parser.parse_args()

    only: set[str] | None = None
    if args.only:
        only = {c.strip() for c in args.only.split(",") if c.strip()}

    result = run_repo_audit(args.repo, only=only, min_severity=args.min_severity)

    if args.json:
        print(result.to_json())
    else:
        print(_human_summary(result))
        print(result.to_json())

    if args.fail_on_findings and result.total_findings > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
