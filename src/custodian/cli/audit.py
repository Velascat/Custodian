# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import argparse
from pathlib import Path

from custodian.cli.runner import run_repo_audit


def _human_summary(result) -> str:
    by_status: dict[str, int] = {}
    for pat in result.patterns.values():
        by_status[pat["status"]] = by_status.get(pat["status"], 0) + pat["count"]
    parts = ", ".join(f"{count} {status}" for status, count in sorted(by_status.items()))
    return (
        f"Custodian audit — repo: {result.repo_key or '(unset)'}\n"
        f"  patterns: {len(result.patterns)}\n"
        f"  findings: {result.total_findings}"
        + (f"  ({parts})" if parts else "")
    )


def main():
    """
    custodian-audit                       → cwd, default config (human + JSON)
    custodian-audit --repo /path/to/repo  → that repo
    custodian-audit --json                 → emit JSON only (machine-readable)
    """
    parser = argparse.ArgumentParser(description="Run a Custodian audit on a repo")
    parser.add_argument("--repo", type=Path, default=Path.cwd(),
                        help="Repository root containing .custodian.yaml (default: cwd)")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON only, no human summary header")
    args = parser.parse_args()

    result = run_repo_audit(args.repo)

    if args.json:
        print(result.to_json())
    else:
        print(_human_summary(result))
        print(result.to_json())
