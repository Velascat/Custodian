# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from custodian.cli.runner import run_repo_audit

_SEV_ORDER = {"high": 0, "medium": 1, "low": 2}
_SEV_LABEL = {"high": "HIGH", "medium": "MED ", "low": "LOW ", None: "    "}


def _worst_severity(patterns: dict) -> str | None:
    """Return the highest severity among patterns that have findings."""
    best: str | None = None
    for pat in patterns.values():
        if pat.get("count", 0) > 0:
            sev = pat.get("severity")
            if sev and (best is None or _SEV_ORDER.get(sev, 99) < _SEV_ORDER.get(best, 99)):
                best = sev
    return best


def _severity_counts(patterns: dict) -> dict[str, int]:
    counts: dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for pat in patterns.values():
        if pat.get("count", 0) > 0:
            sev = pat.get("severity", "medium")
            counts[sev] = counts.get(sev, 0) + 1
    return counts


def main():
    """
    custodian-multi --repos /path/a /path/b ...   → audit multiple repos, print table
    custodian-multi --repos-file repos.txt         → read repo list from file (one path per line)
    custodian-multi ... --json                     → emit JSON array instead of table
    custodian-multi ... --fail-on-findings         → exit 1 if any repo has findings
    custodian-multi ... --min-severity high        → pass filter to each sub-audit
    """
    parser = argparse.ArgumentParser(
        description="Run Custodian audit across multiple repos and summarise"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "--repos",
        nargs="+",
        type=Path,
        metavar="PATH",
        help="One or more repository roots to audit",
    )
    group.add_argument(
        "--repos-file",
        type=Path,
        metavar="FILE",
        help="File with one repo path per line (blank lines and # comments ignored)",
    )
    parser.add_argument("--only", metavar="CODES",
                        help="Comma-separated detector IDs to run (e.g. C1,OC7)")
    parser.add_argument("--min-severity", metavar="LEVEL", choices=["high", "medium", "low"],
                        help="Only run detectors at this severity or higher")
    parser.add_argument("--json", action="store_true",
                        help="Emit JSON array, one object per repo")
    parser.add_argument("--fail-on-findings", action="store_true",
                        help="Exit 1 if any repo has findings")
    args = parser.parse_args()

    if args.repos_file:
        text = args.repos_file.read_text(encoding="utf-8")
        repos = [
            Path(line.strip())
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
    else:
        repos = args.repos

    only: set[str] | None = None
    if args.only:
        only = {c.strip() for c in args.only.split(",") if c.strip()}

    results = []
    errors = []
    for repo in repos:
        try:
            result = run_repo_audit(repo, only=only, min_severity=args.min_severity)
            results.append((repo, result, None))
        except Exception as exc:  # noqa: BLE001
            results.append((repo, None, str(exc)))
            errors.append(repo)

    if args.json:
        out = []
        for repo, result, err in results:
            if err:
                out.append({"repo": str(repo), "error": err})
            else:
                data = json.loads(result.to_json())  # type: ignore[union-attr]
                data["repo_path"] = str(repo)
                out.append(data)
        print(json.dumps(out, indent=2))
    else:
        _print_table(results)

    any_findings = any(
        r.total_findings > 0
        for _, r, err in results
        if r is not None and err is None
    )
    if (args.fail_on_findings and any_findings) or errors:
        sys.exit(1)


def _print_table(results: list) -> None:
    col_repo = max((len(r.repo_key or str(p)) for p, r, _ in results if r), default=12)
    col_repo = max(col_repo, 4)

    header = f"{'repo':<{col_repo}} | findings | HIGH | MED  | LOW  | status"
    sep    = f"{'-' * col_repo}-+---------+------+------+------+--------"
    print(header)
    print(sep)

    for repo, result, err in results:
        if err:
            name = str(repo)[:col_repo]
            print(f"{name:<{col_repo}} | {'ERROR':>8} | {'':4} | {'':4} | {'':4} | {err[:30]}")
            continue
        name = (result.repo_key or str(repo))[:col_repo]
        counts = _severity_counts(result.patterns)
        h, m, l = counts["high"], counts["medium"], counts["low"]
        status = "clean" if result.total_findings == 0 else "FAIL"
        print(
            f"{name:<{col_repo}} | {result.total_findings:>8} | {h:>4} | {m:>4} | {l:>4} | {status}"
        )


if __name__ == "__main__":
    main()
