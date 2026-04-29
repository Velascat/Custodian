from __future__ import annotations

import argparse
from pathlib import Path

from custodian.cli.runner import run_repo_audit


def main():
    """
    custodian-audit                       → cwd, default config
    custodian-audit --repo /path/to/repo  → that repo
    custodian-audit --all                  → walk configured repo list
    custodian-audit --json                  → emit JSON only (default human + JSON)
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--all", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    # v0.1 supports single repo only; --all is accepted for forward compatibility.
    print(run_repo_audit(args.repo))
