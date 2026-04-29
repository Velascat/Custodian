# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Velascat
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from custodian.cli.runner import load_config
from custodian.plugins.loader import load_detectors, load_plugins


def main():
    """
    custodian-doctor          → verify .custodian.yaml is well-formed
                               and all declared paths/plugins/detectors resolve
    custodian-doctor --strict → exit non-zero on any warning
    """
    parser = argparse.ArgumentParser(description="Verify a Custodian consumer setup")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    config = load_config(args.repo)
    warnings: list[str] = []

    for key in ("repo_key", "src_root", "tests_root"):
        if key not in config:
            warnings.append(f"missing key: {key}")

    for root_key in ("src_root", "tests_root"):
        root = args.repo / config.get(root_key, "")
        if not root.exists():
            warnings.append(f"missing path: {root}")

    sys.path.insert(0, str(args.repo))
    try:
        try:
            load_plugins(config)
        except Exception as exc:
            warnings.append(f"plugins error: {exc}")
        try:
            load_detectors(config)
        except Exception as exc:
            warnings.append(f"detectors error: {exc}")
    finally:
        sys.path.remove(str(args.repo))

    if warnings:
        msg = "; ".join(warnings)
        if args.strict:
            raise SystemExit(f"WARN: {msg}")
        print(f"WARN: {msg}")
    else:
        print("OK")
