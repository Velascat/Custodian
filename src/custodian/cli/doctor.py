from __future__ import annotations

import argparse
from pathlib import Path
import sys

from custodian.cli.runner import load_config
from custodian.plugins.loader import load_plugins


def main():
    """
    custodian-doctor          → verify .custodian.yaml is well-formed
                               and all declared paths/plugins resolve
    custodian-doctor --strict → exit non-zero on any warning
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    config = load_config(args.repo)
    warnings = []
    for key in ("repo_key", "src_root", "tests_root"):
        if key not in config:
            warnings.append(f"missing key: {key}")
    for root_key in ("src_root", "tests_root"):
        root = args.repo / config.get(root_key, "")
        if not root.exists():
            warnings.append(f"missing path: {root}")
    sys.path.insert(0, str(args.repo))
    try:
        load_plugins(config)
    finally:
        sys.path.remove(str(args.repo))
    if warnings and args.strict:
        raise SystemExit("; ".join(warnings))
    print("OK" if not warnings else "WARN: " + "; ".join(warnings))
