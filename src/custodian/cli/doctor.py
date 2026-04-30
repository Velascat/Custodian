# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from custodian.audit_kit.code_health import build_code_health_detectors
from custodian.cli import colors
from custodian.cli.runner import load_config
from custodian.plugins.loader import load_detectors, load_plugins

_KNOWN_TOP_LEVEL_KEYS = frozenset({
    "repo_key", "src_root", "tests_root", "plugins", "detectors", "audit",
})
_KNOWN_AUDIT_KEYS = frozenset({
    "exclude_paths", "stale_handlers", "common_words",
})


def _check_config(config: dict, repo: Path, warnings: list[str]) -> list:
    """Run all static config checks; return extra detectors (or [])."""
    # Required top-level keys
    for key in ("repo_key", "src_root", "tests_root"):
        if key not in config:
            warnings.append(f"missing required key: {key!r}")

    # repo_key format
    repo_key = config.get("repo_key", "")
    if repo_key and (" " in str(repo_key) or "/" in str(repo_key)):
        warnings.append(f"repo_key {repo_key!r} should not contain spaces or slashes")

    # Unknown top-level keys (typo guard)
    for key in config:
        if key not in _KNOWN_TOP_LEVEL_KEYS:
            warnings.append(f"unknown top-level key {key!r} (typo?)")

    # Directory existence
    for root_key in ("src_root", "tests_root"):
        root = repo / config.get(root_key, "")
        if not root.exists():
            warnings.append(f"missing path: {root} ({root_key}={config.get(root_key)!r})")

    # audit sub-section
    audit_cfg = config.get("audit") or {}
    if not isinstance(audit_cfg, dict):
        warnings.append("'audit' must be a mapping, not a scalar")
        audit_cfg = {}

    for key in audit_cfg:
        if key not in _KNOWN_AUDIT_KEYS:
            warnings.append(f"unknown audit key {key!r} (typo?)")

    # exclude_paths must be a mapping of lists
    exclude_paths = audit_cfg.get("exclude_paths") or {}
    if not isinstance(exclude_paths, dict):
        warnings.append("audit.exclude_paths must be a mapping")
    else:
        for det_id, val in exclude_paths.items():
            if not isinstance(val, list):
                warnings.append(
                    f"audit.exclude_paths.{det_id} must be a list, got {type(val).__name__}"
                )

    # stale_handlers must be a list
    stale = audit_cfg.get("stale_handlers")
    if stale is not None and not isinstance(stale, list):
        warnings.append(f"audit.stale_handlers must be a list, got {type(stale).__name__}")

    return []


def main():
    """
    custodian-doctor          → verify .custodian.yaml is well-formed
                               and all declared paths/plugins/detectors resolve
    custodian-doctor --strict → exit non-zero on any warning
    """
    parser = argparse.ArgumentParser(description="Verify a Custodian consumer setup")
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--strict", action="store_true")
    parser.add_argument("--no-color", action="store_true")
    args = parser.parse_args()

    import os
    if args.no_color:
        os.environ["NO_COLOR"] = "1"

    config = load_config(args.repo)
    warnings: list[str] = []

    _check_config(config, args.repo, warnings)

    sys.path.insert(0, str(args.repo))
    try:
        try:
            load_plugins(config)
        except Exception as exc:
            warnings.append(f"plugins error: {exc}")
        try:
            extra = load_detectors(config)
        except Exception as exc:
            warnings.append(f"detectors error: {exc}")
            extra = []
    finally:
        sys.path.remove(str(args.repo))

    known_ids = {d.id for d in build_code_health_detectors() + extra}
    exclude_paths = (config.get("audit") or {}).get("exclude_paths") or {}
    if isinstance(exclude_paths, dict):
        for det_id in exclude_paths:
            if det_id not in known_ids:
                warnings.append(f"exclude_paths references unknown detector: {det_id!r}")

    if warnings:
        for w in warnings:
            print(colors.yellow("WARN") + f": {w}")
        if args.strict:
            sys.exit(1)
    else:
        print(colors.green("OK"))


if __name__ == "__main__":
    main()
