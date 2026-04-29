# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Velascat
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from custodian.audit_kit.code_health import build_code_health_detectors
from custodian.audit_kit.detector import AuditContext, run_audit
from custodian.audit_kit.result import AuditResult
from custodian.plugins.loader import load_detectors, load_plugins


def load_config(repo_root: Path) -> dict:
    config_path = repo_root / ".custodian.yaml"
    with config_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def run_repo_audit(repo_root: Path) -> AuditResult:
    """
    Drive one repo through the audit pipeline. Returns AuditResult so callers
    can decide on JSON, human, or aggregator output formatting.
    """
    config = load_config(repo_root)
    sys.path.insert(0, str(repo_root))
    try:
        plugins   = load_plugins(config)
        extra     = load_detectors(config)
    finally:
        sys.path.remove(str(repo_root))

    src_root   = repo_root / config.get("src_root", "src")
    tests_root = repo_root / config.get("tests_root", "tests")
    detectors  = build_code_health_detectors() + extra

    context = AuditContext(
        repo_root=repo_root,
        src_root=src_root,
        tests_root=tests_root,
        config=config,
        plugin_modules=plugins,
    )
    return run_audit(context=context, detectors=detectors)
