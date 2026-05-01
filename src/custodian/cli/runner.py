# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import sys
from pathlib import Path

import yaml

from custodian.audit_kit.code_health import build_code_health_detectors
from custodian.audit_kit.detector import AnalysisGraph, AuditContext, run_audit
from custodian.audit_kit.detectors.dead_code import build_dead_code_detectors
from custodian.audit_kit.detectors.structure import build_structure_detectors
from custodian.audit_kit.detectors.stubs import build_stub_detectors
from custodian.audit_kit.detectors.test_shape import build_test_shape_detectors
from custodian.audit_kit.result import AuditResult
from custodian.plugins.loader import load_detectors, load_plugins


def load_config(repo_root: Path) -> dict:
    config_path = repo_root / ".custodian.yaml"
    with config_path.open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle) or {}


def run_repo_audit(
    repo_root: Path,
    *,
    only: set[str] | None = None,
    min_severity: str | None = None,
) -> AuditResult:
    """Drive one repo through the audit pipeline.

    Args:
        repo_root:    Repository root containing ``.custodian.yaml``.
        only:         Optional set of detector IDs to run (e.g. ``{"C1", "OC7"}``).
                      All other detectors are skipped.  ``None`` runs everything.
        min_severity: If set, skip detectors whose severity is below this level.
                      Accepted values: ``"high"``, ``"medium"``, ``"low"``.
                      ``"high"`` runs only HIGH detectors; ``"medium"`` runs HIGH
                      and MEDIUM; ``"low"`` (the default) runs all.

    Returns AuditResult so callers can decide on JSON, human, or aggregator
    output formatting.
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
    detectors  = (build_code_health_detectors()
                  + build_structure_detectors()
                  + build_stub_detectors()
                  + build_dead_code_detectors()
                  + build_test_shape_detectors()
                  + extra)

    if only:
        detectors = [d for d in detectors if d.id in only]

    context = AuditContext(
        repo_root=repo_root,
        src_root=src_root,
        tests_root=tests_root,
        config=config,
        plugin_modules=plugins,
        graph=_build_analysis_graph(context=None, detectors=detectors,
                                    src_root=src_root, repo_root=repo_root),
    )
    return run_audit(context=context, detectors=detectors, min_severity=min_severity)


def _build_analysis_graph(
    context,
    detectors,
    src_root: Path,
    repo_root: Path,
) -> AnalysisGraph:
    needed: set[str] = set()
    for d in detectors:
        needed |= d.needs
    if not needed:
        return AnalysisGraph()

    graph = AnalysisGraph()

    if "import_graph" in needed:
        from custodian.audit_kit.passes.import_graph import build_import_graph
        graph.import_graph = build_import_graph(src_root, repo_root)

    if "ast_forest" in needed:
        from custodian.audit_kit.passes.ast_forest import build_ast_forest
        graph.ast_forest = build_ast_forest(src_root)

    return graph
