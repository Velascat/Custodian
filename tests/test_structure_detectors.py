# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for S-class (structure) detectors: S1 and S2."""
from __future__ import annotations

from pathlib import Path

import pytest

import ast
import textwrap

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.structure import detect_s1, detect_s2, detect_s3
from custodian.audit_kit.passes.ast_forest import AstForest
from custodian.audit_kit.passes.import_graph import ImportGraph


def _make_context(
    tmp_path: Path,
    config: dict | None = None,
    import_graph: ImportGraph | None = None,
) -> AuditContext:
    graph = AnalysisGraph(import_graph=import_graph)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=graph,
    )


def _make_import_graph(
    imports: dict[str, list[str]],
    module_to_path: dict[str, str] | None = None,
    path_to_module: dict[str, str] | None = None,
) -> ImportGraph:
    g = ImportGraph()
    m2p = module_to_path or {}
    p2m = path_to_module or {}
    for src_rel, targets in imports.items():
        p = Path(src_rel)
        g.imports[p] = set(targets)
        mod = p2m.get(src_rel, src_rel.replace("/", ".").removesuffix(".py"))
        g.path_to_module[p] = mod
    for mod, rel in m2p.items():
        g.module_to_path[mod] = Path(rel)
    return g


# ── S1 tests ─────────────────────────────────────────────────────────────────

class TestS1:
    def test_no_graph_returns_zero(self, tmp_path):
        ctx = _make_context(tmp_path)
        ctx.graph = AnalysisGraph(import_graph=None)
        result = detect_s1(ctx)
        assert result.count == 0

    def test_no_rules_returns_zero(self, tmp_path):
        ig = _make_import_graph({"src/a.py": ["src.b"]})
        ctx = _make_context(tmp_path, config={}, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 0

    def test_clean_imports_no_findings(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/adapters/a.py")] = {"src.domain.model"}
        ig.module_to_path["src.domain.model"] = Path("src/domain/model.py")
        config = {
            "architecture": {
                "layers": [
                    {"name": "adapters", "glob": "src/adapters/**",
                     "may_not_import": ["src/entrypoints/**"]},
                ]
            }
        }
        ctx = _make_context(tmp_path, config=config, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 0

    def test_violation_detected(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/domain/model.py")] = {"src.adapters.db"}
        ig.module_to_path["src.adapters.db"] = Path("src/adapters/db.py")
        config = {
            "architecture": {
                "layers": [
                    {"name": "domain", "glob": "src/domain/**",
                     "may_not_import": ["src/adapters/**"]},
                ]
            }
        }
        ctx = _make_context(tmp_path, config=config, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 1
        assert "domain" in result.samples[0]

    def test_external_import_not_flagged(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/domain/model.py")] = {"requests"}
        # requests not in module_to_path → external
        config = {
            "architecture": {
                "layers": [
                    {"name": "domain", "glob": "src/domain/**",
                     "may_not_import": ["src/adapters/**"]},
                ]
            }
        }
        ctx = _make_context(tmp_path, config=config, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 0

    def test_multiple_violations_capped_at_max_samples(self, tmp_path):
        ig = ImportGraph()
        for i in range(12):
            ig.imports[Path(f"src/domain/m{i}.py")] = {f"src.adapters.db{i}"}
            ig.module_to_path[f"src.adapters.db{i}"] = Path(f"src/adapters/db{i}.py")
        config = {
            "architecture": {
                "layers": [
                    {"name": "domain", "glob": "src/domain/**",
                     "may_not_import": ["src/adapters/**"]},
                ]
            }
        }
        ctx = _make_context(tmp_path, config=config, import_graph=ig)
        result = detect_s1(ctx)
        assert result.count == 12
        assert len(result.samples) == 8  # _MAX_SAMPLES


# ── S2 tests ─────────────────────────────────────────────────────────────────

class TestS2:
    def test_no_graph_returns_zero(self, tmp_path):
        ctx = _make_context(tmp_path)
        ctx.graph = AnalysisGraph(import_graph=None)
        result = detect_s2(ctx)
        assert result.count == 0

    def test_no_mutual_imports_returns_zero(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/a.py")] = {"src.b"}
        ig.imports[Path("src/b.py")] = {"src.c"}
        ig.module_to_path["src.a"] = Path("src/a.py")
        ig.module_to_path["src.b"] = Path("src/b.py")
        ig.module_to_path["src.c"] = Path("src/c.py")
        ig.path_to_module[Path("src/a.py")] = "src.a"
        ig.path_to_module[Path("src/b.py")] = "src.b"
        ctx = _make_context(tmp_path, import_graph=ig)
        result = detect_s2(ctx)
        assert result.count == 0

    def test_mutual_import_detected(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/a.py")] = {"src.b"}
        ig.imports[Path("src/b.py")] = {"src.a"}
        ig.module_to_path["src.a"] = Path("src/a.py")
        ig.module_to_path["src.b"] = Path("src/b.py")
        ig.path_to_module[Path("src/a.py")] = "src.a"
        ig.path_to_module[Path("src/b.py")] = "src.b"
        ctx = _make_context(tmp_path, import_graph=ig)
        result = detect_s2(ctx)
        assert result.count == 1
        assert "↔" in result.samples[0]

    def test_mutual_pair_reported_once(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/a.py")] = {"src.b"}
        ig.imports[Path("src/b.py")] = {"src.a"}
        ig.module_to_path["src.a"] = Path("src/a.py")
        ig.module_to_path["src.b"] = Path("src/b.py")
        ig.path_to_module[Path("src/a.py")] = "src.a"
        ig.path_to_module[Path("src/b.py")] = "src.b"
        ctx = _make_context(tmp_path, import_graph=ig)
        result = detect_s2(ctx)
        assert result.count == 1  # not 2

    def test_three_way_cycle_not_reported_as_mutual(self, tmp_path):
        ig = ImportGraph()
        ig.imports[Path("src/a.py")] = {"src.b"}
        ig.imports[Path("src/b.py")] = {"src.c"}
        ig.imports[Path("src/c.py")] = {"src.a"}
        ig.module_to_path["src.a"] = Path("src/a.py")
        ig.module_to_path["src.b"] = Path("src/b.py")
        ig.module_to_path["src.c"] = Path("src/c.py")
        ig.path_to_module[Path("src/a.py")] = "src.a"
        ig.path_to_module[Path("src/b.py")] = "src.b"
        ig.path_to_module[Path("src/c.py")] = "src.c"
        ctx = _make_context(tmp_path, import_graph=ig)
        result = detect_s2(ctx)
        assert result.count == 0  # three-way cycle, no direct mutual


# ── S3 tests ──────────────────────────────────────────────────────────────────

def _s3_context(tmp_path: Path, src_text: str) -> AuditContext:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / "module.py"
    src = textwrap.dedent(src_text)
    path.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    forest = AstForest()
    forest.trees[path] = tree
    forest.sources[path] = src
    graph = AnalysisGraph(ast_forest=forest)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=graph,
    )


class TestS3:
    def test_import_tests_package_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "from tests.helpers import make_fixture\n")
        assert detect_s3(ctx).count == 1

    def test_import_test_module_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "import test_utils\n")
        assert detect_s3(ctx).count == 1

    def test_import_test_underscore_module_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "from test_helpers import something\n")
        assert detect_s3(ctx).count == 1

    def test_normal_import_not_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "import os\nfrom pathlib import Path\n")
        assert detect_s3(ctx).count == 0

    def test_src_import_not_flagged(self, tmp_path):
        ctx = _s3_context(tmp_path, "from myapp.utils import helper\n")
        assert detect_s3(ctx).count == 0

    def test_no_graph_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "tests",
            config={},
            plugin_modules=[],
            graph=None,
        )
        assert detect_s3(ctx).count == 0
