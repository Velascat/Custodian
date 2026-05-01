# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for X-class detectors: X1 (cyclomatic complexity), X2 (too many params)."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.complexity import detect_x1, detect_x2
from custodian.audit_kit.passes.ast_forest import AstForest


def _forest(src: str, tmp_path: Path, name: str = "module.py") -> AstForest:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / name
    src = textwrap.dedent(src)
    path.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    forest = AstForest()
    forest.trees[path] = tree
    forest.sources[path] = src
    return forest


def _ctx(tmp_path: Path, forest: AstForest, config: dict | None = None) -> AuditContext:
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=forest),
    )


class TestX1:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = _ctx(tmp_path, AstForest())
        ctx.graph = AnalysisGraph(ast_forest=None)
        assert detect_x1(ctx).count == 0

    def test_simple_function_not_flagged(self, tmp_path):
        f = _forest("""
            def foo(x):
                return x + 1
        """, tmp_path)
        assert detect_x1(_ctx(tmp_path, f)).count == 0

    def test_complex_function_flagged(self, tmp_path):
        # Build a function with complexity > 10
        branches = "\n".join(f"    if x == {i}:\n        return {i}" for i in range(11))
        src = f"def complex(x):\n{branches}\n    return -1\n"
        f = _forest(src, tmp_path)
        assert detect_x1(_ctx(tmp_path, f)).count == 1

    def test_custom_threshold_respected(self, tmp_path):
        # 3 branches → complexity 4; threshold 3 should flag it
        f = _forest("""
            def foo(x):
                if x > 0:
                    if x > 10:
                        if x > 100:
                            return 3
                        return 2
                    return 1
                return 0
        """, tmp_path)
        ctx = _ctx(tmp_path, f, config={"audit": {"x1_threshold": 3}})
        assert detect_x1(ctx).count == 1

    def test_boolean_operators_add_complexity(self, tmp_path):
        # `a and b and c` adds 2 to complexity
        f = _forest("""
            def foo(a, b, c, d, e, f, g, h, i, j):
                if a and b and c and d and e and f and g and h and i and j:
                    return True
                return False
        """, tmp_path)
        assert detect_x1(_ctx(tmp_path, f)).count == 1

    def test_sample_contains_function_name_and_score(self, tmp_path):
        branches = "\n".join(f"    if x == {i}:\n        return {i}" for i in range(11))
        src = f"def overloaded(x):\n{branches}\n    return -1\n"
        f = _forest(src, tmp_path)
        result = detect_x1(_ctx(tmp_path, f))
        assert result.count == 1
        assert "overloaded" in result.samples[0]
        assert "complexity" in result.samples[0]


class TestX2:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = _ctx(tmp_path, AstForest())
        ctx.graph = AnalysisGraph(ast_forest=None)
        assert detect_x2(ctx).count == 0

    def test_few_params_not_flagged(self, tmp_path):
        f = _forest("def foo(a, b, c): pass", tmp_path)
        assert detect_x2(_ctx(tmp_path, f)).count == 0

    def test_many_params_flagged(self, tmp_path):
        f = _forest("def foo(a, b, c, d, e, f): pass", tmp_path)
        assert detect_x2(_ctx(tmp_path, f)).count == 1

    def test_self_not_counted(self, tmp_path):
        # self + 5 params = 5 real params, not flagged at default threshold of 5
        f = _forest("""
            class Foo:
                def bar(self, a, b, c, d, e): pass
        """, tmp_path)
        assert detect_x2(_ctx(tmp_path, f)).count == 0

    def test_custom_threshold(self, tmp_path):
        f = _forest("def foo(a, b, c): pass", tmp_path)
        ctx = _ctx(tmp_path, f, config={"audit": {"x2_threshold": 2}})
        assert detect_x2(ctx).count == 1

    def test_sample_contains_function_name_and_count(self, tmp_path):
        f = _forest("def many_args(a, b, c, d, e, f, g): pass", tmp_path)
        result = detect_x2(_ctx(tmp_path, f))
        assert result.count == 1
        assert "many_args" in result.samples[0]
        assert "params" in result.samples[0]
