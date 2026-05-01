# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for T-class detectors: T2 (test functions with no assert)."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.test_shape import detect_t2
from custodian.audit_kit.passes.ast_forest import AstForest


def _write_test_file(src: str, tmp_path: Path, name: str = "test_example.py") -> None:
    tests_root = tmp_path / "tests"
    tests_root.mkdir(parents=True, exist_ok=True)
    (tests_root / name).write_text(textwrap.dedent(src), encoding="utf-8")


def _ctx(tmp_path: Path) -> AuditContext:
    (tmp_path / "src").mkdir(parents=True, exist_ok=True)
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=AstForest()),
    )


class TestT2:
    def test_no_tests_root_returns_zero(self, tmp_path):
        ctx = _ctx(tmp_path)
        ctx = AuditContext(
            repo_root=tmp_path,
            src_root=tmp_path / "src",
            tests_root=tmp_path / "nonexistent_tests",
            config={},
            plugin_modules=[],
            graph=AnalysisGraph(ast_forest=AstForest()),
        )
        assert detect_t2(ctx).count == 0

    def test_test_with_assert_not_flagged(self, tmp_path):
        _write_test_file("""
            def test_something():
                assert 1 + 1 == 2
        """, tmp_path)
        assert detect_t2(_ctx(tmp_path)).count == 0

    def test_test_with_no_assert_flagged(self, tmp_path):
        _write_test_file("""
            def test_nothing():
                x = 1 + 1
        """, tmp_path)
        assert detect_t2(_ctx(tmp_path)).count == 1

    def test_non_test_function_not_flagged(self, tmp_path):
        _write_test_file("""
            def helper():
                x = 1
        """, tmp_path)
        assert detect_t2(_ctx(tmp_path)).count == 0

    def test_test_with_assert_in_nested_if_not_flagged(self, tmp_path):
        _write_test_file("""
            def test_conditional():
                x = compute()
                if x:
                    assert x > 0
        """, tmp_path)
        assert detect_t2(_ctx(tmp_path)).count == 0

    def test_empty_test_body_flagged(self, tmp_path):
        _write_test_file("""
            def test_empty():
                pass
        """, tmp_path)
        assert detect_t2(_ctx(tmp_path)).count == 1

    def test_multiple_tests_counts_correctly(self, tmp_path):
        _write_test_file("""
            def test_one():
                assert True

            def test_two():
                pass

            def test_three():
                x = 1
        """, tmp_path)
        assert detect_t2(_ctx(tmp_path)).count == 2

    def test_async_test_with_no_assert_flagged(self, tmp_path):
        _write_test_file("""
            async def test_async_stub():
                pass
        """, tmp_path)
        assert detect_t2(_ctx(tmp_path)).count == 1

    def test_sample_text_contains_function_name(self, tmp_path):
        _write_test_file("""
            def test_forgotten():
                x = 1
        """, tmp_path)
        result = detect_t2(_ctx(tmp_path))
        assert result.count == 1
        assert "test_forgotten" in result.samples[0]
