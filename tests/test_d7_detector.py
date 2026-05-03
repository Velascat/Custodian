# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for D7 detector — unused function/method parameters."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path


from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.dead_code import detect_d7
from custodian.audit_kit.passes.ast_forest import AstForest


def _make_ctx(src: str, tmp_path: Path) -> AuditContext:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    path = src_root / "mod.py"
    src = textwrap.dedent(src)
    path.write_text(src, encoding="utf-8")
    tree = ast.parse(src)
    forest = AstForest()
    forest.trees[path] = tree
    forest.sources[path] = src
    return AuditContext(
        repo_root=tmp_path, src_root=src_root, tests_root=tmp_path / "tests",
        config={}, plugin_modules=[], graph=AnalysisGraph(ast_forest=forest),
    )


class TestD7:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = AuditContext(repo_root=tmp_path, src_root=tmp_path/"src", tests_root=tmp_path/"tests",
                          config={}, plugin_modules=[], graph=AnalysisGraph(ast_forest=None))
        assert detect_d7(ctx).count == 0

    def test_used_param_not_flagged(self, tmp_path):
        ctx = _make_ctx("def foo(x):\n    return x + 1\n", tmp_path)
        assert detect_d7(ctx).count == 0

    def test_unused_param_flagged(self, tmp_path):
        ctx = _make_ctx("def foo(x, y):\n    return x + 1\n", tmp_path)
        result = detect_d7(ctx)
        assert result.count == 1
        assert "y" in result.samples[0]

    def test_self_not_flagged(self, tmp_path):
        ctx = _make_ctx("""
class Foo:
    def bar(self, x):
        return x
""", tmp_path)
        assert detect_d7(ctx).count == 0

    def test_underscore_param_not_flagged(self, tmp_path):
        ctx = _make_ctx("def foo(_unused, x):\n    return x\n", tmp_path)
        assert detect_d7(ctx).count == 0

    def test_kwargs_function_not_flagged(self, tmp_path):
        # Functions with **kwargs may forward params dynamically
        ctx = _make_ctx("def foo(x, **kwargs):\n    return kwargs\n", tmp_path)
        assert detect_d7(ctx).count == 0

    def test_abstractmethod_not_flagged(self, tmp_path):
        ctx = _make_ctx("""
from abc import abstractmethod
class Base:
    @abstractmethod
    def foo(self, x):
        ...
""", tmp_path)
        assert detect_d7(ctx).count == 0

    def test_stub_body_not_flagged(self, tmp_path):
        ctx = _make_ctx("def foo(x):\n    ...\n", tmp_path)
        assert detect_d7(ctx).count == 0

    def test_dunder_method_not_flagged(self, tmp_path):
        # __exit__ params are protocol-required
        ctx = _make_ctx("""
class CM:
    def __exit__(self, exc_type, exc_val, tb):
        return False
""", tmp_path)
        assert detect_d7(ctx).count == 0

    def test_kwonly_unused_flagged(self, tmp_path):
        ctx = _make_ctx("def foo(*, x, y):\n    return x\n", tmp_path)
        result = detect_d7(ctx)
        assert result.count == 1
        assert "y" in result.samples[0]

    def test_del_param_not_flagged(self, tmp_path):
        # del var is the Python idiom for intentionally discarding a Protocol-required param
        ctx = _make_ctx("""
class Emitter:
    def emit(self, stage_name: str, content_type: str, payload: bytes) -> None:
        del stage_name, content_type
        print(payload)
""", tmp_path)
        assert detect_d7(ctx).count == 0

    def test_return_none_stub_not_flagged(self, tmp_path):
        # Null-object implementations that just return None are stubs
        ctx = _make_ctx("""
class NullEmitter:
    def emit_json(self, *, trace_id: str, stage_name: str, payload: dict) -> None:
        return None
""", tmp_path)
        assert detect_d7(ctx).count == 0

    def test_bare_return_stub_not_flagged(self, tmp_path):
        ctx = _make_ctx("def noop(x, y):\n    return\n", tmp_path)
        assert detect_d7(ctx).count == 0
