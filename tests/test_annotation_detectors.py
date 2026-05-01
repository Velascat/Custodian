# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for E-class detectors: E1 (missing return annotation), E2 (missing param annotations)."""
from __future__ import annotations

import ast
import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.annotations import detect_e1, detect_e2
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


def _ctx(tmp_path: Path, forest: AstForest) -> AuditContext:
    return AuditContext(
        repo_root=tmp_path,
        src_root=tmp_path / "src",
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=forest),
    )


class TestE1:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = _ctx(tmp_path, AstForest())
        ctx.graph = AnalysisGraph(ast_forest=None)
        assert detect_e1(ctx).count == 0

    def test_unannotated_public_function_flagged(self, tmp_path):
        f = _forest("def foo(): pass", tmp_path)
        assert detect_e1(_ctx(tmp_path, f)).count == 1

    def test_annotated_return_not_flagged(self, tmp_path):
        f = _forest("def foo() -> int: return 1", tmp_path)
        assert detect_e1(_ctx(tmp_path, f)).count == 0

    def test_private_function_not_flagged(self, tmp_path):
        f = _forest("def _bar(): pass", tmp_path)
        assert detect_e1(_ctx(tmp_path, f)).count == 0

    def test_init_exempt(self, tmp_path):
        f = _forest("""
            class Foo:
                def __init__(self): pass
        """, tmp_path)
        assert detect_e1(_ctx(tmp_path, f)).count == 0

    def test_abstractmethod_not_flagged(self, tmp_path):
        f = _forest("""
            from abc import abstractmethod
            class Base:
                @abstractmethod
                def run(self): ...
        """, tmp_path)
        assert detect_e1(_ctx(tmp_path, f)).count == 0

    def test_overload_not_flagged(self, tmp_path):
        f = _forest("""
            from typing import overload
            @overload
            def foo(x: int): ...
        """, tmp_path)
        assert detect_e1(_ctx(tmp_path, f)).count == 0

    def test_protocol_method_not_flagged(self, tmp_path):
        f = _forest("""
            from typing import Protocol
            class P(Protocol):
                def run(self): ...
        """, tmp_path)
        assert detect_e1(_ctx(tmp_path, f)).count == 0

    def test_async_unannotated_flagged(self, tmp_path):
        f = _forest("async def bar(): pass", tmp_path)
        assert detect_e1(_ctx(tmp_path, f)).count == 1

    def test_dunder_non_exempt_flagged(self, tmp_path):
        # __call__ is not in the exempt list
        f = _forest("""
            class Foo:
                def __call__(self): pass
        """, tmp_path)
        assert detect_e1(_ctx(tmp_path, f)).count == 1


class TestE2:
    def test_no_forest_returns_zero(self, tmp_path):
        ctx = _ctx(tmp_path, AstForest())
        ctx.graph = AnalysisGraph(ast_forest=None)
        assert detect_e2(ctx).count == 0

    def test_unannotated_param_flagged(self, tmp_path):
        f = _forest("def foo(x) -> None: pass", tmp_path)
        assert detect_e2(_ctx(tmp_path, f)).count == 1

    def test_fully_annotated_not_flagged(self, tmp_path):
        f = _forest("def foo(x: int) -> None: pass", tmp_path)
        assert detect_e2(_ctx(tmp_path, f)).count == 0

    def test_self_excluded(self, tmp_path):
        f = _forest("""
            class Foo:
                def bar(self) -> None: pass
        """, tmp_path)
        assert detect_e2(_ctx(tmp_path, f)).count == 0

    def test_cls_excluded(self, tmp_path):
        f = _forest("""
            class Foo:
                @classmethod
                def create(cls) -> None: pass
        """, tmp_path)
        assert detect_e2(_ctx(tmp_path, f)).count == 0

    def test_private_not_flagged(self, tmp_path):
        f = _forest("def _helper(x) -> None: pass", tmp_path)
        assert detect_e2(_ctx(tmp_path, f)).count == 0

    def test_kwonly_unannotated_flagged(self, tmp_path):
        f = _forest("def foo(*, name) -> None: pass", tmp_path)
        assert detect_e2(_ctx(tmp_path, f)).count == 1

    def test_vararg_unannotated_flagged(self, tmp_path):
        f = _forest("def foo(*args) -> None: pass", tmp_path)
        assert detect_e2(_ctx(tmp_path, f)).count == 1

    def test_no_params_not_flagged(self, tmp_path):
        f = _forest("def foo() -> None: pass", tmp_path)
        assert detect_e2(_ctx(tmp_path, f)).count == 0
