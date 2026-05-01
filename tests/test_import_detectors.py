# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""Tests for I1 (imported name never referenced in same file)."""
from __future__ import annotations

import textwrap
from pathlib import Path

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.imports import detect_i1
from custodian.audit_kit.passes.ast_forest import build_ast_forest


def _write_src(src: str, tmp_path: Path, name: str = "module.py") -> None:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    (src_root / name).write_text(textwrap.dedent(src), encoding="utf-8")


def _ctx(tmp_path: Path) -> AuditContext:
    src_root = tmp_path / "src"
    src_root.mkdir(parents=True, exist_ok=True)
    forest = build_ast_forest(src_root)
    return AuditContext(
        repo_root=tmp_path,
        src_root=src_root,
        tests_root=tmp_path / "tests",
        config={},
        plugin_modules=[],
        graph=AnalysisGraph(ast_forest=forest),
    )


class TestI1Basic:
    def test_no_ast_forest_returns_zero(self, tmp_path):
        ctx = AuditContext(
            repo_root=tmp_path, src_root=tmp_path / "src",
            tests_root=tmp_path / "tests", config={}, plugin_modules=[],
            graph=AnalysisGraph(ast_forest=None),
        )
        assert detect_i1(ctx).count == 0

    def test_unused_simple_import_flagged(self, tmp_path):
        _write_src("import os\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 1

    def test_used_simple_import_not_flagged(self, tmp_path):
        _write_src("import os\nos.path.join('a', 'b')\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_unused_from_import_flagged(self, tmp_path):
        _write_src("from pathlib import Path\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 1

    def test_used_from_import_not_flagged(self, tmp_path):
        _write_src("from pathlib import Path\nx = Path('.')\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_unused_alias_flagged(self, tmp_path):
        _write_src("import numpy as np\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 1

    def test_used_alias_not_flagged(self, tmp_path):
        _write_src("import numpy as np\nx = np.array([1])\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_from_import_with_alias_unused_flagged(self, tmp_path):
        _write_src("from os.path import join as j\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 1

    def test_from_import_with_alias_used_not_flagged(self, tmp_path):
        _write_src("from os.path import join as j\nj('a', 'b')\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_sample_contains_file_and_name(self, tmp_path):
        _write_src("import sys\n", tmp_path)
        result = detect_i1(_ctx(tmp_path))
        assert result.count == 1
        assert "'sys'" in result.samples[0]


class TestI1Exclusions:
    def test_future_import_excluded(self, tmp_path):
        _write_src("from __future__ import annotations\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_star_import_excluded(self, tmp_path):
        _write_src("from os.path import *\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_type_checking_import_excluded(self, tmp_path):
        _write_src("""
            from __future__ import annotations
            from typing import TYPE_CHECKING
            if TYPE_CHECKING:
                import something_unused
        """, tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_type_checking_from_import_excluded(self, tmp_path):
        _write_src("""
            from __future__ import annotations
            from typing import TYPE_CHECKING
            if TYPE_CHECKING:
                from some.module import SomeType
        """, tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_reexported_via_all_not_flagged(self, tmp_path):
        _write_src("""
            from mymodule import Foo
            __all__ = ["Foo"]
        """, tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_dotted_import_root_used_not_flagged(self, tmp_path):
        _write_src("""
            import os.path
            x = os.path.join("a", "b")
        """, tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_dotted_import_root_unused_flagged(self, tmp_path):
        _write_src("import os.path\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 1

    def test_typing_type_checking_attribute_excluded(self, tmp_path):
        _write_src("""
            from __future__ import annotations
            import typing
            if typing.TYPE_CHECKING:
                from mymod import MyClass
        """, tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0


class TestI1MultiFile:
    def test_counts_across_multiple_files(self, tmp_path):
        _write_src("import os\n", tmp_path, "a.py")
        _write_src("import sys\n", tmp_path, "b.py")
        assert detect_i1(_ctx(tmp_path)).count == 2

    def test_mixed_used_and_unused_across_files(self, tmp_path):
        _write_src("import os\nos.getcwd()\n", tmp_path, "a.py")
        _write_src("import sys\n", tmp_path, "b.py")
        assert detect_i1(_ctx(tmp_path)).count == 1

    def test_max_samples_cap(self, tmp_path):
        src_root = tmp_path / "src"
        src_root.mkdir(parents=True, exist_ok=True)
        for i in range(12):
            (src_root / f"mod{i}.py").write_text(f"import os\n", encoding="utf-8")
        forest = build_ast_forest(src_root)
        ctx = AuditContext(
            repo_root=tmp_path, src_root=src_root,
            tests_root=tmp_path / "tests", config={}, plugin_modules=[],
            graph=AnalysisGraph(ast_forest=forest),
        )
        result = detect_i1(ctx)
        assert result.count == 12
        assert len(result.samples) == 8

    def test_noqa_import_excluded(self, tmp_path):
        _write_src("from mymodule import Foo  # noqa: F401\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0

    def test_noqa_bare_import_excluded(self, tmp_path):
        _write_src("import os  # noqa\n", tmp_path)
        assert detect_i1(_ctx(tmp_path)).count == 0
