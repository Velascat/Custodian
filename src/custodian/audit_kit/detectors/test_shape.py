# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""T-class detectors — test coverage shape.

Detectors
─────────
T1  Public src functions and classes with zero name references in tests.
    Uses the tests_forest pass to collect all ast.Name occurrences in
    test files, then flags public src symbols whose name never appears.
    Conservative: only checks module-level definitions, excludes private
    names and dunder names.  LOW severity — indirect testing via wrappers
    and integration tests will produce false positives.

T2  Test functions with no assertion — a function whose name starts with
    ``test_`` and whose body contains no assertion mechanism.  Recognized
    assertion forms: ``assert`` statements, ``pytest.raises/warns/
    deprecated_call`` context managers, unittest-style ``self.assertX``
    / ``self.failX`` calls, and Mock-style ``mock.assert_called_once()``
    / ``mock.assert_not_called()`` / ``mock.assert_any_call()`` etc.
"""
from __future__ import annotations

import ast
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)

_MAX_SAMPLES = 8
_NEEDS_TF = frozenset({"ast_forest", "tests_forest"})


def build_test_shape_detectors() -> list[Detector]:
    return [
        Detector("T1", "public src symbol with no reference in tests", "open",
                 detect_t1, LOW, _NEEDS_TF),
        Detector("T2", "test function with no assert statement", "open",
                 detect_t2, LOW),
    ]


# ── helpers ───────────────────────────────────────────────────────────────────

_PYTEST_ASSERTION_ATTRS = frozenset({
    "raises", "warns", "deprecated_call", "approx", "fail",
})

_MOCK_ASSERT_PREFIXES = ("assert_called", "assert_any_call", "assert_has_calls", "assert_not_called")


def _has_assertion_mechanism(node: ast.AST) -> bool:
    """True if the subtree contains any recognized assertion mechanism.

    Recognized forms:
    - ast.Assert (``assert x``)
    - pytest.raises / pytest.warns / etc. (``with pytest.raises(...):`` or call)
    - self.assertX / self.failX (unittest-style)
    - mock.assert_called_once() / mock.assert_not_called() / etc. (Mock-style)
    - raise AssertionError(...) — explicit assertion failure
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            return True
        # raise AssertionError(...) — explicit fail as assertion
        if isinstance(child, ast.Raise) and child.exc is not None:
            exc = child.exc
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                if exc.func.id == "AssertionError":
                    return True
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if not isinstance(func, ast.Attribute):
            continue
        attr = func.attr
        value = func.value
        # pytest.raises / pytest.warns / pytest.deprecated_call
        if isinstance(value, ast.Name) and value.id == "pytest":
            if attr in _PYTEST_ASSERTION_ATTRS:
                return True
        # self.assertX / self.failX (unittest)
        if isinstance(value, ast.Name) and value.id == "self":
            if attr.startswith("assert") or attr.startswith("fail"):
                return True
        # mock.assert_called_once() / mock.assert_not_called() / etc.
        if any(attr.startswith(p) for p in _MOCK_ASSERT_PREFIXES):
            return True
    # assert_*() module-level function calls (e.g. assert_no_mutation_fields(x))
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id.startswith("assert_")
        ):
            return True
    return False


def _parse_test_files(tests_root: Path) -> list[tuple[Path, ast.Module]]:
    results: list[tuple[Path, ast.Module]] = []
    if not tests_root.is_dir():
        return results
    for path in sorted(tests_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        results.append((path, tree))
    return results


# ── T1 ────────────────────────────────────────────────────────────────────────

def _t1_excluded_paths(context: AuditContext) -> set[str]:
    """Repo-relative path strings excluded from T1 via audit.exclude_paths.T1."""
    from custodian.audit_kit.code_health import _glob_to_regex
    audit_cfg = context.config.get("audit") or {}
    globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T1") or [])
    if not globs:
        return set()
    patterns = [_glob_to_regex(g) for g in globs]
    excluded: set[str] = set()
    for path in context.src_root.rglob("*.py"):
        if not path.is_file():
            continue
        rel = path.relative_to(context.repo_root).as_posix()
        if any(p.match(rel) for p in patterns):
            excluded.add(str(path))
    return excluded


def detect_t1(context: AuditContext) -> DetectorResult:
    """Flag public src functions/classes whose name never appears in any test file."""
    if (context.graph is None
            or context.graph.ast_forest is None
            or context.graph.tests_forest is None):
        return DetectorResult(count=0, samples=[])

    # Collect every ast.Name id that appears anywhere in tests
    test_name_refs: set[str] = set()
    for _path, tree, _src in context.graph.tests_forest.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                test_name_refs.add(node.id)
            elif isinstance(node, ast.Attribute):
                test_name_refs.add(node.attr)

    excluded_paths = _t1_excluded_paths(context)
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        if str(path) in excluded_paths:
            continue
        rel = path.relative_to(context.repo_root)
        for stmt in tree.body:  # module-level only
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            name = stmt.name
            if name.startswith("_"):
                continue
            if name in test_name_refs:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                kind = "class" if isinstance(stmt, ast.ClassDef) else "def"
                samples.append(f"{rel}:{stmt.lineno}: {kind} {name} — no test reference")

    return DetectorResult(count=count, samples=samples)


# ── T2 ────────────────────────────────────────────────────────────────────────

def detect_t2(context: AuditContext) -> DetectorResult:
    """Flag test_ functions whose body contains no assert statement."""
    import fnmatch as _fnmatch
    audit_cfg: dict = context.config.get("audit") or {}
    t2_excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T2") or [])

    samples: list[str] = []
    count = 0

    for path, tree in _parse_test_files(context.tests_root):
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if t2_excludes and any(_fnmatch.fnmatch(rel_posix, excl) for excl in t2_excludes):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            if not _has_assertion_mechanism(node):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{rel}:{node.lineno}: {node.name}() — no assert")

    return DetectorResult(count=count, samples=samples)
