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
    deprecated_call`` context managers, and unittest-style ``self.assertX``
    / ``self.failX`` calls.  Tests using only these forms are not flagged.
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


def _has_assertion_mechanism(node: ast.AST) -> bool:
    """True if the subtree contains any recognized assertion mechanism.

    Recognized forms:
    - ast.Assert (``assert x``)
    - pytest.raises / pytest.warns / etc. (``with pytest.raises(...):`` or call)
    - self.assertX / self.failX (unittest-style)
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
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

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
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
    samples: list[str] = []
    count = 0

    for path, tree in _parse_test_files(context.tests_root):
        rel = path.relative_to(context.repo_root)
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
