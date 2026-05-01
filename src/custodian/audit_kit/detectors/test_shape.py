# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""T-class detectors — test coverage shape.

Detectors
─────────
T2  Test functions with no assertion — a function whose name starts with
    ``test_`` and whose body contains no ``assert`` statement (ast.Assert).
    These are most likely forgotten stubs or tests that lost their
    assertions during a refactor.  Note: unittest-style ``self.assertEqual``
    calls are *not* caught here — T2 targets pytest-style tests only.
"""
from __future__ import annotations

import ast
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)

_MAX_SAMPLES = 8


def build_test_shape_detectors() -> list[Detector]:
    return [
        Detector("T2", "test function with no assert statement", "open",
                 detect_t2, LOW),
    ]


# ── helpers ───────────────────────────────────────────────────────────────────

def _has_assert(node: ast.AST) -> bool:
    """True if any ast.Assert appears in the subtree rooted at node."""
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
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
            if not _has_assert(node):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{rel}:{node.lineno}: {node.name}() — no assert")

    return DetectorResult(count=count, samples=samples)
