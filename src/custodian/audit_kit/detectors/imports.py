# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""I-class detectors — import hygiene.

Detectors
─────────
I1  Imported names that are never referenced in the same file.  Covers
    ``import X``, ``import X as Y``, ``from X import Y``, and
    ``from X import Y as Z``.

    Exclusions:
      - ``from __future__ import ...`` (always implicit)
      - Star imports (``from X import *``) — can't track what is bound
      - Imports inside ``if TYPE_CHECKING:`` blocks (annotation-only,
        intentionally not referenced at runtime)
      - Names exported via ``__all__`` (re-exported, not locally used)
      - Top-level module imports of the form ``import a.b.c`` where ``a``
        binds the root package — treated as used if ``a`` appears anywhere

    Low false-positive risk: only flags names with zero appearances
    anywhere in the file (other than the import line itself).
"""
from __future__ import annotations

import ast
import re

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)

_MAX_SAMPLES = 8
_NEEDS = frozenset({"ast_forest"})
_NOQA_RE = re.compile(r"#\s*noqa\b", re.IGNORECASE)


def build_import_detectors() -> list[Detector]:
    return [
        Detector("I1", "imported name never referenced in same file", "open",
                 detect_i1, LOW, _NEEDS),
    ]


# ── helpers ───────────────────────────────────────────────────────────────────

def _type_checking_node_ids(tree: ast.Module) -> set[int]:
    """Return id() of every node inside a TYPE_CHECKING if-block."""
    ids: set[int] = set()
    for stmt in tree.body:
        if not isinstance(stmt, ast.If):
            continue
        test = stmt.test
        if (isinstance(test, ast.Name) and test.id == "TYPE_CHECKING") or \
                (isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"):
            for node in ast.walk(stmt):
                ids.add(id(node))
    return ids


def _imported_names(
    tree: ast.Module,
    tc_ids: set[int],
    src_lines: list[str],
) -> list[tuple[str, int]]:
    """Return (local_name, lineno) for each trackable import at module scope.

    Lines with ``# noqa`` (any form) are excluded — they're intentional
    re-exports or suppressed by the author.
    """
    result: list[tuple[str, int]] = []
    for stmt in tree.body:
        if id(stmt) in tc_ids:
            continue
        lineno = stmt.lineno
        # Check all physical lines the statement spans for a noqa comment
        end_lineno = getattr(stmt, "end_lineno", lineno)
        if any(
            _NOQA_RE.search(src_lines[ln - 1])
            for ln in range(lineno, end_lineno + 1)
            if 0 < ln <= len(src_lines)
        ):
            continue
        if isinstance(stmt, ast.Import):
            for alias in stmt.names:
                local = alias.asname if alias.asname else alias.name.split(".")[0]
                result.append((local, lineno))
        elif isinstance(stmt, ast.ImportFrom):
            if (stmt.module or "") == "__future__":
                continue
            for alias in stmt.names:
                if alias.name == "*":
                    continue
                local = alias.asname if alias.asname else alias.name
                result.append((local, lineno))
    return result


def _name_refs(tree: ast.Module, import_linenos: set[int]) -> set[str]:
    """Names referenced in the file excluding the import lines themselves."""
    refs: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and getattr(node, "lineno", None) not in import_linenos:
            refs.add(node.id)
        elif isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            # `os.path` → `os` is used; collect root name
            if getattr(node.value, "lineno", None) not in import_linenos:
                refs.add(node.value.id)
    # Names in __all__ string list count as used (re-exported)
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__all__" for t in stmt.targets):
            continue
        if isinstance(stmt.value, (ast.List, ast.Tuple)):
            for elt in stmt.value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    refs.add(elt.value)
    return refs


# ── I1 ────────────────────────────────────────────────────────────────────────

def detect_i1(context: AuditContext) -> DetectorResult:
    """Flag imported names that are never referenced in the same file."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        src_lines = src.splitlines()
        tc_ids = _type_checking_node_ids(tree)
        imports = _imported_names(tree, tc_ids, src_lines)
        if not imports:
            continue

        import_linenos = {lineno for _, lineno in imports}
        refs = _name_refs(tree, import_linenos)

        for name, lineno in imports:
            if name not in refs:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{rel}:{lineno}: '{name}' imported but never used")

    return DetectorResult(count=count, samples=samples)
