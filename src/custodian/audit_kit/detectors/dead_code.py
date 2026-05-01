# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""D-class and F-class detectors — dead code and unused definitions.

Detectors
─────────
D2  Dead else after terminal if-branch — an else clause present when the
    if-body always exits (return/raise/break/continue).  The else is
    structurally unreachable via the if-path and can be deleted, flattening
    the indentation level.  Only flagged inside function bodies.

D4  Unreachable code after unconditional return/raise/break/continue.
    Any statement following a terminal in the same block can never execute.
    Recurses into nested if/for/while/try/with bodies but not into nested
    function or class definitions (separate scopes).

F2  Private module-level constant defined but never referenced in the same
    file.  Matches _ALL_CAPS names at module scope.  Names in ``__all__``
    are excluded (they may be imported by consumers).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW, MEDIUM,
)

_MAX_SAMPLES = 8
_NEEDS = frozenset({"ast_forest"})
_PRIVATE_CAPS = re.compile(r"^_[A-Z][A-Z0-9_]*$")


def build_dead_code_detectors() -> list[Detector]:
    return [
        Detector("D2", "unnecessary else after terminal if-branch", "open",
                 detect_d2, LOW, _NEEDS),
        Detector("D4", "unreachable code after return/raise/break/continue", "open",
                 detect_d4, MEDIUM, _NEEDS),
        Detector("F2", "private module-level constant defined but never referenced", "open",
                 detect_f2, LOW, _NEEDS),
    ]


# ── AST helpers ───────────────────────────────────────────────────────────────

def _is_terminal(stmt: ast.stmt) -> bool:
    return isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue))


def _block_terminates(body: list[ast.stmt]) -> bool:
    return bool(body) and _is_terminal(body[-1])


def _stmts_of(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Return all nested statement lists within stmt (excluding function/class bodies)."""
    if isinstance(stmt, ast.If):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, (ast.For, ast.While)):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, ast.Try):
        nested = [stmt.body, stmt.orelse, stmt.finalbody]
        for h in stmt.handlers:
            nested.append(h.body)
        return nested
    if isinstance(stmt, ast.With):
        return [stmt.body]
    return []


# ── D2 ────────────────────────────────────────────────────────────────────────

def _dead_else_nodes(stmts: list[ast.stmt]) -> list[ast.If]:
    """Recursively find ast.If nodes with a dead (redundant) else clause.

    Only flag when the if-body terminates but the else-body does NOT — this
    catches the guard-clause pattern where the else is pure indentation.
    When BOTH branches terminate (symmetric if/else), the else is intentional
    and is not flagged.
    """
    hits: list[ast.If] = []
    for stmt in stmts:
        if isinstance(stmt, ast.If):
            if (stmt.orelse
                    and not isinstance(stmt.orelse[0], ast.If)
                    and _block_terminates(stmt.body)
                    and not _block_terminates(stmt.orelse)):
                hits.append(stmt)
        for nested in _stmts_of(stmt):
            hits.extend(_dead_else_nodes(nested))
    return hits


def detect_d2(context: AuditContext) -> DetectorResult:
    """Flag else clauses that follow an if-body that always exits."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for hit in _dead_else_nodes(node.body):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{hit.lineno}: {node.name}() — else after terminal if"
                    )

    return DetectorResult(count=count, samples=samples)


# ── D4 ────────────────────────────────────────────────────────────────────────

def _unreachable_stmts(stmts: list[ast.stmt]) -> list[ast.stmt]:
    """Find first unreachable statement in this block, then recurse into compounds."""
    results: list[ast.stmt] = []
    for i, stmt in enumerate(stmts):
        if _is_terminal(stmt) and i + 1 < len(stmts):
            results.append(stmts[i + 1])
            break
        for nested in _stmts_of(stmt):
            results.extend(_unreachable_stmts(nested))
    return results


def detect_d4(context: AuditContext) -> DetectorResult:
    """Flag statements that follow an unconditional return/raise/break/continue."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for hit in _unreachable_stmts(node.body):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    lineno = getattr(hit, "lineno", node.lineno)
                    samples.append(
                        f"{rel}:{lineno}: {node.name}() — unreachable code"
                    )

    return DetectorResult(count=count, samples=samples)


# ── F2 ────────────────────────────────────────────────────────────────────────

def _private_constant_defs(tree: ast.Module) -> dict[str, ast.AST]:
    defs: dict[str, ast.AST] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and _PRIVATE_CAPS.match(target.id):
                    defs[target.id] = target
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name) and _PRIVATE_CAPS.match(stmt.target.id):
                defs[stmt.target.id] = stmt.target
    return defs


def _module_all_exports(tree: ast.Module) -> set[str]:
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__all__" for t in stmt.targets):
            continue
        if isinstance(stmt.value, (ast.List, ast.Tuple)):
            return {
                elt.value
                for elt in stmt.value.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            }
    return set()


def _usage_counts(
    tree: ast.Module,
    names: set[str],
    exclude_node_ids: set[int],
) -> dict[str, int]:
    counts: dict[str, int] = {n: 0 for n in names}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in counts and id(node) not in exclude_node_ids:
            counts[node.id] += 1
    return counts


def detect_f2(context: AuditContext) -> DetectorResult:
    """Flag private _ALL_CAPS module-level constants never referenced in their file."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        defs = _private_constant_defs(tree)
        if not defs:
            continue
        exports = _module_all_exports(tree)
        checkable = {k: v for k, v in defs.items() if k not in exports}
        if not checkable:
            continue

        def_node_ids = {id(n) for n in checkable.values()}
        usages = _usage_counts(tree, set(checkable), def_node_ids)

        for name, use_count in sorted(usages.items()):
            if use_count == 0:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    lineno = getattr(checkable[name], "lineno", 0)
                    rel = path.relative_to(context.repo_root)
                    samples.append(f"{rel}:{lineno}: {name} — defined but never used")

    return DetectorResult(count=count, samples=samples)
