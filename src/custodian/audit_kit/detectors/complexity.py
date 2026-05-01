# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""X-class detectors — function complexity.

Detectors
─────────
X1  Cyclomatic complexity above threshold.  Complexity is counted as 1
    (base) plus one for each: ``if``, ``elif``, ``for``, ``while``,
    ``except`` handler, comprehension clause, ``with`` item, boolean
    operator value beyond the first (``and``/``or``).  Default threshold
    is 10 (industry-standard "should be refactored" level).  Configurable
    via ``.custodian.yaml``:
        audit:
          x1_threshold: 12

X2  Functions with too many parameters.  A large parameter list is a
    design smell — the function likely does too much or needs a config
    object.  ``self`` and ``cls`` are excluded.  Default threshold is 5.
    Configurable via ``.custodian.yaml``:
        audit:
          x2_threshold: 6
"""
from __future__ import annotations

import ast

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW, MEDIUM,
)

_MAX_SAMPLES = 8
_NEEDS = frozenset({"ast_forest"})

_DEFAULT_COMPLEXITY_THRESHOLD = 10
_DEFAULT_PARAM_THRESHOLD = 5
_SKIP_PARAMS = {"self", "cls"}


def build_complexity_detectors() -> list[Detector]:
    return [
        Detector("X1", "function cyclomatic complexity above threshold", "open",
                 detect_x1, MEDIUM, _NEEDS, deprecated=True, replaces="ruff:C901"),
        Detector("X2", "function with too many parameters", "open",
                 detect_x2, LOW, _NEEDS, deprecated=True, replaces="ruff:PLR0913"),
    ]


# ── helpers ───────────────────────────────────────────────────────────────────

def _cyclomatic_complexity(func: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    """Count cyclomatic complexity: 1 + decision points inside func."""
    complexity = 1
    for node in ast.walk(func):
        if node is func:
            continue  # don't double-count the function node itself
        if isinstance(node, (ast.If, ast.For, ast.While, ast.ExceptHandler)):
            complexity += 1
        elif isinstance(node, ast.comprehension):
            complexity += 1
        elif isinstance(node, ast.BoolOp):
            # each extra value in `a and b and c` adds one branch
            complexity += len(node.values) - 1
        elif isinstance(node, ast.IfExp):
            # ternary: `x if cond else y`
            complexity += 1
        elif isinstance(node, ast.match_case):  # Python 3.10+
            complexity += 1
    return complexity


def _param_count(func: ast.FunctionDef | ast.AsyncFunctionDef) -> int:
    args = func.args
    all_args = args.posonlyargs + args.args + args.kwonlyargs
    count = sum(1 for a in all_args if a.arg not in _SKIP_PARAMS)
    if args.vararg:
        count += 1
    if args.kwarg:
        count += 1
    return count


def _threshold(context: AuditContext, key: str, default: int) -> int:
    audit_cfg = context.config.get("audit") or {}
    val = audit_cfg.get(key)
    try:
        return int(val) if val is not None else default
    except (TypeError, ValueError):
        return default


# ── X1 ────────────────────────────────────────────────────────────────────────

def detect_x1(context: AuditContext) -> DetectorResult:
    """Flag functions whose cyclomatic complexity exceeds the threshold."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    limit = _threshold(context, "x1_threshold", _DEFAULT_COMPLEXITY_THRESHOLD)
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            cc = _cyclomatic_complexity(node)
            if cc > limit:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{node.lineno}: {node.name}() — complexity {cc} (limit {limit})"
                    )

    return DetectorResult(count=count, samples=samples)


# ── X2 ────────────────────────────────────────────────────────────────────────

def detect_x2(context: AuditContext) -> DetectorResult:
    """Flag functions with more parameters than the threshold."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    limit = _threshold(context, "x2_threshold", _DEFAULT_PARAM_THRESHOLD)
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            n = _param_count(node)
            if n > limit:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{node.lineno}: {node.name}() — {n} params (limit {limit})"
                    )

    return DetectorResult(count=count, samples=samples)
