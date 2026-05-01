# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""E-class detectors — annotation coverage gaps.

Detectors
─────────
E1  Public functions and methods with no return type annotation.
    Excludes ``__init__``, ``__new__``, dunder methods (convention is
    to omit ``-> None``), private/protected names (leading ``_``),
    ``@abstractmethod``, ``@overload``, and Protocol methods.

E2  Public functions and methods with at least one unannotated parameter.
    ``self`` and ``cls`` are always excluded.  Same exclusions as E1.
"""
from __future__ import annotations

import ast

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)

_MAX_SAMPLES = 8
_NEEDS = frozenset({"ast_forest"})

# Dunder methods where omitting -> None is accepted convention.
_DUNDER_RETURN_EXEMPT = {
    "__init__", "__new__", "__del__", "__init_subclass__",
    "__set_name__", "__post_init__",
}
_SKIP_PARAMS = {"self", "cls"}


def build_annotation_detectors() -> list[Detector]:
    return [
        Detector("E1", "public function missing return type annotation", "open",
                 detect_e1, LOW, _NEEDS, deprecated=True, replaces="ty:return-type / ruff:ANN201"),
        Detector("E2", "public function with unannotated parameter(s)", "open",
                 detect_e2, LOW, _NEEDS, deprecated=True, replaces="ty:annotation / ruff:ANN001"),
    ]


# ── shared helpers ────────────────────────────────────────────────────────────

def _has_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef, *names: str) -> bool:
    for dec in func.decorator_list:
        name = (dec.id if isinstance(dec, ast.Name)
                else dec.attr if isinstance(dec, ast.Attribute) else None)
        if name in names:
            return True
    return False


def _protocol_class_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = (base.id if isinstance(base, ast.Name)
                             else base.attr if isinstance(base, ast.Attribute) else None)
                if base_name == "Protocol":
                    names.add(node.name)
    return names


def _direct_class(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.Module,
) -> ast.ClassDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if item is func:
                    return node
    return None


def _is_public(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    name = func.name
    if name.startswith("_") and not (name.startswith("__") and name.endswith("__")):
        return False
    return True


def _scan(
    context: AuditContext,
    predicate,
) -> DetectorResult:
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        protocol_names = _protocol_class_names(tree)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not _is_public(node):
                continue
            if _has_decorator(node, "abstractmethod", "overload"):
                continue
            container = _direct_class(node, tree)
            if container and container.name in protocol_names:
                continue
            if predicate(node):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{rel}:{node.lineno}: {node.name}()")

    return DetectorResult(count=count, samples=samples)


# ── E1 ────────────────────────────────────────────────────────────────────────

def detect_e1(context: AuditContext) -> DetectorResult:
    """Flag public functions with no return type annotation."""
    def predicate(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        if func.name in _DUNDER_RETURN_EXEMPT:
            return False
        return func.returns is None
    return _scan(context, predicate)


# ── E2 ────────────────────────────────────────────────────────────────────────

def detect_e2(context: AuditContext) -> DetectorResult:
    """Flag public functions with at least one unannotated parameter."""
    def predicate(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        args = func.args
        all_args = args.posonlyargs + args.args + args.kwonlyargs
        if args.vararg:
            all_args = all_args + [args.vararg]
        if args.kwarg:
            all_args = all_args + [args.kwarg]
        for arg in all_args:
            if arg.arg in _SKIP_PARAMS:
                continue
            if arg.annotation is None:
                return True
        return False
    return _scan(context, predicate)
