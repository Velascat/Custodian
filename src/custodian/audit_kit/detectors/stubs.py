# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""U-class detectors — unimplemented / stub functions.

These detectors use the ``ast_forest`` analysis pass to inspect function
bodies across all source files.

Detectors
─────────
U1  ``raise NotImplementedError`` stubs — functions whose entire body
    (after an optional docstring) is a single ``raise NotImplementedError``
    statement.  Excludes ``@abstractmethod``-decorated methods (intentionally
    abstract) and methods in ``Protocol`` classes (convention uses ``...``).

U2  Ellipsis-only stubs — functions whose entire body (after an optional
    docstring) is a single ``...`` expression.  Excludes ``@abstractmethod``,
    ``@overload``, and methods inside ``Protocol`` classes, where ``...`` is
    the correct idiom.

U3  Docstring-only functions — functions that contain only a docstring and
    no other statements.  These are almost always unfinished implementations
    left after scaffolding.  Excludes ``@abstractmethod`` and ``Protocol``
    methods.
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW, MEDIUM,
)

if TYPE_CHECKING:
    pass

_MAX_SAMPLES = 8
_NEEDS = frozenset({"ast_forest"})


def build_stub_detectors() -> list[Detector]:
    return [
        Detector("U1", "raise NotImplementedError stub (unimplemented function)", "open",
                 detect_u1, MEDIUM, _NEEDS),
        Detector("U2", "ellipsis-only stub outside Protocol/abstractmethod", "open",
                 detect_u2, LOW, _NEEDS),
        Detector("U3", "docstring-only function body (no implementation)", "open",
                 detect_u3, LOW, _NEEDS),
    ]


# ── AST helpers ───────────────────────────────────────────────────────────────

def _strip_docstring(body: list[ast.stmt]) -> list[ast.stmt]:
    """Return body with a leading docstring removed, if present."""
    if (body and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)):
        return body[1:]
    return body


def _has_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef, *names: str) -> bool:
    for dec in func.decorator_list:
        dec_name = None
        if isinstance(dec, ast.Name):
            dec_name = dec.id
        elif isinstance(dec, ast.Attribute):
            dec_name = dec.attr
        if dec_name in names:
            return True
    return False


def _is_not_implemented_raise(stmt: ast.stmt) -> bool:
    if not isinstance(stmt, ast.Raise):
        return False
    exc = stmt.exc
    if exc is None:
        return False
    # Unwrap Call: raise NotImplementedError(...)
    if isinstance(exc, ast.Call):
        exc = exc.func
    if isinstance(exc, ast.Name):
        return exc.id == "NotImplementedError"
    if isinstance(exc, ast.Attribute):
        return exc.attr == "NotImplementedError"
    return False


def _is_ellipsis_only(stmt: ast.stmt) -> bool:
    return (isinstance(stmt, ast.Expr)
            and isinstance(stmt.value, ast.Constant)
            and stmt.value.value is ...)


def _protocol_classes(tree: ast.Module) -> set[str]:
    """Return names of Protocol-subclassing classes in this module."""
    names: set[str] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ClassDef):
            continue
        for base in node.bases:
            base_name = None
            if isinstance(base, ast.Name):
                base_name = base.id
            elif isinstance(base, ast.Attribute):
                base_name = base.attr
            if base_name == "Protocol":
                names.add(node.name)
    return names


def _except_handler_functions(tree: ast.Module) -> set[int]:
    """Return ids of FunctionDef nodes that live inside except-handler bodies.

    try/except fallback stubs (e.g. ``except ImportError: class Foo: def add():...``)
    are intentional no-ops, not unfinished implementations.
    """
    ids: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.ExceptHandler):
            continue
        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                ids.add(id(child))
    return ids


def _containing_class(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.Module,
) -> ast.ClassDef | None:
    """Return the ClassDef that directly contains func, or None."""
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if item is func:
                    return node
    return None


def _sample(
    path: Path,
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    context: AuditContext,
) -> str:
    rel = path.relative_to(context.repo_root)
    return f"{rel}:{func.lineno}: {func.name}()"


# ── per-file scanner factory ──────────────────────────────────────────────────

def _scan_functions(
    context: AuditContext,
    predicate,
) -> DetectorResult:
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        protocol_names = _protocol_classes(tree)
        except_fn_ids = _except_handler_functions(tree)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _has_decorator(node, "abstractmethod", "overload"):
                continue
            if id(node) in except_fn_ids:
                continue
            container = _containing_class(node, tree)
            if container and container.name in protocol_names:
                continue
            if predicate(node):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(_sample(path, node, context))

    return DetectorResult(count=count, samples=samples)


# ── U1 ────────────────────────────────────────────────────────────────────────

def detect_u1(context: AuditContext) -> DetectorResult:
    """Flag functions whose body (after docstring) is only raise NotImplementedError."""
    def predicate(func):
        body = _strip_docstring(func.body)
        return len(body) == 1 and _is_not_implemented_raise(body[0])
    return _scan_functions(context, predicate)


# ── U2 ────────────────────────────────────────────────────────────────────────

def detect_u2(context: AuditContext) -> DetectorResult:
    """Flag functions whose body (after docstring) is only ``...``."""
    def predicate(func):
        body = _strip_docstring(func.body)
        return len(body) == 1 and _is_ellipsis_only(body[0])
    return _scan_functions(context, predicate)


# ── U3 ────────────────────────────────────────────────────────────────────────

def detect_u3(context: AuditContext) -> DetectorResult:
    """Flag functions that contain only a docstring (no implementation at all)."""
    def predicate(func):
        # Has a docstring
        if not (func.body and isinstance(func.body[0], ast.Expr)
                and isinstance(func.body[0].value, ast.Constant)
                and isinstance(func.body[0].value.value, str)):
            return False
        # And nothing else after the docstring
        return len(func.body) == 1
    return _scan_functions(context, predicate)
