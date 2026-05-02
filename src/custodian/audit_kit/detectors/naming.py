# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""N-class detectors — naming convention violations.

Detectors
─────────
N1  Custom exception class with a non-conventional name.  Exception
    subclasses should end in ``Error``, ``Exception``, or ``Warning``
    (following PEP 8 and Python stdlib convention).  Classes whose names
    end with ``Stop``, ``Abort``, ``Cancel``, or ``Signal`` are excluded
    — these are legitimately named control-flow signals, not errors.
"""
from __future__ import annotations

import ast

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)

_MAX_SAMPLES = 8

_EXCEPTION_BASES = frozenset({
    "Exception", "BaseException",
    "ValueError", "RuntimeError", "TypeError", "OSError", "IOError",
    "KeyError", "AttributeError", "NotImplementedError", "StopIteration",
    "PermissionError", "FileNotFoundError", "TimeoutError", "ConnectionError",
    "LookupError", "ArithmeticError", "UnicodeError", "ImportError",
    "AssertionError", "EnvironmentError", "IndexError", "NameError",
    "OverflowError", "RecursionError", "SystemError", "ZeroDivisionError",
})

_CONVENTIONAL_SUFFIXES = ("Error", "Exception", "Warning")
_CONTROL_FLOW_SUFFIXES = ("Stop", "Abort", "Cancel", "Signal", "Interrupt")


def build_naming_detectors() -> list[Detector]:
    return [
        Detector("N1", "exception class name does not follow Error/Exception/Warning convention",
                 "open", detect_n1, LOW),
    ]


def detect_n1(context: AuditContext) -> DetectorResult:
    """Flag custom exception classes whose names don't end in Error/Exception/Warning."""
    audit_cfg = context.config.get("audit") or {}
    globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("N1") or [])

    from pathlib import PurePosixPath
    from custodian.audit_kit.code_health import _py_files

    samples: list[str] = []
    count = 0

    for path in _py_files(context, "N1"):
        if globs:
            rel = str(path.relative_to(context.repo_root))
            if any(PurePosixPath(rel).match(g) for g in globs):
                continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            base_names: set[str] = set()
            for base in node.bases:
                if isinstance(base, ast.Name):
                    base_names.add(base.id)
                elif isinstance(base, ast.Attribute):
                    base_names.add(base.attr)
            if not (base_names & _EXCEPTION_BASES):
                continue
            name = node.name
            if any(name.endswith(s) for s in _CONVENTIONAL_SUFFIXES):
                continue
            if any(name.endswith(s) for s in _CONTROL_FLOW_SUFFIXES):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(f"{rel}:{node.lineno}: class {name} (inherits from exception, should end in Error/Exception)")

    return DetectorResult(count=count, samples=samples)
