# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""X-class detectors — function complexity (deprecated; replaced by ruff).

Both detectors are deprecated and return no findings when run.
Use ruff C901 (cyclomatic complexity) and PLR0913 (too many params) instead.
"""
from __future__ import annotations

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW, MEDIUM,
)

_NEEDS = frozenset({"ast_forest"})


def build_complexity_detectors() -> list[Detector]:
    return [
        Detector("X1", "function cyclomatic complexity above threshold", "open",
                 _stub, MEDIUM, _NEEDS, deprecated=True, replaces="ruff:C901"),
        Detector("X2", "function with too many parameters", "open",
                 _stub, LOW, _NEEDS, deprecated=True, replaces="ruff:PLR0913"),
    ]


def _stub(context: AuditContext) -> DetectorResult:
    return DetectorResult(count=0, samples=[])
