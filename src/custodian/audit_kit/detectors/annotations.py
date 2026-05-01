# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""E-class detectors — type annotations (deprecated; replaced by ty/ruff).

Both detectors are deprecated and return no findings when run.
Use ty (or ruff ANN* rules) instead.
"""
from __future__ import annotations

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)

_NEEDS = frozenset({"ast_forest"})


def build_annotation_detectors() -> list[Detector]:
    return [
        Detector("E1", "missing return-type annotation on public functions", "open",
                 _stub, LOW, _NEEDS, deprecated=True, replaces="ty:return-type / ruff:ANN201"),
        Detector("E2", "missing parameter annotation on public functions", "open",
                 _stub, LOW, _NEEDS, deprecated=True, replaces="ty:annotation / ruff:ANN001"),
    ]


def _stub(context: AuditContext) -> DetectorResult:
    return DetectorResult(count=0, samples=[])
