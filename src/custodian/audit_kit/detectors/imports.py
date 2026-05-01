# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""I-class detectors — import hygiene (deprecated; replaced by ruff).

I1 is deprecated and returns no findings when run.
Use ruff F401 instead.
"""
from __future__ import annotations

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)

_NEEDS = frozenset({"ast_forest"})


def build_import_detectors() -> list[Detector]:
    return [
        Detector("I1", "imported name never referenced in same file", "open",
                 _stub, LOW, _NEEDS, deprecated=True, replaces="ruff:F401"),
    ]


def _stub(context: AuditContext) -> DetectorResult:
    return DetectorResult(count=0, samples=[])
