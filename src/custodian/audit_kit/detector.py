# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

from dataclasses import dataclass, field
import pathlib
from typing import Callable

from custodian.audit_kit.result import AuditResult

# Severity constants — use these names in Detector definitions
HIGH   = "high"
MEDIUM = "medium"
LOW    = "low"

_SEVERITY_ORDER = {HIGH: 0, MEDIUM: 1, LOW: 2}


@dataclass
class Detector:
    """One audit pattern. id is repo-namespaced (e.g. "C1", "F3", "G12").

    severity: "high" | "medium" | "low"  (default "medium")
      - high:   code that can hide bugs or break prod (bare except, breakpoints)
      - medium: quality issues that should be fixed but are not urgent
      - low:    tracked debt / style that does not block work
    """

    id: str
    description: str
    status: str  # "fixed" | "open" | "partial" | "deferred"
    detect: Callable[["AuditContext"], "DetectorResult"]
    severity: str = field(default=MEDIUM)


@dataclass(frozen=True)
class DetectorResult:
    count: int
    samples: list[str]


@dataclass
class AuditContext:
    """Passed to every detector. Carries paths + parsed config."""

    repo_root: pathlib.Path
    src_root: pathlib.Path
    tests_root: pathlib.Path
    config: dict
    plugin_modules: list


def run_audit(
    context: AuditContext,
    detectors: list[Detector],
    *,
    min_severity: str | None = None,
) -> AuditResult:
    """Run all detectors consistently so repos can compare outputs across runs.

    Args:
        context:      Audit context (repo root, config, etc.)
        detectors:    List of detectors to run.
        min_severity: If set, skip detectors whose severity is below this level.
                      Accepted values: "high", "medium", "low".
                      "high" runs only HIGH detectors; "medium" runs HIGH + MEDIUM;
                      "low" runs all (equivalent to not filtering).
    """
    cutoff = _SEVERITY_ORDER.get(min_severity or LOW, _SEVERITY_ORDER[LOW])

    result = AuditResult(repo_key=context.config.get("repo_key", ""))
    total = 0
    for detector in detectors:
        det_order = _SEVERITY_ORDER.get(detector.severity, _SEVERITY_ORDER[MEDIUM])
        if det_order > cutoff:
            continue
        detector_result = detector.detect(context)
        total += detector_result.count
        result.patterns[detector.id] = {
            "description": detector.description,
            "status": detector.status,
            "severity": detector.severity,
            "count": detector_result.count,
            "samples": detector_result.samples,
        }
    result.total_findings = total
    return result
