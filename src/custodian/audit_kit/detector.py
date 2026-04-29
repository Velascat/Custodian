from __future__ import annotations

from dataclasses import dataclass
import pathlib
from typing import Callable

from custodian.audit_kit.result import AuditResult


@dataclass
class Detector:
    """One audit pattern. id is repo-namespaced (e.g. "C1", "F3", "G12")."""

    id: str
    description: str
    status: str  # "fixed" | "open" | "partial" | "deferred"
    detect: Callable[["AuditContext"], "DetectorResult"]


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


def run_audit(context: AuditContext, detectors: list[Detector]) -> AuditResult:
    """Run all detectors consistently so repos can compare outputs across runs."""
    result = AuditResult(repo_key=context.config.get("repo_key", ""))
    total = 0
    for detector in detectors:
        detector_result = detector.detect(context)
        total += detector_result.count
        result.patterns[detector.id] = {
            "description": detector.description,
            "status": detector.status,
            "count": detector_result.count,
            "samples": detector_result.samples,
        }
    result.total_findings = total
    return result
