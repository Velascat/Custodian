from __future__ import annotations

import fnmatch
from pathlib import Path
import re

from custodian.audit_kit.detector import AuditContext, Detector, DetectorResult


def _exclude_globs(context: AuditContext, detector_id: str) -> list[str]:
    """Per-detector path exclusions from `.custodian.yaml`.

    Schema:
        audit:
          exclude_paths:
            C2: ["src/cli/**", "src/foo/cli.py"]

    Globs are matched against each file's path relative to ``repo_root``
    via fnmatch. A file is excluded if any glob matches. Repos use this
    to opt specific files out of a generic detector that doesn't fit
    (e.g. C2 'print statements' is wrong for a CLI tool's command files).
    """
    audit_cfg = context.config.get("audit", {}) or {}
    exclude = audit_cfg.get("exclude_paths", {}) or {}
    return list(exclude.get(detector_id, []) or [])


def _py_files(context: AuditContext, detector_id: str | None = None) -> list[Path]:
    """All .py files under ``src_root``, minus any matched by exclude globs."""
    paths = [path for path in context.src_root.rglob("*.py") if path.is_file()]
    if detector_id is None:
        return paths
    globs = _exclude_globs(context, detector_id)
    if not globs:
        return paths
    repo_root = context.repo_root
    kept: list[Path] = []
    for p in paths:
        rel = str(p.relative_to(repo_root))
        if any(fnmatch.fnmatch(rel, g) for g in globs):
            continue
        kept.append(p)
    return kept


def _count_pattern(paths: list[Path], pattern: re.Pattern[str]) -> DetectorResult:
    samples: list[str] = []
    count = 0
    for path in paths:
        text = path.read_text(encoding="utf-8")
        for match in pattern.finditer(text):
            count += 1
            if len(samples) < 5:
                samples.append(f"{path}:{match.group(0)[:60]}")
    return DetectorResult(count=count, samples=samples)


def build_code_health_detectors() -> list[Detector]:
    return [
        Detector("C1", "TODO markers in source", "open", detect_c1),
        Detector("C2", "print statements in source", "open", detect_c2),
        Detector("C3", "bare except usage", "open", detect_c3),
        Detector("C4", "pass statements in exception handlers", "partial", detect_c4),
        Detector("C5", "debugger breakpoints", "open", detect_c5),
        Detector("C6", "FIXME markers", "open", detect_c6),
        Detector("C7", "assert True usage", "deferred", detect_c7),
        Detector("C8", "stale handler references", "partial", detect_c8),
    ]


def detect_c1(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context, "C1"), re.compile(r"TODO"))


def detect_c2(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context, "C2"), re.compile(r"\bprint\("))


def detect_c3(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context, "C3"), re.compile(r"except\s*:\s*"))


def detect_c4(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context, "C4"), re.compile(r"except[^\n]*:\n\s+pass"))


def detect_c5(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context, "C5"), re.compile(r"(pdb\.set_trace|breakpoint\()"))


def detect_c6(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context, "C6"), re.compile(r"FIXME"))


def detect_c7(context: AuditContext) -> DetectorResult:
    # tests_root, not src_root — excludes still scan tests via repo-relative globs.
    paths = [path for path in context.tests_root.rglob("*.py") if path.is_file()]
    globs = _exclude_globs(context, "C7")
    if globs:
        repo_root = context.repo_root
        paths = [p for p in paths
                 if not any(fnmatch.fnmatch(str(p.relative_to(repo_root)), g) for g in globs)]
    return _count_pattern(paths, re.compile(r"assert\s+True"))


def detect_c8(context: AuditContext) -> DetectorResult:
    stale_handlers = set(context.config.get("audit", {}).get("stale_handlers", []))
    common_words = set(context.config.get("audit", {}).get("common_words", []))
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C8"):
        text = path.read_text(encoding="utf-8")
        for handler in stale_handlers:
            if handler in text and handler not in common_words:
                count += 1
                if len(samples) < 5:
                    samples.append(f"{path}:{handler}")
    return DetectorResult(count=count, samples=samples)
