from __future__ import annotations

from pathlib import Path
import re

from custodian.audit_kit.detector import AuditContext, Detector, DetectorResult


def _py_files(root: Path) -> list[Path]:
    return [path for path in root.rglob("*.py") if path.is_file()]


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
    return _count_pattern(_py_files(context.src_root), re.compile(r"TODO"))


def detect_c2(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context.src_root), re.compile(r"\bprint\("))


def detect_c3(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context.src_root), re.compile(r"except\s*:\s*"))


def detect_c4(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context.src_root), re.compile(r"except[^\n]*:\n\s+pass"))


def detect_c5(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context.src_root), re.compile(r"(pdb\.set_trace|breakpoint\()"))


def detect_c6(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context.src_root), re.compile(r"FIXME"))


def detect_c7(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context.tests_root), re.compile(r"assert\s+True"))


def detect_c8(context: AuditContext) -> DetectorResult:
    stale_handlers = set(context.config.get("audit", {}).get("stale_handlers", []))
    common_words = set(context.config.get("audit", {}).get("common_words", []))
    samples: list[str] = []
    count = 0
    for path in _py_files(context.src_root):
        text = path.read_text(encoding="utf-8")
        for handler in stale_handlers:
            if handler in text and handler not in common_words:
                count += 1
                if len(samples) < 5:
                    samples.append(f"{path}:{handler}")
    return DetectorResult(count=count, samples=samples)
