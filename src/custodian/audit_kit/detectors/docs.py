# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""K-class detectors — documentation consistency.

Detectors
─────────
K1  Doc phantom symbols — a backtick-quoted identifier in ``docs/`` or
    README that looks like a code symbol (lowercase, ≥8 chars, snake_case)
    but has no matching ``def``/``class``/field definition in ``src/``.
    Helps catch docs that reference renamed or removed functions. Lines
    in sections marked "deferred", "deprecated", or "out of scope" are
    skipped.  Configure ``audit.common_words`` and ``audit.stale_handlers``
    in ``.custodian.yaml`` to suppress known false positives.

K2  Doc value drift — a backtick-quoted lowercase token on a line that
    names a status/state/kind/priority value (e.g. "status: `pending`")
    but that token does not appear as a string literal anywhere in
    ``src/``.  Catches docs that cite stale enum values after a rename.
    Configure ``audit.known_values`` to suppress common English words
    that are not project-specific enum values.
"""
from __future__ import annotations

import re
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)
from custodian.audit_kit.code_health import _py_files

_MAX_SAMPLES = 8


def build_docs_detectors() -> list[Detector]:
    return [
        Detector("K1", "doc references a symbol not found in src (phantom symbol)", "open",
                 detect_k1, LOW),
        Detector("K2", "doc cites a value not present as string literal in src (value drift)", "open",
                 detect_k2, LOW),
    ]


# ── helpers ───────────────────────────────────────────────────────────────────

_DOC_SKIP_PARTS = frozenset({"history", "audits", "archive", "plans", "changelog", "specs"})


def _doc_files(repo_root: Path, audit_cfg: dict) -> list[Path]:
    """Collect docs/**/*.md + README.md, excluding volatile/historical subdirs.

    Skips ``history/``, ``audits/``, ``archive/``, ``plans/``, ``changelog/``
    subdirs — these reference future or removed symbols by design. Also skips
    any file whose name contains "changelog" (case-insensitive).
    """
    extra_doc_dirs: list[str] = list(audit_cfg.get("k1_extra_doc_dirs") or [])
    files: list[Path] = []
    readme = repo_root / "README.md"
    if readme.exists():
        files.append(readme)
    docs_root = repo_root / "docs"
    if docs_root.is_dir():
        files.extend(docs_root.rglob("*.md"))
    for d in extra_doc_dirs:
        extra = repo_root / d
        if extra.is_dir():
            files.extend(extra.rglob("*.md"))

    def _ok(f: Path) -> bool:
        parts_lower = {p.lower() for p in f.parts}
        if parts_lower & _DOC_SKIP_PARTS:
            return False
        if "changelog" in f.name.lower():
            return False
        return True

    return [f for f in files if _ok(f)]


def _build_src_text(context: AuditContext) -> tuple[str, str]:
    """Return concatenated src text and tests text."""
    src_text = ""
    for f in _py_files(context):
        try:
            src_text += f.read_text(errors="replace") + "\n"
        except OSError:
            continue
    tests_text = ""
    if context.tests_root.is_dir():
        for f in context.tests_root.rglob("*.py"):
            try:
                tests_text += f.read_text(errors="replace") + "\n"
            except OSError:
                continue
    return src_text, tests_text


_DEFERRED_WORDS = ("deferred", "out of scope", "not yet implemented", "future:", "deprecated")
_IMPL_MARKER_RE = re.compile(
    r"\*\*Files:\*\*|\bImplementation:|see\s+`|defined in `|"
    r"\b(?:def|class)\s+|`\s*\(.*?\)\s*",
    re.IGNORECASE,
)
_VALUE_CONTEXT_RE = re.compile(
    r"(?:status|state|kind|name|value|id|type|family|key|column)s?\s*[:=]|"
    r"(?:enum|constant|literal)|\bset\s+to\s+`|\bone\s+of\s+",
    re.IGNORECASE,
)
_SYM_RE = re.compile(r"`(_?[a-z][a-z0-9_]{7,})`")


# ── K1 ────────────────────────────────────────────────────────────────────────

def detect_k1(context: AuditContext) -> DetectorResult:
    """Flag backtick symbols in docs that have no def/class/field in src."""
    audit_cfg = context.config.get("audit") or {}
    common_words: set[str] = set(audit_cfg.get("common_words") or [])
    stale_handlers: set[str] = set(audit_cfg.get("stale_handlers") or [])

    src_text, tests_text = _build_src_text(context)

    def _exists(name: str) -> bool:
        if name in common_words or name in stale_handlers:
            return True
        if re.search(rf"\b(def|class)\s+{re.escape(name)}\b", src_text):
            return True
        if re.search(rf"^\s+{re.escape(name)}\s*:\s*[A-Za-z]", src_text, re.MULTILINE):
            return True
        if re.search(rf"\b(def|class)\s+{re.escape(name)}\b", tests_text):
            return True
        # Exists as a quoted string literal in src (e.g. dict key, enum value, config key)
        if re.search(rf"""['"]{re.escape(name)}['"]""", src_text):
            return True
        return False

    seen: dict[str, tuple[Path, int]] = {}
    for f in _doc_files(context.repo_root, audit_cfg):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        current_section_deferred = False
        for i, line in enumerate(text.splitlines(), 1):
            lower = line.lower()
            if line.startswith("#"):
                current_section_deferred = any(w in lower for w in _DEFERRED_WORDS)
                continue
            if current_section_deferred or any(w in lower for w in _DEFERRED_WORDS):
                continue
            if not _IMPL_MARKER_RE.search(line) or _VALUE_CONTEXT_RE.search(line):
                continue
            for m in _SYM_RE.finditer(line):
                name = m.group(1)
                if name not in seen and not _exists(name):
                    seen[name] = (f, i)

    samples = [
        f"{path.relative_to(context.repo_root)}:{ln}: `{name}` referenced but no def/class in src/"
        for name, (path, ln) in sorted(seen.items())
    ]
    return DetectorResult(count=len(seen), samples=samples[:_MAX_SAMPLES])


# ── K2 ────────────────────────────────────────────────────────────────────────

_VALUE_LINE_RE = re.compile(
    r"(?:status|state|kind|value|priority|severity|level|verdict|outcome)s?\s*"
    r"(?:[:=]|\bcan be\b|\bis\b|\bof\b)",
    re.IGNORECASE,
)
_VAL_SYM_RE = re.compile(r"`([a-z][a-z0-9_]{2,})`")

_DEFAULT_KNOWN_VALUES = {
    "ready for ai", "in review", "in progress", "backlog", "done",
    "cancelled", "blocked", "running", "awaiting input",
    "lgtm", "concerns", "approved", "rejected",
    "low", "medium", "high", "urgent", "none",
    "small", "large",
    "info", "warn", "warning", "error", "critical",
    "bool", "int", "str", "list", "dict", "tuple", "float", "bytes",
    # Standard library module names commonly cited in docs (not enum values)
    "fcntl", "subprocess", "logging", "pathlib", "datetime", "asyncio",
    "threading", "multiprocessing", "json", "yaml", "toml",
}


def detect_k2(context: AuditContext) -> DetectorResult:
    """Flag enum/status values in docs not found as string literals in src."""
    audit_cfg = context.config.get("audit") or {}
    extra_known: set[str] = {v.lower() for v in (audit_cfg.get("known_values") or [])}
    known_values = _DEFAULT_KNOWN_VALUES | extra_known

    src_text, _ = _build_src_text(context)

    seen: dict[str, tuple[Path, int]] = {}
    for f in _doc_files(context.repo_root, audit_cfg):
        try:
            text = f.read_text(errors="replace")
        except OSError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if not _VALUE_LINE_RE.search(line):
                continue
            for m in _VAL_SYM_RE.finditer(line):
                name = m.group(1)
                if name in seen or name.lower() in known_values:
                    continue
                if re.search(rf"""['"]{re.escape(name)}['"]""", src_text):
                    continue
                if re.search(rf"^\s+{re.escape(name)}\s*:\s*[A-Za-z]", src_text, re.MULTILINE):
                    continue
                if re.search(rf"\b(def|class)\s+{re.escape(name)}\b", src_text):
                    continue
                seen[name] = (f, i)

    samples = [
        f"{path.relative_to(context.repo_root)}:{ln}: `{name}` cited as value but no string literal in src/"
        for name, (path, ln) in sorted(seen.items())
    ]
    return DetectorResult(count=len(seen), samples=samples[:_MAX_SAMPLES])
