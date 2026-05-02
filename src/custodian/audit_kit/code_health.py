# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import ast
from pathlib import Path
import re

from custodian.audit_kit.detector import AuditContext, Detector, DetectorResult, HIGH, MEDIUM, LOW


def _glob_to_regex(glob: str) -> re.Pattern[str]:
    """Translate a path-style glob to a regex.

    Supports:
      ``*``    — any chars except path separator (``/``)
      ``/**/`` — zero or more directory segments (recursive marker)
      ``**``   — any chars including ``/`` (loose recursive form)
      ``?``    — any single char except ``/``

    Unlike stdlib ``fnmatch``, ``*`` here is path-component aware so
    ``src/foo/*.py`` matches ``src/foo/bar.py`` but **not**
    ``src/foo/sub/bar.py``. Use ``**`` for recursive intent.

    The ``/**/`` form is special-cased so ``src/pkg/**/*.py`` matches
    both ``src/pkg/leaf.py`` (zero dir segments) and
    ``src/pkg/sub/leaf.py`` (one or more).
    """
    # Pre-pass: collapse `/**/` to a sentinel that becomes `(?:/.*/|/)` —
    # this matches a single separator OR `/anything/`, i.e. zero or more
    # directory segments. Done before per-char processing so the special
    # form isn't mistaken for `**` followed by `/`.
    SENTINEL = "\x00DOUBLESTAR_DIR\x00"
    glob = glob.replace("/**/", SENTINEL)

    out: list[str] = []
    i = 0
    while i < len(glob):
        if glob.startswith(SENTINEL, i):
            out.append("(?:/.*/|/)")
            i += len(SENTINEL)
            continue
        ch = glob[i]
        if ch == "*":
            if i + 1 < len(glob) and glob[i + 1] == "*":
                out.append(".*")
                i += 2
                continue
            out.append("[^/]*")
        elif ch == "?":
            out.append("[^/]")
        else:
            out.append(re.escape(ch))
        i += 1
    return re.compile("\\A" + "".join(out) + "\\Z")


def _matches_any(rel_path: str, globs: list[str]) -> bool:
    return any(_glob_to_regex(g).match(rel_path) for g in globs)


def _exclude_globs(context: AuditContext, detector_id: str) -> list[str]:
    """Per-detector path exclusions from `.custodian.yaml`.

    Schema:
        audit:
          exclude_paths:
            C2: ["src/cli/**", "src/foo/cli.py"]

    Globs are matched against each file's path relative to ``repo_root``
    via the glob matcher above (`*` is path-aware, `**` is recursive).
    A file is excluded if any glob matches. Repos use this
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
        if _matches_any(rel, globs):
            continue
        kept.append(p)
    return kept


_MAX_SAMPLES = 8


_COMMENT_LINE_RE = re.compile(r"^\s*#.*$", re.MULTILINE)


def _strip_comment_lines(text: str) -> str:
    """Remove pure-comment lines (lines whose first non-whitespace char is '#')."""
    return _COMMENT_LINE_RE.sub("", text)


def _count_pattern(
    paths: list[Path],
    pattern: re.Pattern[str],
    *,
    skip_comment_lines: bool = False,
) -> DetectorResult:
    samples: list[str] = []
    count = 0
    for path in paths:
        try:
            raw = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        text = _strip_comment_lines(raw) if skip_comment_lines else raw
        for match in pattern.finditer(text):
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{path}:{match.group(0)[:60]}")
    return DetectorResult(count=count, samples=samples)


def build_code_health_detectors() -> list[Detector]:
    D = Detector
    return [
        D("C1",  "TODO markers in source",                                          "open",    detect_c1,   LOW),
        D("C6",  "FIXME markers",                                                   "open",    detect_c6,   LOW),
        D("C8",  "stale handler references",                                        "partial", detect_c8,   MEDIUM),
        D("C11", "subprocess call without timeout",                                 "open",    detect_c11,  MEDIUM),
        D("C28", "hardcoded IP address in string literal",                          "open",    detect_c28,  LOW),
        D("C29", "file exceeds line-count threshold",                               "open",    detect_c29,  LOW),
        D("C32", "hardcoded credential in assignment",                              "open",    detect_c32,  HIGH),
        D("C33", "file with high ghost-work comment density (TODO/FIXME/HACK/XXX)", "open",    detect_c33,  LOW),
    ]


def detect_c1(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context, "C1"), re.compile(r"TODO"))






def detect_c6(context: AuditContext) -> DetectorResult:
    return _count_pattern(_py_files(context, "C6"), re.compile(r"FIXME"))



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
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{path}:{handler}")
    return DetectorResult(count=count, samples=samples)


_SUBPROCESS_CALL_RE = re.compile(
    r"\bsubprocess\.(run|call|check_output|check_call)\s*\("
)


def _extract_call_body(text: str, start: int) -> str:
    """Return the full text of a function call starting at ``start``.

    ``start`` should point to the opening ``(`` or the function name.
    Tracks parenthesis depth to find the closing ``)``; does not handle
    string literals containing unmatched parens (good enough for subprocess).
    """
    depth = 0
    i = text.find("(", start)
    if i == -1:
        return ""
    for j, ch in enumerate(text[i:], i):
        if ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return text[i : j + 1]
    return text[i:]


def detect_c11(context: AuditContext) -> DetectorResult:
    """Flag ``subprocess.run/call/check_output/check_call`` calls without ``timeout=``.

    A subprocess without a timeout can hang indefinitely, blocking the
    calling process (and any polling worker that owns it).  Short-lived
    tool calls (git, ruff, etc.) should specify a conservative timeout;
    long-running agent invocations may legitimately omit one and should
    be excluded via ``audit.exclude_paths.C11`` in ``.custodian.yaml``.

    Detection extracts the full call body by tracking parenthesis depth,
    so multi-line calls are handled correctly.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C11"):
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        lines = text.splitlines()
        for m in _SUBPROCESS_CALL_RE.finditer(text):
            lineno = text[: m.start()].count("\n") + 1
            if lines[lineno - 1].lstrip().startswith("#"):
                continue
            call_body = _extract_call_body(text, m.start())
            if "timeout" in call_body:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(f"{rel}:{lineno}: {lines[lineno - 1].strip()[:60]}")
    return DetectorResult(count=count, samples=samples)












def detect_c28(context: AuditContext) -> DetectorResult:
    """Flag hardcoded IPv4 address literals in string constants.

    Hardcoded IPs couple code to a specific environment and are easy to
    overlook when infrastructure changes.  Use configuration, environment
    variables, or named constants instead.  ``127.0.0.1`` and ``0.0.0.0``
    (localhost/any-bind) are excluded as they are almost always intentional.
    """
    _EXCLUDED = {"127.0.0.1", "0.0.0.0", "127.0.0.0"}
    samples: list[str] = []
    count = 0
    _IP_IN_STRING = re.compile(r"""["'](\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})["']""")
    for path in _py_files(context, "C28"):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        for m in _IP_IN_STRING.finditer(text):
            ip = m.group(1)
            if ip in _EXCLUDED:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{path}:{m.group(0)[:40]}")
    return DetectorResult(count=count, samples=samples)


def detect_c29(context: AuditContext) -> DetectorResult:
    """Flag source files that exceed the line-count threshold.

    Very long files are hard to navigate and often indicate a missing
    abstraction boundary.  Default threshold: 500 lines.  Configurable:
        audit:
          c29_threshold: 800
    """
    audit_cfg = context.config.get("audit") or {}
    try:
        limit = int(audit_cfg.get("c29_threshold") or 500)
    except (TypeError, ValueError):
        limit = 500

    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C29"):
        try:
            n = path.read_text(encoding="utf-8").count("\n")
        except (OSError, UnicodeDecodeError):
            continue
        if n > limit:
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(f"{rel}: {n} lines (limit {limit})")
    return DetectorResult(count=count, samples=samples)


# ── C31: weak hash algorithms ─────────────────────────────────────────────────


# ── C32: hardcoded credentials ────────────────────────────────────────────────

_CREDENTIAL_NAMES = frozenset({
    "password", "passwd", "pwd", "secret", "token",
    "api_key", "apikey", "access_key", "private_key",
    "client_secret", "auth_token", "signing_key", "service_key",
    "credentials", "credential",
})

_CREDENTIAL_NAME_EXCLUSION_SUFFIXES = frozenset({
    "endpoint", "url", "uri", "path", "env", "var", "name", "param",
    "header", "field", "label",
})

_PLACEHOLDER_RE = re.compile(
    r"(?i)(your[-_]?|example|test[-_]?|dummy|fake|change[-_]?me|"
    r"replace|placeholder|xxx+|yyy+|aaa+|\$\{|<[^>]+>|todo|fixme)"
)

_ENV_VAR_RE = re.compile(r"^[A-Z][A-Z0-9_]+$")


def _is_credential_name(name: str) -> bool:
    """True if the variable/key name refers to an actual credential value.

    Uses word-boundary matching: splits on ``_``, ``.``, ``-`` and checks
    unigrams and bigrams against the credential name set.  Names whose last
    word is an exclusion suffix (endpoint, url, env, …) are skipped — they
    typically hold a URL or env-var name, not the secret itself.

    Examples that match:  password, api_key, client_secret, auth_token
    Examples that don't:  token_endpoint, word_tokenizer, secret_env
    """
    words = [w.lower().rstrip("s") for w in re.split(r"[_.\-]", name) if w]
    if not words:
        return False
    # If the last word is a non-credential suffix, this name is a URL/env ref
    if words[-1] in _CREDENTIAL_NAME_EXCLUSION_SUFFIXES:
        return False
    # Check unigrams
    if any(w in _CREDENTIAL_NAMES for w in words):
        return True
    # Check bigrams (api_key, access_key, client_secret, etc.)
    bigrams = ["_".join(words[i:i+2]) for i in range(len(words) - 1)]
    return any(b in _CREDENTIAL_NAMES for b in bigrams)


def _is_real_credential(value: str) -> bool:
    """Return True if value looks like an actual credential (not a placeholder)."""
    if not value or len(value) < 4:
        return False
    if _PLACEHOLDER_RE.search(value):
        return False
    # URL values are not credentials
    if value.startswith(("http://", "https://", "ftp://")):
        return False
    # ALL_CAPS values are env-var names pointing to where the secret lives
    if _ENV_VAR_RE.match(value):
        return False
    return True


def detect_c32(context: AuditContext) -> DetectorResult:
    """Flag assignments where a credential-named variable is set to a string literal.

    Detects patterns like:
        password = "actual_value"
        self.api_key = "sk-..."
        config = {"token": "live-secret"}

    Skips obvious placeholders ("your-token-here", "example", etc.) and
    very short values that are likely defaults or empty sentinels.
    """
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C32"):
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            # Variable assignments: password = "..."
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                value = node.value
                if not isinstance(value, ast.Constant) or not isinstance(value.value, str):
                    continue
                for target in targets:
                    name = None
                    if isinstance(target, ast.Name):
                        name = target.id
                    elif isinstance(target, ast.Attribute):
                        name = target.attr
                    if name and _is_credential_name(name) and _is_real_credential(value.value):
                        count += 1
                        if len(samples) < _MAX_SAMPLES:
                            samples.append(
                                f"{rel}:{node.lineno}: {name} = {value.value[:20]!r}..."
                                if len(value.value) > 20
                                else f"{rel}:{node.lineno}: {name} = {value.value!r}"
                            )
            # Dict literals: {"password": "...", "token": "..."}
            elif isinstance(node, ast.Dict):
                for key, val in zip(node.keys, node.values):
                    if not (isinstance(key, ast.Constant) and isinstance(key.value, str)):
                        continue
                    if not (isinstance(val, ast.Constant) and isinstance(val.value, str)):
                        continue
                    if _is_credential_name(key.value) and _is_real_credential(val.value):
                        count += 1
                        if len(samples) < _MAX_SAMPLES:
                            samples.append(
                                f"{rel}:{node.lineno}: dict key {key.value!r} = {val.value[:20]!r}..."
                                if len(val.value) > 20
                                else f"{rel}:{node.lineno}: dict key {key.value!r} = {val.value!r}"
                            )
    return DetectorResult(count=count, samples=samples)


# ── C33: ghost-work comment density ──────────────────────────────────────────

_GHOST_MARKER_RE = re.compile(r"#[^\n]*\b(TODO|FIXME|HACK|XXX|NOCOMMIT)\b", re.IGNORECASE)


def detect_c33(context: AuditContext) -> DetectorResult:
    """Flag files with a high density of ghost-work comment markers.

    Counts # TODO / FIXME / HACK / XXX / NOCOMMIT per file. Files at or
    above the threshold are flagged with their total count. The threshold
    is configurable via audit.c33_threshold in .custodian.yaml (default 5).
    """
    audit_cfg = context.config.get("audit") or {}
    threshold = int(audit_cfg.get("c33_threshold") or 5)
    samples: list[str] = []
    count = 0
    for path in _py_files(context, "C33"):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        markers = _GHOST_MARKER_RE.findall(text)
        if len(markers) >= threshold:
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(
                    f"{rel} — {len(markers)} ghost markers (TODO/FIXME/HACK/XXX)"
                )
    return DetectorResult(count=count, samples=samples)
