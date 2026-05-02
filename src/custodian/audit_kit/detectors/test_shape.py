# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""T-class detectors — test coverage shape.

Detectors
─────────
T1  Public src functions and classes with zero name references in tests.
    Uses the tests_forest pass to collect all ast.Name occurrences in
    test files, then flags public src symbols whose name never appears.
    Conservative: only checks module-level definitions, excludes private

T3  Unconditional pytest.skip() call or @pytest.mark.skip decorator with
    no environment-gate context in the surrounding lines. A skip that is
    not conditioned on a missing tool, platform, or env var silently
    drops test coverage permanently. Configure extra gate hints via
    ``audit.t3_env_gate_hints`` in ``.custodian.yaml``.

T4  Orphan pytest fixture — a function decorated with ``@pytest.fixture``
    that is never requested by any test function or other fixture.  An
    orphan fixture adds setup cost (import, potential side effects) but
    provides no coverage value.  Fixtures with ``autouse=True`` are
    excluded (they apply implicitly).  Built-in fixtures (``tmp_path``,
    ``capsys``, etc.) are not flagged because they are not defined in the
    codebase.  Fixtures defined in ``conftest.py`` are included in the
    search but so are their callers across the whole tests tree.
    names and dunder names.  LOW severity — indirect testing via wrappers
    and integration tests will produce false positives.

T2  Test functions with no assertion — a function whose name starts with
    ``test_`` and whose body contains no assertion mechanism.  Recognized
    assertion forms: ``assert`` statements, ``pytest.raises/warns/
    deprecated_call`` context managers, unittest-style ``self.assertX``
    / ``self.failX`` calls, and Mock-style ``mock.assert_called_once()``
    / ``mock.assert_not_called()`` / ``mock.assert_any_call()`` etc.
"""
from __future__ import annotations

import ast
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW,
)

_MAX_SAMPLES = 8
_NEEDS_TF = frozenset({"ast_forest", "tests_forest"})


def build_test_shape_detectors() -> list[Detector]:
    return [
        Detector("T1", "public src symbol with no reference in tests", "open",
                 detect_t1, LOW, _NEEDS_TF),
        Detector("T2", "test function with no assert statement", "open",
                 detect_t2, LOW),
        Detector("T3", "unconditional pytest.skip without environment gate", "open",
                 detect_t3, LOW),
        Detector("T4", "pytest fixture defined but never requested by any test or fixture", "open",
                 detect_t4, LOW),
    ]


# ── helpers ───────────────────────────────────────────────────────────────────

_PYTEST_ASSERTION_ATTRS = frozenset({
    "raises", "warns", "deprecated_call", "approx", "fail",
})

_MOCK_ASSERT_PREFIXES = ("assert_called", "assert_any_call", "assert_has_calls", "assert_not_called")


def _has_assertion_mechanism(node: ast.AST) -> bool:
    """True if the subtree contains any recognized assertion mechanism.

    Recognized forms:
    - ast.Assert (``assert x``)
    - pytest.raises / pytest.warns / etc. (``with pytest.raises(...):`` or call)
    - self.assertX / self.failX (unittest-style)
    - mock.assert_called_once() / mock.assert_not_called() / etc. (Mock-style)
    - raise AssertionError(...) — explicit assertion failure
    """
    for child in ast.walk(node):
        if isinstance(child, ast.Assert):
            return True
        # raise AssertionError(...) — explicit fail as assertion
        if isinstance(child, ast.Raise) and child.exc is not None:
            exc = child.exc
            if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                if exc.func.id == "AssertionError":
                    return True
        if not isinstance(child, ast.Call):
            continue
        func = child.func
        if not isinstance(func, ast.Attribute):
            continue
        attr = func.attr
        value = func.value
        # pytest.raises / pytest.warns / pytest.deprecated_call
        if isinstance(value, ast.Name) and value.id == "pytest":
            if attr in _PYTEST_ASSERTION_ATTRS:
                return True
        # self.assertX / self.failX (unittest)
        if isinstance(value, ast.Name) and value.id == "self":
            if attr.startswith("assert") or attr.startswith("fail"):
                return True
        # mock.assert_called_once() / mock.assert_not_called() / etc.
        if any(attr.startswith(p) for p in _MOCK_ASSERT_PREFIXES):
            return True
    # assert_*() module-level function calls (e.g. assert_no_mutation_fields(x))
    for child in ast.walk(node):
        if (
            isinstance(child, ast.Call)
            and isinstance(child.func, ast.Name)
            and child.func.id.startswith("assert_")
        ):
            return True
    return False


def _parse_test_files(tests_root: Path) -> list[tuple[Path, ast.Module]]:
    results: list[tuple[Path, ast.Module]] = []
    if not tests_root.is_dir():
        return results
    for path in sorted(tests_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        results.append((path, tree))
    return results


# ── T1 ────────────────────────────────────────────────────────────────────────

def _t1_excluded_paths(context: AuditContext) -> set[str]:
    """Repo-relative path strings excluded from T1 via audit.exclude_paths.T1."""
    from custodian.audit_kit.code_health import _glob_to_regex
    audit_cfg = context.config.get("audit") or {}
    globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T1") or [])
    if not globs:
        return set()
    patterns = [_glob_to_regex(g) for g in globs]
    excluded: set[str] = set()
    for path in context.src_root.rglob("*.py"):
        if not path.is_file():
            continue
        rel = path.relative_to(context.repo_root).as_posix()
        if any(p.match(rel) for p in patterns):
            excluded.add(str(path))
    return excluded


def detect_t1(context: AuditContext) -> DetectorResult:
    """Flag public src functions/classes whose name never appears in any test file."""
    if (context.graph is None
            or context.graph.ast_forest is None
            or context.graph.tests_forest is None):
        return DetectorResult(count=0, samples=[])

    # Collect every ast.Name id that appears anywhere in tests
    test_name_refs: set[str] = set()
    for _path, tree, _src in context.graph.tests_forest.items():
        for node in ast.walk(tree):
            if isinstance(node, ast.Name):
                test_name_refs.add(node.id)
            elif isinstance(node, ast.Attribute):
                test_name_refs.add(node.attr)

    excluded_paths = _t1_excluded_paths(context)
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        if str(path) in excluded_paths:
            continue
        rel = path.relative_to(context.repo_root)
        for stmt in tree.body:  # module-level only
            if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                continue
            name = stmt.name
            if name.startswith("_"):
                continue
            if name in test_name_refs:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                kind = "class" if isinstance(stmt, ast.ClassDef) else "def"
                samples.append(f"{rel}:{stmt.lineno}: {kind} {name} — no test reference")

    return DetectorResult(count=count, samples=samples)


# ── T2 ────────────────────────────────────────────────────────────────────────

def detect_t2(context: AuditContext) -> DetectorResult:
    """Flag test_ functions whose body contains no assert statement."""
    import fnmatch as _fnmatch
    audit_cfg: dict = context.config.get("audit") or {}
    t2_excludes: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T2") or [])

    samples: list[str] = []
    count = 0

    for path, tree in _parse_test_files(context.tests_root):
        rel = path.relative_to(context.repo_root)
        rel_posix = rel.as_posix()
        if t2_excludes and any(_fnmatch.fnmatch(rel_posix, excl) for excl in t2_excludes):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if not node.name.startswith("test_"):
                continue
            if not _has_assertion_mechanism(node):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{rel}:{node.lineno}: {node.name}() — no assert")

    return DetectorResult(count=count, samples=samples)


# ── T3 ────────────────────────────────────────────────────────────────────────

_DEFAULT_ENV_GATE_HINTS = (
    "os.environ", "os.getenv", "pytest.importorskip", "shutil.which",
    "sys.platform", "sys.version", "importlib", "skipif", "reason=",
    "not in fixture", "no records", "not present", "fixture",
)


def detect_t3(context: AuditContext) -> DetectorResult:
    """Flag pytest.skip() / @pytest.mark.skip without an environment-gate hint nearby.

    Scans a 7-line window (6 lines before the skip + the skip line itself) for
    any env-gate hint. Configurable extra hints via ``audit.t3_env_gate_hints``
    in ``.custodian.yaml``. Unconditional skips silently drop coverage; they
    should be guarded by an env/tool check or replaced with pytest.mark.xfail.
    """
    audit_cfg = context.config.get("audit") or {}
    extra_hints: list[str] = list(audit_cfg.get("t3_env_gate_hints") or [])
    hints = _DEFAULT_ENV_GATE_HINTS + tuple(extra_hints)

    samples: list[str] = []
    count = 0
    for path, _tree in _parse_test_files(context.tests_root):
        rel = path.relative_to(context.repo_root)
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            stripped = line.lstrip()
            is_call = "pytest.skip(" in line
            is_decorator = stripped.startswith("@pytest.mark.skip")
            if not is_call and not is_decorator:
                continue
            window = "\n".join(lines[max(0, i - 7): i])
            if any(h.lower() in window.lower() for h in hints):
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                samples.append(f"{rel}:{i}: {line.strip()[:80]}")
    return DetectorResult(count=count, samples=samples)


# ── T4 ────────────────────────────────────────────────────────────────────────

def _is_fixture_decorator(dec: ast.expr) -> bool:
    """Return True if the decorator is @pytest.fixture or @fixture (with or without args)."""
    if isinstance(dec, ast.Attribute) and dec.attr == "fixture":
        return True
    if isinstance(dec, ast.Name) and dec.id == "fixture":
        return True
    if isinstance(dec, ast.Call):
        return _is_fixture_decorator(dec.func)
    return False


def _fixture_is_autouse(dec: ast.expr) -> bool:
    """Return True if @pytest.fixture(autouse=True) is set."""
    if not isinstance(dec, ast.Call):
        return False
    for kw in dec.keywords:
        if kw.arg == "autouse" and isinstance(kw.value, ast.Constant) and kw.value.value:
            return True
    return False


def detect_t4(context: AuditContext) -> DetectorResult:
    """Flag pytest fixtures that are never requested by any test or other fixture.

    Collects all fixture names across the tests tree (including conftest.py),
    then collects all parameter names from test functions (``test_*``) and
    from other fixture functions.  A fixture whose name never appears in any
    parameter list is an orphan — it adds overhead but provides no coverage.

    Fixtures with ``autouse=True`` are skipped (they apply without being named).
    Exclude paths via ``audit.exclude_paths.T4``.
    """
    if not context.tests_root.is_dir():
        return DetectorResult(count=0, samples=[])

    audit_cfg = context.config.get("audit") or {}
    globs: list[str] = list((audit_cfg.get("exclude_paths") or {}).get("T4") or [])

    from pathlib import PurePosixPath

    # Pass 1: collect fixture definitions {name → (path, lineno)}
    fixture_defs: dict[str, tuple[Path, int]] = {}
    # Pass 2: collect all parameter names across test functions and fixtures
    requested_names: set[str] = set()

    all_files: list[tuple[Path, ast.Module]] = _parse_test_files(context.tests_root)

    for path, tree in all_files:
        rel_str = str(path.relative_to(context.repo_root))
        if globs and any(PurePosixPath(rel_str).match(g) for g in globs):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            name = node.name

            # Collect parameter names from test functions and fixture functions
            is_test = name.startswith("test_")
            is_fix = any(_is_fixture_decorator(d) for d in node.decorator_list)

            if is_test or is_fix:
                for arg in node.args.args + node.args.posonlyargs + node.args.kwonlyargs:
                    if arg.arg not in ("self", "cls"):
                        requested_names.add(arg.arg)

            # Register fixture definition
            if is_fix:
                if any(_fixture_is_autouse(d) for d in node.decorator_list):
                    continue  # autouse — doesn't need to be requested
                if name not in fixture_defs:
                    fixture_defs[name] = (path, node.lineno)

    # Plugin-consumed override fixtures that are implicitly used by third-party plugins
    # (anyio, asyncio, trio, pytest-asyncio) and never explicitly requested by tests.
    _PLUGIN_OVERRIDE_FIXTURES = frozenset({
        "anyio_backend", "event_loop", "event_loop_policy", "asyncio_mode",
    })

    # Orphans: defined fixtures never appearing in any parameter list
    orphans = {
        name: loc for name, loc in fixture_defs.items()
        if name not in requested_names and name not in _PLUGIN_OVERRIDE_FIXTURES
    }

    samples = [
        f"{loc[0].relative_to(context.repo_root)}:{loc[1]}: fixture {name}() — never requested"
        for name, loc in sorted(orphans.items(), key=lambda x: (str(x[1][0]), x[1][1]))
    ]
    return DetectorResult(count=len(orphans), samples=samples[:_MAX_SAMPLES])
