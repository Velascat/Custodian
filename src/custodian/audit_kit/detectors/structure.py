# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""S-class detectors — structural / architecture invariants.

These detectors require the ``import_graph`` analysis pass.  They answer
questions about relationships *between* modules rather than patterns within
a single file.

Detectors
─────────
A1  Architecture invariants — declarative YAML rules enforcing structural
    constraints per file/glob.  Rules are expressed in ``.custodian.yaml``
    under ``architecture.invariants``.  Each rule may enforce one of:
    max_lines, max_classes, max_functions, or forbidden_import.  If no
    invariants are declared the detector silently reports 0 findings.

S1  Layer boundary violations — files in a declared layer import from a
    layer they are forbidden to depend on.  Rules are expressed in
    ``.custodian.yaml`` under ``architecture.layers``.  If no rules are
    declared the detector silently reports 0 findings.

S2  Mutual imports — module A imports module B and module B imports module A
    (runtime imports only; TYPE_CHECKING-guarded imports are excluded).
    Mutual imports almost always indicate a design problem: the two modules
    should be merged, or one should expose an interface the other depends on.

S3  Test-only imports in production code — a ``src/`` file imports from a
    ``tests.*`` or ``test_*`` module.  Test utilities should not leak into
    production code; shared fixtures belong in a separate ``conftest.py``
    or helper package inside ``src/``.

S4  Missing venv guard in tests/conftest.py — the top-level conftest must
    contain a ``sys.prefix`` / ``_EXPECTED_VENV`` check so that tests cannot
    silently run against the wrong Python environment.  Absent guard means CI
    or a developer can run the suite with a foreign venv and get misleading
    green results from the wrong package versions.

Config example for S1::

    architecture:
      layers:
        - name: adapters
          glob: "src/myapp/adapters/**"
          may_not_import:
            - "src/myapp/entrypoints/**"
        - name: domain
          glob: "src/myapp/domain/**"
          may_not_import:
            - "src/myapp/adapters/**"
            - "src/myapp/entrypoints/**"

Globs are matched against file paths relative to repo_root.
"""
from __future__ import annotations

import ast
import fnmatch
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW, MEDIUM,
)

if TYPE_CHECKING:
    from custodian.audit_kit.passes.import_graph import ImportGraph

_MAX_SAMPLES = 8
_NEEDS = frozenset({"import_graph"})
_NEEDS_AST = frozenset({"ast_forest"})


def build_structure_detectors() -> list[Detector]:
    return [
        Detector("A1", "architecture invariant violation (max_lines/max_classes/forbidden_import)", "open",
                 detect_a1, MEDIUM, _NEEDS_AST),
        Detector("S1", "architecture layer boundary violations", "open", detect_s1,
                 MEDIUM, _NEEDS),
        Detector("S2", "mutual imports (direct circular dependencies)", "open", detect_s2,
                 LOW, _NEEDS),
        Detector("S3", "test-only import in production code", "open", detect_s3,
                 MEDIUM, _NEEDS_AST),
        Detector("S4", "tests/conftest.py missing venv guard", "open", detect_s4,
                 MEDIUM, frozenset()),
    ]


# ── helpers ──────────────────────────────────────────────────────────────────

def _glob_match(rel_path: Path, glob: str) -> bool:
    """Match a repo-relative path against a glob pattern.

    Uses fnmatch so that ``**`` matches any number of path components
    (including those with ``/`` separators), which pathlib.match() does not
    handle correctly for nested directories in Python 3.12.
    """
    return fnmatch.fnmatch(rel_path.as_posix(), glob)


def _any_glob(rel_path: Path, globs: list[str]) -> bool:
    return any(_glob_match(rel_path, g) for g in globs)


def _parse_layer_rules(config: dict) -> list[dict]:
    """Return the list of layer rule dicts from config, or []."""
    arch = config.get("architecture") or {}
    return list(arch.get("layers") or [])


def _parse_invariants(config: dict) -> list[dict]:
    """Return the list of architecture invariant dicts from config, or []."""
    arch = config.get("architecture") or {}
    return list(arch.get("invariants") or [])


# ── A1: architecture invariants ──────────────────────────────────────────────

def detect_a1(context: AuditContext) -> DetectorResult:
    """Flag files that violate declared architecture invariants.

    Rules are declared in .custodian.yaml under architecture.invariants.
    Each rule applies to files matching its glob and checks one constraint:
    max_lines, max_classes, max_functions, or forbidden_import.
    If no invariants are declared, silently returns 0 findings.
    """
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    invariants = _parse_invariants(context.config)
    if not invariants:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        rel_str = rel.as_posix()  # noqa: F841 — available for debug if needed

        for rule in invariants:
            glob = rule.get("glob") or ""
            if not glob or not _glob_match(rel, glob):
                continue
            name = rule.get("name") or glob

            # max_lines
            if "max_lines" in rule:
                limit = int(rule["max_lines"])
                actual = len(src.splitlines())
                if actual > limit:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel}:{actual} lines — exceeds {name!r} limit of {limit}"
                        )

            # max_classes
            if "max_classes" in rule:
                limit = int(rule["max_classes"])
                actual = sum(1 for n in ast.walk(tree) if isinstance(n, ast.ClassDef))
                if actual > limit:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel}:{actual} classes — exceeds {name!r} limit of {limit}"
                        )

            # max_functions (module-level only)
            if "max_functions" in rule:
                limit = int(rule["max_functions"])
                actual = sum(
                    1 for s in tree.body
                    if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
                )
                if actual > limit:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        samples.append(
                            f"{rel}:{actual} functions — exceeds {name!r} limit of {limit}"
                        )

            # forbidden_import — glob match against dotted module path (dots → slashes)
            if "forbidden_import" in rule:
                pattern = rule["forbidden_import"]
                path_pattern = pattern.replace(".", "/")
                for node in ast.walk(tree):
                    mod = None
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            mod_as_path = alias.name.replace(".", "/")
                            if _glob_match(Path(mod_as_path), path_pattern):
                                mod = alias.name
                                break
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        mod_as_path = node.module.replace(".", "/")
                        if _glob_match(Path(mod_as_path), path_pattern):
                            mod = node.module
                    if mod:
                        count += 1
                        if len(samples) < _MAX_SAMPLES:
                            samples.append(
                                f"{rel}:{node.lineno}: imports {mod!r} — forbidden by {name!r}"
                            )
                        break  # one violation per rule per file is enough

            # forbidden_import_prefix — prefix match (exact or sub-module).
            # Use this instead of forbidden_import when you want to catch both
            # `import foo` and `from foo.bar import baz` with a single rule.
            if "forbidden_import_prefix" in rule:
                prefix = rule["forbidden_import_prefix"]
                prefix_path = prefix.replace(".", "/")
                for node in ast.walk(tree):
                    mod = None
                    if isinstance(node, ast.Import):
                        for alias in node.names:
                            mp = alias.name.replace(".", "/")
                            if mp == prefix_path or mp.startswith(prefix_path + "/"):
                                mod = alias.name
                                break
                    elif isinstance(node, ast.ImportFrom) and node.module:
                        mp = node.module.replace(".", "/")
                        if mp == prefix_path or mp.startswith(prefix_path + "/"):
                            mod = node.module
                    if mod:
                        count += 1
                        if len(samples) < _MAX_SAMPLES:
                            samples.append(
                                f"{rel}:{node.lineno}: imports {mod!r} — forbidden prefix {prefix!r}"
                            )
                        break  # one violation per rule per file is enough

    return DetectorResult(count=count, samples=samples)


# ── S1: layer boundary violations ────────────────────────────────────────────

def detect_s1(context: AuditContext) -> DetectorResult:
    if context.graph is None or context.graph.import_graph is None:
        return DetectorResult(count=0, samples=[])

    rules = _parse_layer_rules(context.config)
    if not rules:
        return DetectorResult(count=0, samples=[])

    graph = context.graph.import_graph
    samples: list[str] = []
    count = 0

    for rel_path, imported_modules in graph.imports.items():
        # Which layer does this file belong to?
        src_layer = _find_layer(rel_path, rules)
        if src_layer is None:
            continue
        forbidden_globs: list[str] = src_layer.get("may_not_import") or []
        if not forbidden_globs:
            continue

        for mod_name in sorted(imported_modules):
            # Resolve the imported module to a file path in our repo
            imported_path = graph.module_to_path.get(mod_name)
            if imported_path is None:
                # External dependency — not subject to layer rules
                continue
            if _any_glob(imported_path, forbidden_globs):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    src_layer_name = src_layer.get("name", "?")
                    imp_str = f"{rel_path} → {imported_path}"
                    samples.append(
                        f"[{src_layer_name}] {imp_str}"
                    )

    return DetectorResult(count=count, samples=samples)


def _find_layer(rel_path: Path, rules: list[dict]) -> dict | None:
    """Return the first layer whose glob matches rel_path, or None."""
    for rule in rules:
        globs = rule.get("glob") or rule.get("globs") or []
        if isinstance(globs, str):
            globs = [globs]
        if _any_glob(rel_path, globs):
            return rule
    return None


# ── S2: mutual imports ────────────────────────────────────────────────────────

def detect_s2(context: AuditContext) -> DetectorResult:
    """Flag pairs of modules that import each other at runtime.

    Only runtime imports are checked (TYPE_CHECKING-guarded imports are
    excluded).  The pair is reported once, with the module containing the
    first alphabetical import listed first.
    """
    if context.graph is None or context.graph.import_graph is None:
        return DetectorResult(count=0, samples=[])

    graph = context.graph.import_graph
    # Build module-name → module-name edges (intra-repo only)
    local_modules = graph.all_local_modules()
    # mod_name -> set of mod_names it imports (local only)
    runtime_edges: dict[str, set[str]] = {}
    for rel_path, imports in graph.imports.items():
        mod = graph.path_to_module.get(rel_path)
        if not mod:
            continue
        local_imports = set()
        for imp in imports:
            # Match exact or as prefix (e.g. "ops.adapters" imports "ops.adapters.plane")
            if imp in local_modules:
                local_imports.add(imp)
            else:
                # Check if any local module starts with imp + "."
                for local in local_modules:
                    if local.startswith(imp + ".") or local == imp:
                        local_imports.add(local)
        runtime_edges[mod] = local_imports

    samples: list[str] = []
    count = 0
    seen: set[frozenset[str]] = set()

    for mod_a, imports_a in sorted(runtime_edges.items()):
        for mod_b in sorted(imports_a):
            if mod_b == mod_a:  # self-import from relative resolution
                continue
            if mod_b not in runtime_edges:
                continue
            if mod_a in runtime_edges.get(mod_b, set()):
                pair = frozenset({mod_a, mod_b})
                if pair in seen:
                    continue
                seen.add(pair)
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    path_a = graph.module_to_path.get(mod_a, Path(mod_a))
                    path_b = graph.module_to_path.get(mod_b, Path(mod_b))
                    samples.append(f"{path_a} ↔ {path_b}")

    return DetectorResult(count=count, samples=samples)


# ── S3: test-only imports in production code ──────────────────────────────────

def _is_test_module(name: str) -> bool:
    """True if the top-level component of a module name is test-related."""
    top = name.split(".")[0]
    return top in {"tests", "test"} or top.startswith("test_")


def detect_s3(context: AuditContext) -> DetectorResult:
    """Flag production modules that import from test packages or test_* modules.

    Test utilities must not leak into src/: shared helpers should live in
    src/ or be exposed via conftest.py.
    """
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            module_name: str | None = None
            lineno: int = 0
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if _is_test_module(alias.name):
                        module_name = alias.name
                        lineno = node.lineno
                        break
            elif isinstance(node, ast.ImportFrom):
                if node.module and _is_test_module(node.module):
                    module_name = node.module
                    lineno = node.lineno
            if module_name:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(f"{rel}:{lineno}: imports {module_name!r}")

    return DetectorResult(count=count, samples=samples)


# ── S4: missing venv guard in tests/conftest.py ────────────────────────────────

_VENV_GUARD_MARKERS = ("sys.prefix", "_EXPECTED_VENV", "ACTIVE_PREFIX", "active_prefix")


def detect_s4(context: AuditContext) -> DetectorResult:
    """Flag repos whose tests/conftest.py lacks a venv guard.

    A valid guard checks that the active Python environment matches the repo's
    own .venv, preventing silent test runs against the wrong package set.
    Skipped when tests_root does not exist (no tests directory).
    """
    tests_root = context.tests_root
    if tests_root is None or not tests_root.is_dir():
        return DetectorResult(count=0, samples=[])

    # Check both tests_root/conftest.py and repo_root/conftest.py — some repos
    # put the guard at the project root when pytest rootdir is the repo root.
    candidates = [tests_root / "conftest.py", context.repo_root / "conftest.py"]
    for candidate in candidates:
        if candidate.exists():
            try:
                content = candidate.read_text(encoding="utf-8")
            except OSError:
                continue
            if any(marker in content for marker in _VENV_GUARD_MARKERS):
                return DetectorResult(count=0, samples=[])

    # Neither candidate has a guard
    conftest = tests_root / "conftest.py"
    if not conftest.exists():
        root_conftest = context.repo_root / "conftest.py"
        if not root_conftest.exists():
            rel = str(conftest.relative_to(context.repo_root))
            return DetectorResult(count=1, samples=[f"{rel}: file missing — add conftest.py with venv guard"])

    rel = str(conftest.relative_to(context.repo_root)) if conftest.exists() else "conftest.py"
    return DetectorResult(
        count=1,
        samples=[f"{rel}: no venv guard — add sys.prefix / _EXPECTED_VENV check"],
    )
