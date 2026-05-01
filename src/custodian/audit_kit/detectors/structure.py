# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""S-class detectors — structural / architecture invariants.

These detectors require the ``import_graph`` analysis pass.  They answer
questions about relationships *between* modules rather than patterns within
a single file.

Detectors
─────────
S1  Layer boundary violations — files in a declared layer import from a
    layer they are forbidden to depend on.  Rules are expressed in
    ``.custodian.yaml`` under ``architecture.layers``.  If no rules are
    declared the detector silently reports 0 findings.

S2  Mutual imports — module A imports module B and module B imports module A
    (runtime imports only; TYPE_CHECKING-guarded imports are excluded).
    Mutual imports almost always indicate a design problem: the two modules
    should be merged, or one should expose an interface the other depends on.

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

from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW, MEDIUM,
)

if TYPE_CHECKING:
    from custodian.audit_kit.passes.import_graph import ImportGraph

_MAX_SAMPLES = 8
_NEEDS = frozenset({"import_graph"})


def build_structure_detectors() -> list[Detector]:
    return [
        Detector("S1", "architecture layer boundary violations", "open", detect_s1,
                 MEDIUM, _NEEDS),
        Detector("S2", "mutual imports (direct circular dependencies)", "open", detect_s2,
                 LOW, _NEEDS),
    ]


# ── helpers ──────────────────────────────────────────────────────────────────

def _glob_match(rel_path: Path, glob: str) -> bool:
    """Match a repo-relative path against a glob pattern.

    Uses PurePosixPath.match() which supports ``*`` (single component) and
    ``**`` (any number of components) in Python 3.12+.  Paths are normalised
    to POSIX form before matching.
    """
    return PurePosixPath(rel_path.as_posix()).match(glob)


def _any_glob(rel_path: Path, globs: list[str]) -> bool:
    return any(_glob_match(rel_path, g) for g in globs)


def _parse_layer_rules(config: dict) -> list[dict]:
    """Return the list of layer rule dicts from config, or []."""
    arch = config.get("architecture") or {}
    return list(arch.get("layers") or [])


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
