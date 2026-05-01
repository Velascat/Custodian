# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""D-class and F-class detectors — dead code and unused definitions.

Detectors
─────────
D1  Module-level functions defined but never called within the same
    codebase.  Uses the call-graph pass for cross-file analysis.
    Conservative: only flags non-private, non-test, non-main functions.
    Functions exported via ``__all__`` or used as decorators are excluded.

D2  Dead else after terminal if-branch — an else clause present when the
    if-body always exits (return/raise/break/continue).  The else is
    structurally unreachable via the if-path and can be deleted, flattening
    the indentation level.  Only flagged inside function bodies.

D3  Functions that never return normally — every code path ends with
    ``raise`` or a call to ``sys.exit``/``exit``/``quit``.  These should
    be annotated ``-> NoReturn``.  Functions already annotated NoReturn or
    Never are excluded.  Excludes @abstractmethod and Protocol methods.

D4  Unreachable code after unconditional return/raise/break/continue.
    Any statement following a terminal in the same block can never execute.
    Recurses into nested if/for/while/try/with bodies but not into nested
    function or class definitions (separate scopes).

D5  Module-level classes never referenced anywhere in the codebase.
    A class is dead if its name never appears as a Name Load in any
    scanned file — it is never instantiated, subclassed, used in
    isinstance(), used as a type annotation, or imported.  Complements D1.

D6  Module-level classes referenced (e.g. in type annotations or imports)
    but never instantiated (constructor never called) in the codebase.
    Complements D5: catches classes that exist in the type system but are
    never constructed — common with DTO classes defined for pipelines that
    are partially implemented.  Only flags classes whose name appears in
    called_names (referenced) but not in constructed_names (never called
    as a constructor).  Does NOT flag classes not in called_names — D5
    covers that case.

F1  ``@dataclass`` fields never accessed as attributes anywhere in the
    codebase.  Uses the call-graph pass to collect all attribute accesses.
    Conservative: only flags fields whose name does not appear in any
    attribute-load expression across all source files.

F2  Private module-level constant defined but never referenced in the same
    file.  Matches _ALL_CAPS names at module scope.  Names in ``__all__``
    are excluded (they may be imported by consumers).
"""
from __future__ import annotations

import ast
import re
from pathlib import Path

from custodian.audit_kit.detector import (
    AuditContext, Detector, DetectorResult, LOW, MEDIUM,
)

_MAX_SAMPLES = 8
_NEEDS_AST = frozenset({"ast_forest"})
_NEEDS_CG  = frozenset({"call_graph"})
_PRIVATE_CAPS = re.compile(r"^_[A-Z][A-Z0-9_]*$")

# Module-level function names that should never be flagged as dead.
_NEVER_DEAD = frozenset({
    "main", "setup", "teardown", "conftest",
    "__main__", "app", "create_app", "get_app",
})


_NEEDS_CG_AND_AST = frozenset({"call_graph", "ast_forest"})


def build_dead_code_detectors() -> list[Detector]:
    return [
        Detector("D1", "module-level function defined but never called in codebase", "open",
                 detect_d1, LOW, _NEEDS_CG),
        Detector("D2", "unnecessary else after terminal if-branch", "open",
                 detect_d2, LOW, _NEEDS_AST),
        Detector("D3", "function never returns normally — missing -> NoReturn", "open",
                 detect_d3, LOW, _NEEDS_AST),
        Detector("D4", "unreachable code after return/raise/break/continue", "open",
                 detect_d4, MEDIUM, _NEEDS_AST),
        Detector("D5", "module-level class never referenced in codebase", "open",
                 detect_d5, LOW, _NEEDS_CG_AND_AST),
        Detector("D6", "class defined but never instantiated (constructor never called)", "open",
                 detect_d6, LOW, _NEEDS_CG_AND_AST),
        Detector("F1", "dataclass field never accessed as attribute in codebase", "open",
                 detect_f1, LOW, _NEEDS_CG),
        Detector("F2", "private module-level constant defined but never referenced", "open",
                 detect_f2, LOW, _NEEDS_AST),
    ]


# ── D1 ────────────────────────────────────────────────────────────────────────

def detect_d1(context: AuditContext) -> DetectorResult:
    """Flag module-level functions never called anywhere in the codebase."""
    if context.graph is None or context.graph.call_graph is None:
        return DetectorResult(count=0, samples=[])

    cg = context.graph.call_graph
    all_calls = cg.called_names | cg.called_attrs | cg.decorated_names

    samples: list[str] = []
    count = 0

    for name in sorted(cg.module_functions):
        if name.startswith("_"):
            continue
        if name.startswith("test_"):
            continue
        if name in _NEVER_DEAD:
            continue
        if name in cg.defined_in_all:
            continue
        if name in all_calls:
            continue
        if name in cg.framework_decorated:
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(f"{name}() — defined but never called")

    return DetectorResult(count=count, samples=samples)


# ── D5 ────────────────────────────────────────────────────────────────────────

def detect_d5(context: AuditContext) -> DetectorResult:
    """Flag module-level classes never referenced anywhere in the codebase.

    A class is dead if its name never appears as a Name Load (instantiation,
    subclassing, isinstance(), type annotation, import) in any scanned file.
    The call_graph's Name Load tracking captures all of these forms.

    Skips:
    - Private classes (name starts with ``_``)
    - Classes exported via ``__all__``
    - Test classes (name starts with ``Test``)
    - Exception/Warning classes (name ends with Error/Exception/Warning/Fault)
      Note: raised/caught exceptions DO appear as Name Loads, so these are
      only excluded as a conservative hedge for exception hierarchies.
    """
    if (context.graph is None
            or context.graph.call_graph is None
            or context.graph.ast_forest is None):
        return DetectorResult(count=0, samples=[])

    cg = context.graph.call_graph
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        for stmt in tree.body:
            if not isinstance(stmt, ast.ClassDef):
                continue
            name = stmt.name
            if name.startswith("_"):
                continue
            if name in cg.defined_in_all:
                continue
            if name.startswith("Test"):
                continue
            if name.endswith(("Error", "Exception", "Warning", "Fault")):
                continue
            # Protocol subclasses are structural interfaces used only as type
            # annotations; with PEP 563 lazy evaluation those refs aren't Name Loads
            if any(
                (isinstance(b, ast.Name) and b.id in {"Protocol", "ABC"})
                or (isinstance(b, ast.Attribute) and b.attr in {"Protocol", "ABC"})
                for b in stmt.bases
            ):
                continue
            if name in cg.called_names:
                continue
            # Classes accessed via module alias (e.g. mod.ClassName) appear as
            # attribute loads, not Name Loads — check both attr sets
            if name in cg.called_attrs or name in cg.accessed_attrs:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(f"{rel}:{stmt.lineno}: class {name} — never referenced")

    return DetectorResult(count=count, samples=samples)


# ── D6 ────────────────────────────────────────────────────────────────────────

def detect_d6(context: AuditContext) -> DetectorResult:
    """Flag module-level classes referenced but never instantiated in the codebase.

    D6 complements D5: D5 catches classes that are never mentioned at all;
    D6 catches classes that appear in the type system (annotations, imports,
    isinstance checks) but whose constructor is never called anywhere.

    Only flags if:
    - name is in cg.called_names (referenced somewhere — D5 skips these)
    - name is NOT in cg.constructed_names (constructor never called)

    Same skips as D5: private, __all__, Test*, Error/Exception/Warning/Fault,
    Protocol/ABC base classes.
    """
    if (context.graph is None
            or context.graph.call_graph is None
            or context.graph.ast_forest is None):
        return DetectorResult(count=0, samples=[])

    cg = context.graph.call_graph
    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        for stmt in tree.body:
            if not isinstance(stmt, ast.ClassDef):
                continue
            name = stmt.name
            if name.startswith("_"):
                continue
            if name in cg.defined_in_all:
                continue
            if name.startswith("Test"):
                continue
            if name.endswith(("Error", "Exception", "Warning", "Fault")):
                continue
            if any(
                (isinstance(b, ast.Name) and b.id in {"Protocol", "ABC"})
                or (isinstance(b, ast.Attribute) and b.attr in {"Protocol", "ABC"})
                for b in stmt.bases
            ):
                continue
            # Only flag if referenced (in called_names) but never constructed
            if name not in cg.called_names:
                continue  # D5 covers this case
            if name in cg.constructed_names:
                continue
            count += 1
            if len(samples) < _MAX_SAMPLES:
                rel = path.relative_to(context.repo_root)
                samples.append(
                    f"{rel}:{stmt.lineno}: class {name} — never constructed (referenced in annotations/imports only)"
                )

    return DetectorResult(count=count, samples=samples)


# ── F1 ────────────────────────────────────────────────────────────────────────

_SERIALIZATION_METHODS = frozenset({"to_dict", "to_json", "asdict", "model_dump", "dict", "__dict__"})


def _dataclass_field_names(src_root: Path) -> set[str]:
    """Collect field names from @dataclass classes that lack serialization methods.

    Dataclasses with to_dict/to_json/model_dump/asdict methods expose all fields
    indirectly via serialization — we skip those to avoid false positives.
    """
    fields: set[str] = set()
    for path in sorted(src_root.rglob("*.py")):
        if not path.is_file():
            continue
        try:
            text = path.read_text(encoding="utf-8")
            tree = ast.parse(text, filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(
                (isinstance(d, ast.Name) and d.id == "dataclass")
                or (isinstance(d, ast.Attribute) and d.attr == "dataclass")
                for d in node.decorator_list
            ):
                continue
            # Skip dataclasses that expose fields via serialization methods
            method_names = {
                stmt.name
                for stmt in node.body
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if method_names & _SERIALIZATION_METHODS:
                continue
            for stmt in node.body:
                if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
                    fields.add(stmt.target.id)
                elif isinstance(stmt, ast.Assign):
                    for t in stmt.targets:
                        if isinstance(t, ast.Name) and not t.id.startswith("_"):
                            fields.add(t.id)
    return fields


def detect_f1(context: AuditContext) -> DetectorResult:
    """Flag @dataclass fields never accessed as attributes anywhere in the codebase."""
    if context.graph is None or context.graph.call_graph is None:
        return DetectorResult(count=0, samples=[])

    cg = context.graph.call_graph
    field_names = _dataclass_field_names(context.src_root)

    samples: list[str] = []
    count = 0

    for name in sorted(field_names):
        if name.startswith("_"):
            continue
        if name in cg.accessed_attrs:
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(f"{name} — dataclass field never accessed as attribute")

    return DetectorResult(count=count, samples=samples)


# ── AST helpers ───────────────────────────────────────────────────────────────

def _is_terminal(stmt: ast.stmt) -> bool:
    return isinstance(stmt, (ast.Return, ast.Raise, ast.Break, ast.Continue))


def _block_terminates(body: list[ast.stmt]) -> bool:
    return bool(body) and _is_terminal(body[-1])


def _stmts_of(stmt: ast.stmt) -> list[list[ast.stmt]]:
    """Return all nested statement lists within stmt (excluding function/class bodies)."""
    if isinstance(stmt, ast.If):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, (ast.For, ast.While)):
        return [stmt.body, stmt.orelse]
    if isinstance(stmt, ast.Try):
        nested = [stmt.body, stmt.orelse, stmt.finalbody]
        for h in stmt.handlers:
            nested.append(h.body)
        return nested
    if isinstance(stmt, ast.With):
        return [stmt.body]
    return []


# ── D3 helpers ────────────────────────────────────────────────────────────────

def _is_noreturn_call(stmt: ast.stmt) -> bool:
    """True for bare calls to sys.exit / exit / quit / os._exit."""
    if not isinstance(stmt, ast.Expr) or not isinstance(stmt.value, ast.Call):
        return False
    func = stmt.value.func
    if isinstance(func, ast.Name) and func.id in {"exit", "quit"}:
        return True
    if isinstance(func, ast.Attribute) and func.attr in {"exit", "_exit"}:
        return True
    return False


def _is_noreturn_terminal(stmt: ast.stmt) -> bool:
    return isinstance(stmt, ast.Raise) or _is_noreturn_call(stmt)


def _all_paths_noreturn(stmts: list[ast.stmt]) -> bool:
    """True if every code path through stmts ends in raise or a sys.exit-style call."""
    if not stmts:
        return False
    last = stmts[-1]
    if _is_noreturn_terminal(last):
        return True
    if isinstance(last, ast.If):
        # Without an else, the if-false path falls through — not NoReturn.
        if not last.orelse:
            return False
        return _all_paths_noreturn(last.body) and _all_paths_noreturn(last.orelse)
    if isinstance(last, ast.Try):
        if not _all_paths_noreturn(last.body):
            return False
        for handler in last.handlers:
            if not _all_paths_noreturn(handler.body):
                return False
        return True
    return False


def _has_decorator(func: ast.FunctionDef | ast.AsyncFunctionDef, *names: str) -> bool:
    for dec in func.decorator_list:
        dec_name = (dec.id if isinstance(dec, ast.Name)
                    else dec.attr if isinstance(dec, ast.Attribute) else None)
        if dec_name in names:
            return True
    return False


def _protocol_class_names(tree: ast.Module) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for base in node.bases:
                base_name = (base.id if isinstance(base, ast.Name)
                             else base.attr if isinstance(base, ast.Attribute) else None)
                if base_name == "Protocol":
                    names.add(node.name)
    return names


def _direct_class(
    func: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.Module,
) -> ast.ClassDef | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                if item is func:
                    return node
    return None


def _is_annotated_noreturn(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    ann = func.returns
    if ann is None:
        return False
    if isinstance(ann, ast.Name) and ann.id in {"NoReturn", "Never"}:
        return True
    if isinstance(ann, ast.Attribute) and ann.attr in {"NoReturn", "Never"}:
        return True
    return False


def _has_return_in_scope(stmts: list[ast.stmt]) -> bool:
    """True if stmts contains a Return statement not inside a nested function/class."""
    for stmt in stmts:
        if isinstance(stmt, ast.Return):
            return True
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue  # nested scope — do not descend
        # Recurse into compound statement blocks
        for nested in _stmts_of(stmt):
            if _has_return_in_scope(nested):
                return True
    return False


# ── D2 ────────────────────────────────────────────────────────────────────────

def _dead_else_nodes(stmts: list[ast.stmt]) -> list[ast.If]:
    """Recursively find ast.If nodes with a dead (redundant) else clause.

    Only flag when the if-body terminates but the else-body does NOT — this
    catches the guard-clause pattern where the else is pure indentation.
    When BOTH branches terminate (symmetric if/else), the else is intentional
    and is not flagged.
    """
    hits: list[ast.If] = []
    for stmt in stmts:
        if isinstance(stmt, ast.If):
            if (stmt.orelse
                    and not isinstance(stmt.orelse[0], ast.If)
                    and _block_terminates(stmt.body)
                    and not _block_terminates(stmt.orelse)):
                hits.append(stmt)
        for nested in _stmts_of(stmt):
            hits.extend(_dead_else_nodes(nested))
    return hits


def detect_d2(context: AuditContext) -> DetectorResult:
    """Flag else clauses that follow an if-body that always exits."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for hit in _dead_else_nodes(node.body):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{hit.lineno}: {node.name}() — else after terminal if"
                    )

    return DetectorResult(count=count, samples=samples)


# ── D3 ────────────────────────────────────────────────────────────────────────

def detect_d3(context: AuditContext) -> DetectorResult:
    """Flag functions that never return normally but lack -> NoReturn."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        protocol_names = _protocol_class_names(tree)

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if _has_decorator(node, "abstractmethod", "overload"):
                continue
            container = _direct_class(node, tree)
            if container and container.name in protocol_names:
                continue
            if _is_annotated_noreturn(node):
                continue
            if not node.body:
                continue
            if _has_return_in_scope(node.body):
                continue  # can return normally — not NoReturn
            if _all_paths_noreturn(node.body):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    samples.append(
                        f"{rel}:{node.lineno}: {node.name}() — never returns, missing -> NoReturn"
                    )

    return DetectorResult(count=count, samples=samples)


# ── D4 ────────────────────────────────────────────────────────────────────────

def _unreachable_stmts(stmts: list[ast.stmt]) -> list[ast.stmt]:
    """Find first unreachable statement in this block, then recurse into compounds."""
    results: list[ast.stmt] = []
    for i, stmt in enumerate(stmts):
        if _is_terminal(stmt) and i + 1 < len(stmts):
            results.append(stmts[i + 1])
            break
        for nested in _stmts_of(stmt):
            results.extend(_unreachable_stmts(nested))
    return results


def detect_d4(context: AuditContext) -> DetectorResult:
    """Flag statements that follow an unconditional return/raise/break/continue."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for hit in _unreachable_stmts(node.body):
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    lineno = getattr(hit, "lineno", node.lineno)
                    samples.append(
                        f"{rel}:{lineno}: {node.name}() — unreachable code"
                    )

    return DetectorResult(count=count, samples=samples)


# ── F2 ────────────────────────────────────────────────────────────────────────

def _private_constant_defs(tree: ast.Module) -> dict[str, ast.AST]:
    defs: dict[str, ast.AST] = {}
    for stmt in tree.body:
        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                if isinstance(target, ast.Name) and _PRIVATE_CAPS.match(target.id):
                    defs[target.id] = target
        elif isinstance(stmt, ast.AnnAssign):
            if isinstance(stmt.target, ast.Name) and _PRIVATE_CAPS.match(stmt.target.id):
                defs[stmt.target.id] = stmt.target
    return defs


def _module_all_exports(tree: ast.Module) -> set[str]:
    for stmt in tree.body:
        if not isinstance(stmt, ast.Assign):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "__all__" for t in stmt.targets):
            continue
        if isinstance(stmt.value, (ast.List, ast.Tuple)):
            return {
                elt.value
                for elt in stmt.value.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            }
    return set()


def _usage_counts(
    tree: ast.Module,
    names: set[str],
    exclude_node_ids: set[int],
) -> dict[str, int]:
    counts: dict[str, int] = {n: 0 for n in names}
    for node in ast.walk(tree):
        if isinstance(node, ast.Name) and node.id in counts and id(node) not in exclude_node_ids:
            counts[node.id] += 1
    return counts


def detect_f2(context: AuditContext) -> DetectorResult:
    """Flag private _ALL_CAPS module-level constants never referenced in their file."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        defs = _private_constant_defs(tree)
        if not defs:
            continue
        exports = _module_all_exports(tree)
        checkable = {k: v for k, v in defs.items() if k not in exports}
        if not checkable:
            continue

        def_node_ids = {id(n) for n in checkable.values()}
        usages = _usage_counts(tree, set(checkable), def_node_ids)

        for name, use_count in sorted(usages.items()):
            if use_count == 0:
                count += 1
                if len(samples) < _MAX_SAMPLES:
                    lineno = getattr(checkable[name], "lineno", 0)
                    rel = path.relative_to(context.repo_root)
                    samples.append(f"{rel}:{lineno}: {name} — defined but never used")

    return DetectorResult(count=count, samples=samples)
