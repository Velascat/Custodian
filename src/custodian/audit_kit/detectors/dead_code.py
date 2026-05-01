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

D7  A function/method parameter that is never referenced in the function
    body.  Only checks regular params (not *args/**kwargs).  Skips self,
    cls, underscore-prefixed params, functions with **kwargs (dynamic
    forwarding), and stub bodies (abstractmethod, overload, pass/ellipsis).

F1  ``@dataclass`` fields never accessed as attributes anywhere in the
    codebase.  Uses the call-graph pass to collect all attribute accesses.
    Conservative: only flags fields whose name does not appear in any
    attribute-load expression across all source files.

F2  Private module-level constant defined but never referenced in the same
    file.  Matches _ALL_CAPS names at module scope.  Names in ``__all__``
    are excluded (they may be imported by consumers).

F3  Pydantic ``BaseModel`` / ``BaseSettings`` fields never accessed as
    attributes anywhere in the codebase.  Uses the call-graph pass to
    collect attribute accesses.  Skips private fields and classes that
    expose all fields via serialization methods (model_dump/dict/to_dict).
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
        Detector("D7", "method parameter defined but never used in function body", "open",
                 detect_d7, LOW, _NEEDS_AST),
        Detector("F1", "dataclass field never accessed as attribute in codebase", "open",
                 detect_f1, LOW, _NEEDS_CG),
        Detector("F3", "BaseModel field never accessed as attribute in codebase", "open",
                 detect_f3, LOW, _NEEDS_CG),
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


_D5_D6_SKIP_BASES = frozenset({
    "Protocol", "ABC",          # structural typing / abstract
    "BaseModel", "BaseSettings", "TypedDict",  # Pydantic — deserialized, not constructed directly
})

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
            if any(
                (isinstance(b, ast.Name) and b.id in _D5_D6_SKIP_BASES)
                or (isinstance(b, ast.Attribute) and b.attr in _D5_D6_SKIP_BASES)
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
                (isinstance(b, ast.Name) and b.id in _D5_D6_SKIP_BASES)
                or (isinstance(b, ast.Attribute) and b.attr in _D5_D6_SKIP_BASES)
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


# ── D7 ────────────────────────────────────────────────────────────────────────

def _is_stub_body(body: list[ast.stmt]) -> bool:
    """True if the function body is a stub (pass, ellipsis, raise NotImplementedError, or docstring-only)."""
    if not body:
        return True
    s = body[0]
    # Pure ellipsis: ...
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and s.value.value is ...:
        return True
    # Docstring-only or docstring + ellipsis/pass
    if isinstance(s, ast.Expr) and isinstance(s.value, ast.Constant) and isinstance(s.value.value, str):
        rest = body[1:]
        if not rest:
            return True
        if len(rest) == 1:
            r = rest[0]
            if isinstance(r, ast.Expr) and isinstance(r.value, ast.Constant) and r.value.value is ...:
                return True
            if isinstance(r, ast.Pass):
                return True
            if _is_raise_not_implemented(r):
                return True
    if len(body) == 1 and isinstance(body[0], ast.Pass):
        return True
    # raise NotImplementedError(...) — unimplemented stub
    if len(body) == 1 and _is_raise_not_implemented(body[0]):
        return True
    return False


def _is_raise_not_implemented(stmt: ast.stmt) -> bool:
    """True if *stmt* is ``raise NotImplementedError(...)`` or ``raise NotImplementedError``."""
    if not isinstance(stmt, ast.Raise) or stmt.exc is None:
        return False
    exc = stmt.exc
    # raise NotImplementedError
    if isinstance(exc, ast.Name) and exc.id == "NotImplementedError":
        return True
    # raise NotImplementedError(...)
    if (isinstance(exc, ast.Call)
            and isinstance(exc.func, ast.Name)
            and exc.func.id == "NotImplementedError"):
        return True
    return False


def detect_d7(context: AuditContext) -> DetectorResult:
    """Flag function/method parameters that are never referenced in the function body."""
    if context.graph is None or context.graph.ast_forest is None:
        return DetectorResult(count=0, samples=[])

    samples: list[str] = []
    count = 0

    for path, tree, _src in context.graph.ast_forest.items():
        rel = path.relative_to(context.repo_root)
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            # Skip stubs: abstractmethod, overload, override decorators
            if _has_decorator(node, "abstractmethod", "overload", "override"):
                continue
            # Skip stub bodies
            if _is_stub_body(node.body):
                continue
            # Skip dunder methods — params are protocol-required (__exit__, __getitem__, etc.)
            if node.name.startswith("__") and node.name.endswith("__"):
                continue
            # Skip functions with **kwargs (dynamic forwarding pattern)
            if node.args.kwarg is not None:
                continue
            # Collect all regular params (not *args / **kwargs)
            params = (
                node.args.posonlyargs
                + node.args.args
                + node.args.kwonlyargs
            )
            # Filter out self, cls, and underscore-prefixed params
            checkable = [
                arg for arg in params
                if arg.arg not in ("self", "cls") and not arg.arg.startswith("_")
            ]
            if not checkable:
                continue
            # Collect all Name Load/Del nodes in the function body
            # del var counts as intentional acknowledgement of the param
            used_names: set[str] = set()
            for stmt in node.body:
                for n in ast.walk(stmt):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Load, ast.Del)):
                        used_names.add(n.id)
            # Flag params not appearing as Name Loads in the body
            for arg in checkable:
                if arg.arg not in used_names:
                    count += 1
                    if len(samples) < _MAX_SAMPLES:
                        lineno = getattr(arg, "lineno", node.lineno)
                        samples.append(
                            f"{rel}:{lineno}: "
                            f"{node.name}() — parameter '{arg.arg}' never used"
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
        if name in cg.kw_arg_names:  # set via SomeClass(field=value) — still in use
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(f"{name} — dataclass field never accessed as attribute")

    return DetectorResult(count=count, samples=samples)


# ── F3 ────────────────────────────────────────────────────────────────────────

_PYDANTIC_BASES = frozenset({"BaseModel", "BaseSettings"})
_PYDANTIC_VALIDATOR_DECORATORS = frozenset({"validator", "field_validator", "model_validator"})


def _pydantic_field_names(src_root: Path) -> dict[str, set[str]]:
    """Collect annotated field names from BaseModel/BaseSettings subclasses.

    Returns a mapping of field_name → set of class names that declare it.

    Skips:
    - Classes with serialization methods (model_dump/dict/to_dict) — all fields
      exposed indirectly via serialization.
    - Private fields (starting with ``_``).
    - Fields that are decorated (validators, class methods, etc.).
    """
    fields: dict[str, set[str]] = {}
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
            # Only consider direct BaseModel/BaseSettings subclasses
            if not any(
                (isinstance(b, ast.Name) and b.id in _PYDANTIC_BASES)
                or (isinstance(b, ast.Attribute) and b.attr in _PYDANTIC_BASES)
                for b in node.bases
            ):
                continue
            # Skip classes that expose all fields via serialization
            method_names = {
                stmt.name
                for stmt in node.body
                if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef))
            }
            if method_names & _SERIALIZATION_METHODS:
                continue
            # Collect decorated names (validators) to skip
            decorated_names: set[str] = set()
            for stmt in node.body:
                if not isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue
                for dec in stmt.decorator_list:
                    dec_name = (
                        dec.id if isinstance(dec, ast.Name)
                        else dec.attr if isinstance(dec, ast.Attribute)
                        else dec.func.id if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name)
                        else dec.func.attr if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute)
                        else None
                    )
                    if dec_name in _PYDANTIC_VALIDATOR_DECORATORS:
                        decorated_names.add(stmt.name)
            # Collect AnnAssign fields (Pydantic v2 style)
            for stmt in node.body:
                if not isinstance(stmt, ast.AnnAssign):
                    continue
                if not isinstance(stmt.target, ast.Name):
                    continue
                name = stmt.target.id
                if name.startswith("_"):
                    continue
                if name in decorated_names:
                    continue
                fields.setdefault(name, set()).add(node.name)
    return fields


def _expand_model_validate_classes(src_root: Path, seed: set[str]) -> set[str]:
    """Transitively expand model_validate_classes to include nested Pydantic models.

    If class A is deserialized via model_validate and has a field typed as class B,
    then B is also effectively deserialized (Pydantic handles nested model inflation).
    Runs until stable (usually 2-3 iterations for real codebases).
    """
    # Build: class_name → set of field type names (from AnnAssign annotations)
    class_to_field_types: dict[str, set[str]] = {}
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
            type_names: set[str] = set()
            for stmt in node.body:
                if not isinstance(stmt, ast.AnnAssign):
                    continue
                ann = stmt.annotation
                # Unwrap Optional/list/Union subscripts to find the inner Name
                to_check = [ann]
                while to_check:
                    a = to_check.pop()
                    if isinstance(a, ast.Name):
                        type_names.add(a.id)
                    elif isinstance(a, ast.Subscript):
                        to_check.append(a.value)
                        if isinstance(a.slice, ast.Tuple):
                            to_check.extend(a.slice.elts)
                        else:
                            to_check.append(a.slice)
                    elif isinstance(a, ast.BinOp):  # X | Y union syntax
                        to_check.extend([a.left, a.right])
            if type_names:
                class_to_field_types.setdefault(node.name, set()).update(type_names)

    expanded = set(seed)
    while True:
        added: set[str] = set()
        for cls in list(expanded):
            for field_type in class_to_field_types.get(cls, set()):
                if field_type not in expanded:
                    added.add(field_type)
        if not added:
            break
        expanded |= added
    return expanded


def detect_f3(context: AuditContext) -> DetectorResult:
    """Flag Pydantic BaseModel/BaseSettings fields never accessed as attributes."""
    if context.graph is None or context.graph.call_graph is None:
        return DetectorResult(count=0, samples=[])

    cg = context.graph.call_graph
    field_map = _pydantic_field_names(context.src_root)  # field_name → set of class names
    # Expand: nested Pydantic models under deserialized classes are also schema fields
    model_validate_classes = _expand_model_validate_classes(
        context.src_root, cg.model_validate_classes
    )

    samples: list[str] = []
    count = 0

    for name, class_names in sorted(field_map.items()):
        if name.startswith("_"):
            continue
        if name in cg.accessed_attrs:
            continue
        if name in cg.kw_arg_names:  # set via Model(field=value) — still in use
            continue
        # Skip fields from classes that use getattr(self, variable) — dynamic access
        if class_names & cg.dynamic_getattr_classes:
            continue
        # Skip fields from classes deserialized via model_validate* — all fields are schema fields
        if class_names & model_validate_classes:
            continue
        count += 1
        if len(samples) < _MAX_SAMPLES:
            samples.append(f"{name} — BaseModel field never accessed as attribute")

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
