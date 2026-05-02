# Log

_Chronological continuity log. Decisions, stop points, what changed and why._
_Not a task tracker — that's backlog.md. Keep entries concise and dated._

## Recent Decisions

| Decision | Rationale | Date |
| C35 detector added: bare type: ignore without error-code brackets | Uses tokenize for comment-only scanning (no string/docstring false positives); found 23 in VF, all fixed; 8 tests | 2026-05-02 |
| C34 detector added: commented-out def/class/decorator definitions | Regex-based; flagged 2 commented-out functions in VF filter_function.py; 9 tests | 2026-05-02 |
| D8 detector added: value return with implicit None fall-through | Uses _all_paths_terminate() helper; false positives fixed for with-blocks and while True loops; found _initial_authenticate() in VF and fixed it explicitly; 10 tests | 2026-05-02 |
| Audit round 3 complete (2026-05-02) | All repos: Custodian=0, VF=1(A1 advisory known), OConsole=0, CxRP=0, OC=0; 593 tests | 2026-05-02 |
| Audit round 2 complete (2026-05-02) | All repos: Custodian=0, VF=1(A1 advisory), OConsole=0, CxRP=0, OC=155(T1 LOW domain gaps). Dead code removed, vulture FP rate reduced, D7/T1 glob fixed, 502 tests. | 2026-05-02 |
| Vulture adapter now includes tests_root in scan | False positives for public API functions only called from tests (run_adapters, filter_findings, apply_policy, etc.) — vulture couldn't see test callers; now passes tests_root as additional scan path | 2026-05-02 |
| D7 and T1 exclusions now use _glob_to_regex from code_health | PurePosixPath.match() doesn't handle src/**/*.py correctly (** needs ≥1 intermediate dir); switched to code_health._glob_to_regex which handles zero-or-more segments | 2026-05-02 |
| D7 exclude_paths support added | detect_d7() now reads audit.exclude_paths.D7; used for command-dispatch functions with interface-required params | 2026-05-02 |
| T1 broad exclusions added for VF/OC | VF: all production dirs excluded (integration-tested pipeline); OC: adapters/entrypoints/artifact_index/backends excluded (monkeypatch-tested) | 2026-05-02 |
| Dead code removed: _top_level_arg_count, _worst_severity, _SEV_ORDER, cmd_install, get_aider_command, spawn_update_clis_background, read_decision, queue.remove | VF/OC/OConsole genuinely dead functions and variables cleaned up; protocols.py Protocol classes whitelisted as plugin author API | 2026-05-02 |
| A2 detector (directory structure invariants) | Generic version of VF1 capability DDD folder shape; uses PurePosixPath.match() (not fnmatch) so * = one path component; config: architecture.directory_structure with glob/required_files/required_dirs/exclude | 2026-05-02 |
| A1 extended with class_field_count rule type | Generic version of VF5 WorkflowContext god-object check; counts ast.AnnAssign fields in a named class, excludes InitVar; config: class_field_count: {class_name, max_fields} | 2026-05-02 |
| H1 detector (hexagonal architecture layer ordering) | Layers declared in architecture.hex in order from innermost to outermost; each layer may only import from layers with lower index; more concise than S1's explicit may_not_import lists | 2026-05-02 |
| VF1 and VF5 migrated to declarative config | VF1 now uses A2 (directory_structure in .custodian.yaml), VF5 now uses A1 class_field_count; custom _custodian/detectors.py only retains VF3 (TRANSITIONAL) and VF6 (cross-file) | 2026-05-02 |
| VF A1 excludes extended for entrypoints/start | src/entrypoints/** and src/start/** excluded from A1 VF2 rule; these are composition roots legitimately importing get_default_mongo() from class_mongo_conn | 2026-05-02 |
| F1 inheritance check for serializable base classes | _dataclass_field_names() now does two passes: first collects which classes have serialization methods; second skips subclasses of those (handles BaseContract → subclass pattern in CxRP) | 2026-05-02 |
| T2 exclude_paths support added | detect_t2() now reads audit.exclude_paths.T2 to skip "should not raise" validation test files; consistent with T1/C-class exclusion pattern | 2026-05-02 |
| Multi-repo audit round complete (2026-05-02) | VF: A1=1(advisory), VULTURE=342, T1=670. OC: T1=266, VULTURE=470. SB: VULTURE=64. OConsole: D1=5(dead funcs), D7=16, T1=75, VULTURE=11. CxRP: T1=1, VULTURE=66. Custodian: VULTURE=19. WorkStation: clean. All hard violations resolved. | 2026-05-02 |
| All 15 Custodian refactor phases complete | Phases 4-15 implemented in one session: Semgrep/ty/mypy/Vulture adapters, policy layer, codemod base, config migration, JSON/SARIF/Markdown reports, integration tests, deprecated detector cleanup, unified CLI, pre-commit hooks, multi-repo enhancements. 475 tests. | 2026-05-01 |
| S4 detector: missing venv guard in tests/conftest.py | Repeatedly having to add venv guard manually; made it a detector so Custodian flags repos that are missing it | 2026-05-01 |
| Deprecated detectors stubbed not deleted | 27 detect_* functions replaced with stubs returning (0,[]); Detector registrations kept for --list-detectors to show them with deprecated=True status | 2026-05-01 |
| F3 skips classes deserialized via model_validate*() | ClassName.model_validate*() calls mean all fields are part of the external schema; not dead even if not accessed as Python attributes | 2026-05-01 |
| F3 transitively expands model_validate_classes | Pydantic inflates nested models automatically during deserialization; a field typed as NestedModel in a deserialized class means NestedModel's fields are also schema fields | 2026-05-01 |
| align_text_to_scene restored + added to __all__ (VF) | Function was deleted as D1 false positive; actually monkey-patched via module attribute access in tools/audit/adapters/runtime_hooks — D1 checks called_names not called_attrs | 2026-05-01 |
| D1 false positive: module attribute monkey-patching | `align_mod.align_text_to_scene = ...` is attribute access not a call; D1 misses these. Fix: add __all__ to suppress, or improve D1 to also check called_attrs (but that would suppress too many) | 2026-05-01 |
| D7 recognizes del var as param use | del stage_name, content_type is the Python idiom for intentionally discarding Protocol-required params; Del ctx added to used_names check | 2026-05-01 |
| D7 skips @override methods | Override implementations must match the parent signature; unused params are interface-required | 2026-05-01 |
| D7 treats raise NotImplementedError as stub body | Single-statement or docstring+raise NIE body = incomplete stub; params not flagged | 2026-05-01 |
| test_cli_doctor subprocess needs PYTHONPATH | Tests spawn python -m custodian.cli.doctor; without PYTHONPATH=src the module isn't found (custodian not pip-installed) | 2026-05-01 |
| Settings.policy_path accessed via getattr(self, attr) — F3 false positive | Dynamic string-based attribute access not captured by call_graph; added to known gap | 2026-05-01 |
| D6 added: class referenced but never constructed | D5 catches "never referenced"; D6 catches "referenced but constructor never called" — the partial-pipeline pattern where a DTO is wired into type annotations but the produce-side was never implemented | 2026-05-01 |
| constructed_names tracked separately in call_graph | ast.Call where func is ast.Name → constructor call; also: ClassName.method() attr access, ClassName[T]() generic subscript, keyword kwarg values, base class names — all treated as "class in active use" | 2026-05-01 |
| D5/D6 skip BaseModel/BaseSettings/TypedDict bases | Pydantic models deserialized via model_validate/parse_obj — not via direct constructor; static analysis can't see this | 2026-05-01 |
| D7 skips dunder methods | __exit__/__getitem__ etc. — params required by protocol even if unused | 2026-05-01 |
| F1/F3 skip kw_arg_names | Model(field=value) sets a field; track kwarg names in call_graph so fields used only via constructor aren't flagged as dead | 2026-05-01 |
| call_graph tracks getattr() strings | getattr(obj, "field") is a string-based attribute read; add to accessed_attrs so F1/F3 don't false-positive on these | 2026-05-01 |
| A1 uses declarative invariants YAML | architecture.invariants in .custodian.yaml; complements S1 (import layer rules) with structural constraints (max_lines, max_classes, max_functions, forbidden_import) | 2026-05-01 |
| C33 flags per-file ghost-work density | Unlike C1/C6 (per-occurrence), C33 flags a FILE when it accumulates ≥ threshold TODO/FIXME/HACK/XXX markers; threshold configurable via audit.c33_threshold | 2026-05-01 |
| D6 false positive: dict-registry factory pattern | "nltk": NLTKCheckStage → builders[name](cfg) is dynamic dispatch; can't trace statically. Known limitation; add to .custodian.yaml exclusions if needed | 2026-05-01 |
| OC deleted classes were partial-pipeline DTOs | ArchonFailureInfo, KodoFailureInfo, OpenClawFailureInfo, OpenClawEventDetailRef, ChildTaskSpec were referenced but not wired; restored all and added _extract_failure_info() adapter methods | 2026-05-01 |
| Policy: only delete truly orphaned/duplicated code | DTOs/structs that are partially wired should be completed (restore + wire), not deleted; safe deletions = exact duplication or zero references anywhere including type annotations | 2026-05-01 |
| D5 also checks called_attrs/accessed_attrs | Classes accessed as mod.ClassName are attribute loads, not Name Loads; D5 missed them without this check | 2026-05-01 |
| D5 skips Protocol/ABC base classes | Protocol subclasses are structural interfaces used only in type annotations; PEP 563 lazy eval means no Name Load → false positive | 2026-05-01 |
| C32 uses word-boundary + bigram matching | Substring match ("token" in "word_tokenizer") caused false positives; split on _/./- and check whole words and bigrams | 2026-05-01 |
| C32 skips URL values (http/https prefix) | TOKEN_ENDPOINT = "https://..." is a URL, not a credential value | 2026-05-01 |
| C32 skips ALL_CAPS values | _SECRET_ENV = "OPERATIONS_CENTER_WEBHOOK_SECRET" stores an env var NAME, not the secret itself | 2026-05-01 |
| C32 skips names ending in exclusion suffixes | endpoint/url/env/name/param/var suffixes indicate the var holds a URL or env var reference, not a secret | 2026-05-01 |
| C23 false positive in executor.py docstring | "Never uses shell=True." in a module docstring matched the regex; regex-based C23 doesn't distinguish string context | 2026-05-01 |
| C2 switched to AST-based detection | Regex matched print( inside string literals (docstrings, f-strings); AST walk on ast.Call(func=Name(id='print')) is accurate | 2026-05-01 |
| C16 skips write_text with 2+ positional args | Custom audit.write_text(filename, content) was false positive; Path.write_text takes 1 positional (text) so 2+ = custom method | 2026-05-01 |
| T2 recognizes assert_*() function calls | assert_no_mutation_fields(x) and similar custom helpers are assertion mechanisms; previously caused false positives | 2026-05-01 |
| call_graph tracks all Name Load nodes | Functions passed as values (target=fn, callbacks=[fn]) weren't counted as "used"; Name Load in AST covers all reference forms | 2026-05-01 |
| U1/U2/U3 skip except-handler fallback classes | try/except fallback stubs (import real lib, except: define stub) are intentional no-ops, not unfinished code | 2026-05-01 |
| D1 uses __all__ to mark intentional public APIs | exclude_paths doesn't work for D1 (call_graph has no file context); __all__ is the correct Python idiom for declaring public exports | 2026-05-01 |
| Cross-file detectors use lazy AnalysisGraph | File-local C-class detectors should not pay AST/graph cost | 2026-04-30 |
| U2 excludes Protocol/abstractmethod/overload | Correct Python idioms for ellipsis bodies | 2026-04-30 |
| S1 uses declarative YAML architecture.layers | Rules are explicit and auditable | 2026-04-30 |
| ArchonAdapter/OpenClawRunner converted to ABC | @abstractmethod alone doesn't enforce without ABC base | 2026-04-30 |
| doctor plugin_audit_keys escape hatch | Plugin audit config keys should not trigger unknown-key warnings | 2026-04-30 |
| D2: check else-body does NOT terminate | Symmetric if/else (both return) is intentional; only flag when if exits but else falls through | 2026-04-30 |
| D3 uses separate _all_paths_noreturn | return is not a NoReturn terminal; D3 only counts raise/exit | 2026-04-30 |
| T2 scans tests_root directly | ast_forest covers only src_root; T2 predated the tests_forest pass | 2026-04-30 |
| C19/C20/C22-C25 are regex | Patterns tight enough; consistent with C-class file-local pattern detectors | 2026-04-30 |
| C21 uses inline AST parse | Avoids needing ast_forest for a single C-class detector | 2026-04-30 |
| D1 conservative: module-level only | Methods need type info; false positive cost too high for method-level dead detection | 2026-04-30 |
| call_graph tracks decorated_names separately | A function used as @decorator is "used" even without direct foo() call | 2026-04-30 |
| F1 uses accessed_attrs from call_graph | Any obj.field attribute load marks field live; zero accesses = dead | 2026-04-30 |
| E1 exempts __init__/__new__/__del__ etc. | Convention is to omit -> None on these; flagging is noise | 2026-04-30 |
| G1 uses CamelCase only (not snake_case) | Common English words match snake_case patterns; CamelCase = class/type name, low false-positive rate | 2026-04-30 |
| symbol_index strips comments before tokenizing | A word that appears ONLY in a comment is not "in source" — must strip comments so G1 can detect it | 2026-04-30 |
| tests_forest is a separate pass | Mirrors ast_forest for tests_root; enables T1 without ad-hoc file reads | 2026-04-30 |
| X1 counts BoolOp values beyond first | `a and b and c` has 2 branches, not 1; each extra `and`/`or` value adds complexity | 2026-04-30 |
| x1_threshold/x2_threshold added to doctor known audit keys | Configurable thresholds need to be recognized to avoid false doctor warnings | 2026-04-30 |
| I1 excludes # noqa lines | `# noqa: F401` marks intentional re-exports; I1 must respect these | 2026-05-01 |
| T2 recognizes pytest.raises/warns and self.assertX | These are valid assertion mechanisms; not recognizing them caused 200+ false positives across OC+VF | 2026-05-01 |
| D3 pre-checks _has_return_in_scope | Functions with any return path are NOT NoReturn — fix false positives like if/elif/.../raise at end | 2026-05-01 |
| S2 skips self-import pairs (mod_a == mod_b) | Relative imports in __init__.py resolve to the same module; self-loops are spurious | 2026-05-01 |
| C18 regex excludes -f"..." patterns | `-f", "null"` command-line flag list elements were incorrectly matching the f-string pattern | 2026-05-01 |
| D1 skips framework-decorated functions | @app.command(), @router.get(), @pytest.fixture etc. register via decoration not call-site; flagging them as dead is wrong | 2026-04-30 |
| call_graph scans tests_root as extra_roots | F1/D1 false positives for fields/functions used in tests but not in src; extra_roots contribute only usages, not definitions | 2026-04-30 |
| F1 skips dataclasses with serialization methods | to_dict/model_dump/asdict expose all fields indirectly; attribute-level analysis can't see this | 2026-04-30 |
| T2 recognizes mock assertions and raise AssertionError | mock.assert_called_once() / raise AssertionError(...) are legitimate test mechanisms | 2026-04-30 |
| C18 excludes f after quote chars | `"f", "h"` list elements matched `f", "` as f-string; add (?<!")(?<!') lookbehinds | 2026-04-30 |

## Coverage map

**What Custodian covers (70 detectors: 57 core + 13 OC plugin):**
- Dead code: D1–D7 (functions, classes, branches, unreachable code, fields, partially-implemented pipelines, dead method params)
- Partially implemented: U1–U3 (stub bodies), D6 (referenced but never constructed), G1 (ghost CamelCase names in comments)
- Structure: S1 (import layer violations), S2 (circular imports), S3 (test import in src)
- Architecture invariants: A1 (declarative YAML max_lines/max_classes/max_functions/forbidden_import per glob)
- Code health: C1–C33 (file-local quality, security, complexity, ghost-work density)
- Dead fields: F1 (dataclass fields), F2 (module-level constants), F3 (Pydantic BaseModel/BaseSettings fields)
- Test shape: T1 (no tests), T2 (no assertions)
- Annotations: E1 (missing return type), E2 (missing param types)
- Imports: I1 (unused imports)
- Complexity: X1 (cyclomatic), X2 (too many params)

**What's NOT in Custodian:**

| Gap area | Priority | Notes |
|---|---|---|
| Protocol contract (P1) | MEDIUM | U1-U3 catch stub shape but don't verify signature matches Protocol |
| Naming conventions (N1) | LOW | No is_/has_/can_ bool-func prefix enforcement — AST-based, feasible |
| C30: random outside tests | LOW | Prefer secrets for security-sensitive code |
| Flow audits | LOW | No reachability, no missing-error-path, no constant-return analysis |
| Pipeline completeness | LOW | No "producer → consumer" graph across stages |
| Config key liveness | LOW | String subscript `config["key"]` invisible to call_graph |
| Feature flag liveness | LOW | No unused/always-true flag detection |
| Documentation drift | STOP | Needs docstring parser; complex |
| Duplicate code | STOP | Needs hash/similarity pass; complex |
| Resource lifecycle | STOP | No unclosed file/connection detection |

**Known Custodian limitations (not gaps — won't fix):**
- D1: module-level only; method-level dead detection needs type info (too many false positives)
- D1: module attribute monkey-patching (`mod.fn = wrapper`) is attribute access, not a call — workaround: `__all__`
- D1: per-file exclude_paths doesn't work; call_graph has no file context — would need `(file, name)` pairs
- D5/D6: string-based class factory (`"module.ClassName"` in registry dict) — can't trace statically
- C23: regex matches "shell=True" in docstrings — fix would require AST-based C23
- I1: multi-line `from x import (\n  a, b\n)` — lineno points to first line only, b not caught
- VF D7=35: all keyword-only params (after `*`) — can't rename with `_` without breaking callers

## Stop Points

- Contract drift (docstring vs signature): needs docstring parser — complex, lower priority
- Duplicate code detection: needs hash/similarity pass — complex, likely out of scope
- D1 per-file context: module_functions is a flat set; exclude_paths can't target specific files; fix requires storing (file, name) pairs
- D1 module attribute monkey-patching: `mod.fn = wrapper` is attribute access, not call; D1 misses this pattern; workaround is __all__
- C23 regex false positive on docstrings: "shell=True" in docstring text matches; fix requires AST-based C23
- VF D7 35 remaining: all keyword-only params — cannot rename with _ prefix without breaking callers; need to either wire them or accept as known

## Notes

**Detector class map (70 total: 57 core + 13 OC plugin [OC1–OC9, AI1–AI4]):**
- C (C1–C33): file-local code health — regex + inline AST; C33=ghost-work density (new)
- S (S1–S3): cross-file structure — import_graph (S1, S2) + ast_forest (S3)
- A (A1): architecture invariants — declarative YAML max_lines/max_classes/max_functions/forbidden_import (new)
- U (U1–U3): unimplemented stubs — ast_forest
- D (D1–D7): dead code — D7=dead method params (new); D5/D6=dead classes (ast_forest+call_graph)
- F (F1–F3): dead fields/constants — F3=Pydantic BaseModel field liveness (new)
- E (E1–E2): annotation gaps — ast_forest
- T (T1–T2): test shape — T1 uses ast_forest+tests_forest, T2 direct scan
- X (X1–X2): complexity — ast_forest
- G (G1): ghost work — symbol_index
- I (I1): import hygiene — ast_forest

**Analysis passes and what they enable:**
- import_graph → S1, S2
- ast_forest → U1-U3, D2-D4, F2, E1-E2, X1-X2, T1, I1, S3, D5 (class list), D6 (class list)
- call_graph → D1, F1, D5 (reference check), D6 (constructed_names check)
- symbol_index → G1
- tests_forest → T1

**D6 constructed_names tracking covers:**
- `ClassName(...)` — direct constructor call
- `ClassName[T](...)` — generic parameterized constructor
- `ClassName.method(...)` — classmethod/factory dispatch
- `EnumClass.MEMBER` — enum member access (any Attribute node)
- `default_factory=ClassName` — keyword argument factory reference
- `class Child(ClassName):` — base class inheritance

**False-positive risk guide:**
- LOW: file-local AST (D2, D3, D4, F2, E1, E2, X1, X2, C21, I1)
- MEDIUM: call_graph (D1, F1, D5, D6) — dynamic dispatch/string-based factories not captured; G1 — CamelCase heuristic
- HIGHER: T1 — indirect testing via integration tests produces false positives

**Test counts as of 2026-05-01 (round 9):**
Custodian 393 tests (committed 55282f8). OC 3037 tests. SB 287 tests. VF 1660 tests (7 pre-existing failures unchanged).

**Audit totals as of 2026-05-01 (round 9, post-fixes):**
VF ~2024 (estimate), OC 460, SB 41. Total ~2525 (was 2674 round 8 end, -149 this round).
Round 9 new fixes: VF D1 -42 (bulk dead function removal), VF D5 -1 (VideoPerformance), VF F2 -1 (_BRANDING_MAP), VF I1 -1 (contextlib), VF D1 -2 files deleted (audit_summary.py, validation.py).
Custodian improvements this round: F3 model_validate_classes tracking + transitive expansion for nested Pydantic models.

**Native tool migration — completed 2026-05-01 (this session):**
- OC `tools/audit/architecture_invariants/` — all 4 rule files (import_rules, layer_rules, mutation_rules, scanning_rules) inlined directly into `_custodian/architecture.py` (AI1–AI4). No more try/import wrappers. Directory deleted.
- VF `tools/audit/architecture_invariants/` — all 4 rule files (capability_rules, singleton_rules, config_rules, audit_policy_rules) inlined into `_custodian/detectors.py` (VF1–VF4). import_rules covered by S1 config. Added VF5 (WorkflowContext field count advisory ≥ 20 fields). Directory deleted.
- VF workflow context guardrails (`workflow_context_guardrails.py`, `check_workflow_context_guardrails.py`, `workflow_context_ownership.json`) moved to `tools/audit/workflow_context/` — still needed as a standalone tool that requires a pre-generated context map.
- Custodian self-audit: 64 → 0 findings (C11: timeout= on all 5 adapters; F2: 8 dead regex constants deleted; D1: maintenance_kit/ deleted; F1: replaces field removed; D7: unused context param removed; C29/C1/C6/T1: config exclusions with rationale).
- SB T1: 3 → 0 (DecisionSink, AdjustmentStoreState, SummaryStats excluded — tested via containing services).
- VF C1: 23 → 0 (per-file exclusions added; all 23 TODOs tracked in .console/backlog.md).

**Current findings (post this session):** Custodian 0, SwitchBoard 0, VF 671 (T1=670, VF5=1, VF6=0), OC 266 (T1=266). All HIGH/MED findings are zero across all repos.

**VF6 added (2026-05-01):** Detects stage classes (have `run(self, context)` method) under `stages/` that are not referenced in any of the three pipeline wiring files (orchestration/api.py, core/manager.py, stages/system/preflight_bundle.py). Currently returns 0 — all stages correctly wired. Will fire if a new stage file is added but not wired in.
