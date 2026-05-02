# Task

## Objective

Expand Custodian's detector coverage into dead code, dead fields, flow audit, and architecture invariant categories — the analysis classes it currently lacks entirely.

## Context

Current detector inventory (2026-04-30):

**C-class — 18 file-local code health detectors (C1–C18)**
Style, safety, encoding, logging, datetime, subprocess patterns.

**S-class — 2 cross-file structure detectors (S1–S2)**
S1 layer boundary violations (declarative YAML config), S2 mutual imports.

**U-class — 3 cross-file stub detectors (U1–U3)**
U1 raise NotImplementedError, U2 ellipsis-only, U3 docstring-only bodies.

**Gaps — what Custodian does NOT detect:**
- D-class (dead code): unused functions/classes/constants, unreachable branches,
  functions that never return normally (always raise), dead `else` after `return`
- F-class (field/variable): dataclass fields never read outside __init__,
  module-level constants only assigned never read
- G-class (ghost work): TODO/FIXME that reference symbols no longer in the codebase
- T-class (test coverage): public API functions with no test file referencing them
- A-class (architecture invariants): naming pattern enforcement, forbidden direct
  dependencies (e.g. domain must not call requests directly), interface compliance

## Definition of Done

Each new detector class: implemented with tests, running clean on all 5 repos,
committed and pushed.
