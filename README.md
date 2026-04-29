# Custodian

Custodian is a pip-installable cross-repo audit and maintenance toolkit for Python repos. It centralizes reusable detector logic and maintenance helpers so teams can stop re-implementing the same operational checks in each consumer repository.

## Why it exists

Large multi-repo organizations need consistent health checks and maintenance routines, but each repo has local conventions. Custodian provides shared infrastructure (detector execution, schema-stable result output, plugin loading) while letting each consumer supply repo-specific plugins and config.

## Quick start

```bash
pip install custodian
custodian-doctor
custodian-audit
```

For local development against this repo:

```bash
pip install -e .[dev]
```

## Detector model

Detectors are defined with IDs that follow namespace conventions like `Cn`, `Fn`, and `Gn`. The built-in v0.1 package includes generic code-health detectors `C1` through `C8`, plus extension points for consumer-defined detectors.

## Consumer configuration (`.custodian.yaml`)

Each consumer repo declares:

- `repo_key`: stable identifier
- `src_root` and `tests_root`: relative paths for scanning
- `audit` settings (for example stale handler names and common words)
- `plugins`: module import targets used by Custodian
- `maintenance` thresholds

See `tests/fixtures/sample_consumer/.custodian.yaml` for a concrete example.

## Versioning and schema stability

Custodian follows semantic versioning from day 1. Audit output is explicitly versioned using `schema_version` in `AuditResult`; v0.1 emits `schema_version = 1`.
