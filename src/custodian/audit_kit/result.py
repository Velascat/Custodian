# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Velascat
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
import json

SCHEMA_VERSION = 1


@dataclass
class AuditResult:
    schema_version: int = SCHEMA_VERSION
    repo_key: str = ""
    scanned_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    patterns: dict = field(default_factory=dict)
    total_findings: int = 0

    def to_json(self) -> str:
        """Emit stable, explicit JSON for downstream aggregation later."""
        return json.dumps(asdict(self), indent=2, sort_keys=True)
