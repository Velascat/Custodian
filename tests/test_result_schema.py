# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import json

from custodian.audit_kit.result import AuditResult, SCHEMA_VERSION


def test_audit_result_json_round_trip():
    result = AuditResult(repo_key="Sample", patterns={"C1": {"count": 1}}, total_findings=1)
    data = json.loads(result.to_json())
    assert data["schema_version"] == SCHEMA_VERSION == 1
    assert data["repo_key"] == "Sample"
    assert data["patterns"]["C1"]["count"] == 1
