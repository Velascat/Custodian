# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""X-class detectors are deprecated — verify they are marked deprecated and return no findings."""
from __future__ import annotations

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.complexity import build_complexity_detectors


def _ctx(tmp_path):
    return AuditContext(
        repo_root=tmp_path, src_root=tmp_path / "src",
        tests_root=tmp_path / "tests", config={},
        plugin_modules=[], graph=AnalysisGraph(),
    )


class TestComplexityDetectorsDeprecated:
    def test_x1_is_deprecated(self):
        detectors = {d.id: d for d in build_complexity_detectors()}
        assert detectors["X1"].deprecated is True
        assert "ruff" in detectors["X1"].replaces

    def test_x2_is_deprecated(self):
        detectors = {d.id: d for d in build_complexity_detectors()}
        assert detectors["X2"].deprecated is True

    def test_x1_returns_no_findings(self, tmp_path):
        detectors = {d.id: d for d in build_complexity_detectors()}
        assert detectors["X1"].detect(_ctx(tmp_path)).count == 0

    def test_x2_returns_no_findings(self, tmp_path):
        detectors = {d.id: d for d in build_complexity_detectors()}
        assert detectors["X2"].detect(_ctx(tmp_path)).count == 0
