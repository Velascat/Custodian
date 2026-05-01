# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""E-class detectors are deprecated — verify they are marked deprecated and return no findings."""
from __future__ import annotations

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.annotations import build_annotation_detectors


def _ctx(tmp_path):
    return AuditContext(
        repo_root=tmp_path, src_root=tmp_path / "src",
        tests_root=tmp_path / "tests", config={},
        plugin_modules=[], graph=AnalysisGraph(),
    )


class TestAnnotationDetectorsDeprecated:
    def test_e1_is_deprecated(self):
        detectors = {d.id: d for d in build_annotation_detectors()}
        assert detectors["E1"].deprecated is True
        assert "ruff" in detectors["E1"].replaces or "ty" in detectors["E1"].replaces

    def test_e2_is_deprecated(self):
        detectors = {d.id: d for d in build_annotation_detectors()}
        assert detectors["E2"].deprecated is True

    def test_e1_returns_no_findings(self, tmp_path):
        detectors = {d.id: d for d in build_annotation_detectors()}
        assert detectors["E1"].detect(_ctx(tmp_path)).count == 0

    def test_e2_returns_no_findings(self, tmp_path):
        detectors = {d.id: d for d in build_annotation_detectors()}
        assert detectors["E2"].detect(_ctx(tmp_path)).count == 0
