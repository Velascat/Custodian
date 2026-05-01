# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""I-class detectors are deprecated — verify they are marked deprecated and return no findings."""
from __future__ import annotations

from custodian.audit_kit.detector import AnalysisGraph, AuditContext
from custodian.audit_kit.detectors.imports import build_import_detectors


def _ctx(tmp_path):
    return AuditContext(
        repo_root=tmp_path, src_root=tmp_path / "src",
        tests_root=tmp_path / "tests", config={},
        plugin_modules=[], graph=AnalysisGraph(),
    )


class TestImportDetectorsDeprecated:
    def test_i1_is_deprecated(self):
        detectors = {d.id: d for d in build_import_detectors()}
        assert detectors["I1"].deprecated is True
        assert "ruff" in detectors["I1"].replaces

    def test_i1_returns_no_findings(self, tmp_path):
        detectors = {d.id: d for d in build_import_detectors()}
        assert detectors["I1"].detect(_ctx(tmp_path)).count == 0
