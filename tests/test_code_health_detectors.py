from __future__ import annotations

from custodian.audit_kit.code_health import build_code_health_detectors
from custodian.audit_kit.detector import AuditContext


def test_c1_to_c8_detectors_on_fixture(tmp_path):
    src = tmp_path / "src"
    tests = tmp_path / "tests"
    src.mkdir()
    tests.mkdir()

    (src / "sample.py").write_text(
        """# TODO: fix\nprint('x')\ntry:\n    x = 1\nexcept:\n    pass\n# FIXME\nbreakpoint()\nhandle_old_thing()\n""",
        encoding="utf-8",
    )
    (tests / "test_sample.py").write_text("assert True\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tests,
        config={"audit": {"stale_handlers": ["handle_old_thing"], "common_words": []}},
        plugin_modules=[],
    )

    by_id = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert by_id["C1"] == 1
    assert by_id["C2"] == 1
    assert by_id["C3"] == 1
    assert by_id["C4"] == 1
    assert by_id["C5"] == 1
    assert by_id["C6"] == 1
    assert by_id["C7"] == 1
    assert by_id["C8"] == 1
