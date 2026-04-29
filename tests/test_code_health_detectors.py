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


def test_exclude_paths_skips_matched_files(tmp_path):
    """audit.exclude_paths.<id> filters specific files from a single detector."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "lib.py").write_text("x = 1\n", encoding="utf-8")
    (src / "cli.py").write_text("print('hello')\nprint('world')\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path,
        config={"audit": {"exclude_paths": {"C2": ["src/cli.py"]}}},
        plugin_modules=[],
    )

    by_id = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert by_id["C2"] == 0  # cli.py excluded; lib.py has no prints


def test_exclude_paths_supports_globs(tmp_path):
    src = tmp_path / "src"
    (src / "cli").mkdir(parents=True)
    (src / "lib.py").write_text("# TODO\n", encoding="utf-8")
    (src / "cli" / "a.py").write_text("# TODO\n# TODO\n", encoding="utf-8")
    (src / "cli" / "b.py").write_text("# TODO\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path,
        config={"audit": {"exclude_paths": {"C1": ["src/cli/*.py"]}}},
        plugin_modules=[],
    )
    counts = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert counts["C1"] == 1  # only lib.py's TODO


def test_exclude_paths_recursive_glob(tmp_path):
    """`**` matches any depth, unlike single `*` which is path-component-aware."""
    src = tmp_path / "src"
    (src / "pkg" / "deep" / "nested").mkdir(parents=True)
    (src / "outside.py").write_text("# TODO\n", encoding="utf-8")
    (src / "pkg" / "shallow.py").write_text("# TODO\n", encoding="utf-8")
    (src / "pkg" / "deep" / "mid.py").write_text("# TODO\n", encoding="utf-8")
    (src / "pkg" / "deep" / "nested" / "leaf.py").write_text("# TODO\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path,
        config={"audit": {"exclude_paths": {"C1": ["src/pkg/**/*.py"]}}},
        plugin_modules=[],
    )
    counts = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert counts["C1"] == 1  # only outside.py survives the glob


def test_exclude_paths_single_star_is_path_aware(tmp_path):
    """`*.py` does NOT cross directory separators — that's the `**` job."""
    src = tmp_path / "src"
    (src / "sub").mkdir(parents=True)
    (src / "top.py").write_text("# TODO\n", encoding="utf-8")
    (src / "sub" / "deep.py").write_text("# TODO\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path,
        config={"audit": {"exclude_paths": {"C1": ["src/*.py"]}}},
        plugin_modules=[],
    )
    counts = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert counts["C1"] == 1  # sub/deep.py NOT excluded by single-star glob


def test_exclude_paths_only_applies_to_named_detector(tmp_path):
    """An entry under C2 must not silence C1, etc."""
    src = tmp_path / "src"
    src.mkdir()
    (src / "noisy.py").write_text("# TODO\nprint('x')\n", encoding="utf-8")

    context = AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path,
        config={"audit": {"exclude_paths": {"C2": ["src/noisy.py"]}}},
        plugin_modules=[],
    )
    counts = {det.id: det.detect(context).count for det in build_code_health_detectors()}
    assert counts["C1"] == 1   # TODO still reported
    assert counts["C2"] == 0   # print suppressed by exclude
