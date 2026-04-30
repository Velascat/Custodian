# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import pytest

from custodian.audit_kit.code_health import build_code_health_detectors, detect_c9, detect_c10, detect_c11, detect_c12, detect_c13, detect_c14
from custodian.audit_kit.detector import AuditContext


def _ctx(tmp_path, src_text: str, *, config: dict | None = None) -> AuditContext:
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    (src / "sample.py").write_text(src_text, encoding="utf-8")
    return AuditContext(
        repo_root=tmp_path,
        src_root=src,
        tests_root=tmp_path / "tests",
        config=config or {},
        plugin_modules=[],
    )


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


# ── C9: broad except Exception without logger ────────────────────────────────

def test_c9_flags_silent_broad_except(tmp_path):
    ctx = _ctx(tmp_path, """\
def bad():
    try:
        pass
    except Exception:
        x = 1
""")
    assert detect_c9(ctx).count == 1


def test_c9_skips_logged_except(tmp_path):
    ctx = _ctx(tmp_path, """\
import logging
logger = logging.getLogger(__name__)

def ok():
    try:
        pass
    except Exception as exc:
        logger.warning("failed: %s", exc)
""")
    assert detect_c9(ctx).count == 0


def test_c9_skips_reraise(tmp_path):
    ctx = _ctx(tmp_path, """\
def ok():
    try:
        pass
    except Exception as exc:
        raise RuntimeError("wrapped") from exc
""")
    assert detect_c9(ctx).count == 0


def test_c9_skips_base_exception_that_reraises(tmp_path):
    ctx = _ctx(tmp_path, """\
def ok():
    try:
        pass
    except BaseException:
        raise
""")
    assert detect_c9(ctx).count == 0


def test_c9_flags_base_exception_silent(tmp_path):
    ctx = _ctx(tmp_path, """\
def bad():
    try:
        pass
    except BaseException:
        return None
""")
    assert detect_c9(ctx).count == 1


def test_c9_narrow_except_not_flagged(tmp_path):
    ctx = _ctx(tmp_path, """\
def ok():
    try:
        pass
    except ValueError:
        return None
""")
    assert detect_c9(ctx).count == 0


# ── C10: naive datetime ───────────────────────────────────────────────────────

def test_c10_flags_naive_now(tmp_path):
    ctx = _ctx(tmp_path, "from datetime import datetime\nx = datetime.now()\n")
    assert detect_c10(ctx).count == 1


def test_c10_flags_utcnow(tmp_path):
    ctx = _ctx(tmp_path, "from datetime import datetime\nx = datetime.utcnow()\n")
    assert detect_c10(ctx).count == 1


def test_c10_skips_tz_aware_now(tmp_path):
    ctx = _ctx(tmp_path, "from datetime import datetime, UTC\nx = datetime.now(UTC)\n")
    assert detect_c10(ctx).count == 0


def test_c10_skips_timezone_utc(tmp_path):
    ctx = _ctx(tmp_path, "from datetime import datetime, timezone\nx = datetime.now(timezone.utc)\n")
    assert detect_c10(ctx).count == 0


# ── C11: subprocess without timeout ──────────────────────────────────────────

def test_c11_flags_run_without_timeout(tmp_path):
    ctx = _ctx(tmp_path, "import subprocess\nsubprocess.run(['ls'])\n")
    assert detect_c11(ctx).count == 1


def test_c11_skips_run_with_timeout(tmp_path):
    ctx = _ctx(tmp_path, "import subprocess\nsubprocess.run(['ls'], timeout=5)\n")
    assert detect_c11(ctx).count == 0


def test_c11_flags_check_output_without_timeout(tmp_path):
    ctx = _ctx(tmp_path, "import subprocess\nsubprocess.check_output(['git', 'log'])\n")
    assert detect_c11(ctx).count == 1


def test_c11_handles_multiline_call_with_timeout(tmp_path):
    ctx = _ctx(tmp_path, """\
import subprocess
subprocess.run(
    ['git', 'status'],
    capture_output=True,
    timeout=30,
)
""")
    assert detect_c11(ctx).count == 0


def test_c11_handles_multiline_call_without_timeout(tmp_path):
    ctx = _ctx(tmp_path, """\
import subprocess
subprocess.run(
    ['git', 'status'],
    capture_output=True,
    text=True,
)
""")
    assert detect_c11(ctx).count == 1


# ── C12: bare # type: ignore ─────────────────────────────────────────────────

def test_c12_flags_bare_type_ignore(tmp_path):
    ctx = _ctx(tmp_path, "x = foo()  # type: ignore\n")
    assert detect_c12(ctx).count == 1


def test_c12_skips_type_ignore_with_code(tmp_path):
    ctx = _ctx(tmp_path, "x = foo()  # type: ignore[attr-defined]\n")
    assert detect_c12(ctx).count == 0


def test_c12_skips_type_ignore_with_multiple_codes(tmp_path):
    ctx = _ctx(tmp_path, "x = foo()  # type: ignore[attr-defined, return-value]\n")
    assert detect_c12(ctx).count == 0


# ── C13: assert in production source ─────────────────────────────────────────

def test_c13_flags_assert_in_src(tmp_path):
    ctx = _ctx(tmp_path, """\
def validate(x):
    assert x is not None
""")
    assert detect_c13(ctx).count == 1


def test_c13_flags_multiple_asserts(tmp_path):
    ctx = _ctx(tmp_path, """\
def validate(x, y):
    assert x is not None
    assert isinstance(y, int)
""")
    assert detect_c13(ctx).count == 2


def test_c13_ignores_top_level_assert(tmp_path):
    ctx = _ctx(tmp_path, "assert __name__ == '__main__'\n")
    assert detect_c13(ctx).count == 0


# ── C14: open() without encoding ─────────────────────────────────────────────

def test_c14_flags_open_without_encoding(tmp_path):
    ctx = _ctx(tmp_path, 'with open("file.txt") as f:\n    data = f.read()\n')
    assert detect_c14(ctx).count == 1


def test_c14_flags_open_with_mode_no_encoding(tmp_path):
    ctx = _ctx(tmp_path, 'with open("file.txt", "r") as f:\n    data = f.read()\n')
    assert detect_c14(ctx).count == 1


def test_c14_skips_open_with_encoding(tmp_path):
    ctx = _ctx(tmp_path, 'with open("file.txt", encoding="utf-8") as f:\n    data = f.read()\n')
    assert detect_c14(ctx).count == 0


def test_c14_skips_binary_mode(tmp_path):
    ctx = _ctx(tmp_path, 'with open("file.bin", "rb") as f:\n    data = f.read()\n')
    assert detect_c14(ctx).count == 0


def test_c14_skips_write_binary_mode(tmp_path):
    ctx = _ctx(tmp_path, 'with open("out.bin", "wb") as f:\n    f.write(b"data")\n')
    assert detect_c14(ctx).count == 0


def test_c14_skips_method_open(tmp_path):
    ctx = _ctx(tmp_path, 'path.open("r")\n')
    assert detect_c14(ctx).count == 0


def test_c14_skips_string_literal_mention(tmp_path):
    ctx = _ctx(tmp_path, 'msg = "call open() with encoding"\n')
    assert detect_c14(ctx).count == 0
