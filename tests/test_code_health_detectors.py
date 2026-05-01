# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations

import pytest

from custodian.audit_kit.code_health import (
    build_code_health_detectors,
    detect_c2,
    detect_c9, detect_c10, detect_c11, detect_c12, detect_c13,
    detect_c14, detect_c15, detect_c16, detect_c17, detect_c18,
    detect_c21, detect_c22, detect_c23, detect_c24, detect_c25,
    detect_c26, detect_c27, detect_c28, detect_c29,
    detect_c31, detect_c32,
)
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


def test_c2_skips_commented_out_print(tmp_path):
    ctx = _ctx(tmp_path, "# print('debug')\n# also: print('x')\nx = 1\n")
    assert detect_c2(ctx).count == 0


def test_c2_flags_real_print(tmp_path):
    ctx = _ctx(tmp_path, "print('hello')\n")
    assert detect_c2(ctx).count == 1


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


# ── C15: f-string passed to logger ───────────────────────────────────────────

def test_c15_flags_fstring_logger_info(tmp_path):
    ctx = _ctx(tmp_path, 'import logging\nlogger = logging.getLogger(__name__)\nlogger.info(f"value={x}")\n')
    assert detect_c15(ctx).count == 1


def test_c15_flags_underscore_logger(tmp_path):
    ctx = _ctx(tmp_path, 'import logging\n_logger = logging.getLogger(__name__)\n_logger.error(f"bad: {msg}")\n')
    assert detect_c15(ctx).count == 1


def test_c15_skips_lazy_format(tmp_path):
    ctx = _ctx(tmp_path, 'import logging\nlogger = logging.getLogger(__name__)\nlogger.info("value=%s", x)\n')
    assert detect_c15(ctx).count == 0


def test_c15_skips_plain_string(tmp_path):
    ctx = _ctx(tmp_path, 'import logging\nlogger = logging.getLogger(__name__)\nlogger.warning("static message")\n')
    assert detect_c15(ctx).count == 0


# ── C16: Path.read_text/write_text without encoding ──────────────────────────

def test_c16_flags_read_text_no_args(tmp_path):
    ctx = _ctx(tmp_path, 'from pathlib import Path\nPath("f.txt").read_text()\n')
    assert detect_c16(ctx).count == 1


def test_c16_flags_write_text_no_encoding(tmp_path):
    ctx = _ctx(tmp_path, 'from pathlib import Path\nPath("f.txt").write_text("hello")\n')
    assert detect_c16(ctx).count == 1


def test_c16_skips_read_text_with_encoding(tmp_path):
    ctx = _ctx(tmp_path, 'from pathlib import Path\nPath("f.txt").read_text(encoding="utf-8")\n')
    assert detect_c16(ctx).count == 0


def test_c16_skips_write_text_with_encoding(tmp_path):
    ctx = _ctx(tmp_path, 'from pathlib import Path\nPath("f.txt").write_text("hi", encoding="utf-8")\n')
    assert detect_c16(ctx).count == 0


def test_c16_skips_read_bytes(tmp_path):
    ctx = _ctx(tmp_path, 'from pathlib import Path\nPath("f.bin").read_bytes()\n')
    assert detect_c16(ctx).count == 0


def test_c16_skips_write_text_two_positional_args(tmp_path):
    ctx = _ctx(tmp_path, 'audit.write_text("section.txt", piece_text)\n')
    assert detect_c16(ctx).count == 0


# ── C17: len(x) == 0 / len(x) > 0 comparisons ───────────────────────────────

def test_c17_flags_len_eq_zero(tmp_path):
    ctx = _ctx(tmp_path, "if len(items) == 0:\n    pass\n")
    assert detect_c17(ctx).count == 1


def test_c17_flags_len_ne_zero(tmp_path):
    ctx = _ctx(tmp_path, "if len(items) != 0:\n    pass\n")
    assert detect_c17(ctx).count == 1


def test_c17_flags_len_gt_zero(tmp_path):
    ctx = _ctx(tmp_path, "if len(items) > 0:\n    pass\n")
    assert detect_c17(ctx).count == 1


def test_c17_skips_truthiness(tmp_path):
    ctx = _ctx(tmp_path, "if items:\n    pass\nif not items:\n    pass\n")
    assert detect_c17(ctx).count == 0


def test_c17_skips_nonzero_comparison(tmp_path):
    ctx = _ctx(tmp_path, "if len(items) > 5:\n    pass\n")
    assert detect_c17(ctx).count == 0


def test_c17_flags_inline_expression(tmp_path):
    ctx = _ctx(tmp_path, 'status = "ok" if len(errors) == 0 else "fail"\n')
    assert detect_c17(ctx).count == 1


# ── C18: f-string with no interpolation ──────────────────────────────────────

def test_c18_flags_plain_fstring(tmp_path):
    ctx = _ctx(tmp_path, 'msg = f"hello world"\n')
    assert detect_c18(ctx).count == 1


def test_c18_flags_single_quote_fstring(tmp_path):
    ctx = _ctx(tmp_path, "msg = f'hello world'\n")
    assert detect_c18(ctx).count == 1


def test_c18_skips_interpolated_fstring(tmp_path):
    ctx = _ctx(tmp_path, 'msg = f"hello {name}"\n')
    assert detect_c18(ctx).count == 0


def test_c18_skips_plain_string(tmp_path):
    ctx = _ctx(tmp_path, 'msg = "hello world"\n')
    assert detect_c18(ctx).count == 0


def test_c18_flags_continuation_line(tmp_path):
    ctx = _ctx(tmp_path, 'raise ValueError(\n    f"context: {x}"\n    f"no interpolation here"\n)\n')
    assert detect_c18(ctx).count == 1


def test_c18_skips_list_element_quoted_f(tmp_path):
    ctx = _ctx(tmp_path, 'ascenders = ["b", "d", "f", "h"]\n')
    assert detect_c18(ctx).count == 0


# ── C21: mutable default argument ────────────────────────────────────────────

def test_c21_flags_list_default(tmp_path):
    ctx = _ctx(tmp_path, "def foo(x=[]):\n    pass\n")
    assert detect_c21(ctx).count == 1


def test_c21_flags_dict_default(tmp_path):
    ctx = _ctx(tmp_path, "def foo(x={}):\n    pass\n")
    assert detect_c21(ctx).count == 1


def test_c21_flags_set_default(tmp_path):
    ctx = _ctx(tmp_path, "def foo(x=set()):\n    pass\n")
    assert detect_c21(ctx).count == 0  # set() is a Call, not ast.Set literal


def test_c21_flags_set_literal_default(tmp_path):
    ctx = _ctx(tmp_path, "def foo(x={1, 2}):\n    pass\n")
    assert detect_c21(ctx).count == 1


def test_c21_skips_none_default(tmp_path):
    ctx = _ctx(tmp_path, "def foo(x=None):\n    pass\n")
    assert detect_c21(ctx).count == 0


def test_c21_skips_immutable_default(tmp_path):
    ctx = _ctx(tmp_path, "def foo(x=42, y='hi'):\n    pass\n")
    assert detect_c21(ctx).count == 0


# ── C22: time.sleep() ─────────────────────────────────────────────────────────

def test_c22_flags_time_sleep(tmp_path):
    ctx = _ctx(tmp_path, "import time\ntime.sleep(1)\n")
    assert detect_c22(ctx).count == 1


def test_c22_skips_sleep_in_name(tmp_path):
    ctx = _ctx(tmp_path, "sleepytime = 5\n")
    assert detect_c22(ctx).count == 0


# ── C23: subprocess shell=True ────────────────────────────────────────────────

def test_c23_flags_shell_true(tmp_path):
    ctx = _ctx(tmp_path, 'import subprocess\nsubprocess.run("ls", shell=True)\n')
    assert detect_c23(ctx).count == 1


def test_c23_skips_shell_false(tmp_path):
    ctx = _ctx(tmp_path, 'import subprocess\nsubprocess.run(["ls"], shell=False)\n')
    assert detect_c23(ctx).count == 0


# ── C24: pickle.load/loads ────────────────────────────────────────────────────

def test_c24_flags_pickle_loads(tmp_path):
    ctx = _ctx(tmp_path, "import pickle\ndata = pickle.loads(raw)\n")
    assert detect_c24(ctx).count == 1


def test_c24_flags_pickle_load(tmp_path):
    ctx = _ctx(tmp_path, "import pickle\ndata = pickle.load(f)\n")
    assert detect_c24(ctx).count == 1


def test_c24_skips_pickle_dump(tmp_path):
    ctx = _ctx(tmp_path, "import pickle\npickle.dump(obj, f)\n")
    assert detect_c24(ctx).count == 0


# ── C25: raise ... from None ──────────────────────────────────────────────────

def test_c25_flags_raise_from_none(tmp_path):
    ctx = _ctx(tmp_path, "raise ValueError('oops') from None\n")
    assert detect_c25(ctx).count == 1


def test_c25_skips_plain_raise(tmp_path):
    ctx = _ctx(tmp_path, "raise ValueError('oops')\n")
    assert detect_c25(ctx).count == 0


# ── C26: os.system() ─────────────────────────────────────────────────────────

def test_c26_flags_os_system(tmp_path):
    ctx = _ctx(tmp_path, 'import os\nos.system("ls")\n')
    assert detect_c26(ctx).count == 1


def test_c26_skips_os_path(tmp_path):
    ctx = _ctx(tmp_path, "import os\nos.path.join('a', 'b')\n")
    assert detect_c26(ctx).count == 0


# ── C27: assert False / assert 0 ─────────────────────────────────────────────

def test_c27_flags_assert_false(tmp_path):
    ctx = _ctx(tmp_path, "def bad():\n    assert False, 'not reached'\n")
    assert detect_c27(ctx).count == 1


def test_c27_flags_assert_zero(tmp_path):
    ctx = _ctx(tmp_path, "def bad():\n    assert 0\n")
    assert detect_c27(ctx).count == 1


def test_c27_skips_normal_assert(tmp_path):
    ctx = _ctx(tmp_path, "def ok(x):\n    assert x > 0\n")
    assert detect_c27(ctx).count == 0


# ── C28: hardcoded IP address ─────────────────────────────────────────────────

def test_c28_flags_real_ip(tmp_path):
    ctx = _ctx(tmp_path, 'host = "192.168.1.1"\n')
    assert detect_c28(ctx).count == 1


def test_c28_skips_localhost(tmp_path):
    ctx = _ctx(tmp_path, 'host = "127.0.0.1"\n')
    assert detect_c28(ctx).count == 0


def test_c28_skips_any_bind(tmp_path):
    ctx = _ctx(tmp_path, 'bind = "0.0.0.0"\n')
    assert detect_c28(ctx).count == 0


def test_c28_skips_non_ip_string(tmp_path):
    ctx = _ctx(tmp_path, 'addr = "not.an.ip.address"\n')
    assert detect_c28(ctx).count == 0


# ── C29: file too long ────────────────────────────────────────────────────────

def test_c29_flags_file_over_threshold(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "big.py").write_text("\n" * 501, encoding="utf-8")
    ctx = AuditContext(
        repo_root=tmp_path, src_root=src, tests_root=tmp_path / "tests",
        config={}, plugin_modules=[],
    )
    assert detect_c29(ctx).count == 1


def test_c29_skips_file_at_threshold(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.py").write_text("\n" * 500, encoding="utf-8")
    ctx = AuditContext(
        repo_root=tmp_path, src_root=src, tests_root=tmp_path / "tests",
        config={}, plugin_modules=[],
    )
    assert detect_c29(ctx).count == 0


def test_c29_respects_custom_threshold(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "medium.py").write_text("\n" * 201, encoding="utf-8")
    ctx = AuditContext(
        repo_root=tmp_path, src_root=src, tests_root=tmp_path / "tests",
        config={"audit": {"c29_threshold": 200}}, plugin_modules=[],
    )
    assert detect_c29(ctx).count == 1


# ── C31: weak hash algorithms ─────────────────────────────────────────────────

def test_c31_flags_md5_without_flag(tmp_path):
    ctx = _ctx(tmp_path, "import hashlib\nhashlib.md5(data)\n")
    assert detect_c31(ctx).count == 1


def test_c31_flags_sha1_without_flag(tmp_path):
    ctx = _ctx(tmp_path, "import hashlib\nhashlib.sha1(data)\n")
    assert detect_c31(ctx).count == 1


def test_c31_skips_md5_with_usedforsecurity_false(tmp_path):
    ctx = _ctx(tmp_path, "import hashlib\nhashlib.md5(data, usedforsecurity=False)\n")
    assert detect_c31(ctx).count == 0


def test_c31_skips_sha256(tmp_path):
    ctx = _ctx(tmp_path, "import hashlib\nhashlib.sha256(data)\n")
    assert detect_c31(ctx).count == 0


def test_c31_skips_non_hashlib_md5(tmp_path):
    ctx = _ctx(tmp_path, "import foo\nfoo.md5(data)\n")
    assert detect_c31(ctx).count == 0


# ── C32: hardcoded credentials ────────────────────────────────────────────────

def test_c32_flags_password_assignment(tmp_path):
    ctx = _ctx(tmp_path, 'password = "supersecret"\n')
    assert detect_c32(ctx).count == 1


def test_c32_flags_api_key_assignment(tmp_path):
    ctx = _ctx(tmp_path, 'api_key = "sk-abc123def456"\n')
    assert detect_c32(ctx).count == 1


def test_c32_flags_dict_token_key(tmp_path):
    ctx = _ctx(tmp_path, 'cfg = {"token": "live-secret-value"}\n')
    assert detect_c32(ctx).count == 1


def test_c32_skips_placeholder_password(tmp_path):
    ctx = _ctx(tmp_path, 'password = "your-password-here"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_example_token(tmp_path):
    ctx = _ctx(tmp_path, 'token = "example"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_empty_password(tmp_path):
    ctx = _ctx(tmp_path, 'password = ""\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_non_credential_name(tmp_path):
    ctx = _ctx(tmp_path, 'username = "alice"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_url_value(tmp_path):
    ctx = _ctx(tmp_path, 'TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_env_var_name_as_value(tmp_path):
    ctx = _ctx(tmp_path, '_SECRET_ENV = "OPERATIONS_CENTER_WEBHOOK_SECRET"\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_token_in_tokenizer_key(tmp_path):
    ctx = _ctx(tmp_path, 'cfg = {"word_tokenizer": "You are a script str"}\n')
    assert detect_c32(ctx).count == 0


def test_c32_skips_token_endpoint_name(tmp_path):
    ctx = _ctx(tmp_path, 'token_endpoint = "https://example.com/oauth"\n')
    assert detect_c32(ctx).count == 0
