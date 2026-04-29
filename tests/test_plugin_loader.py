from __future__ import annotations

from pathlib import Path
import sys

import pytest

from custodian.plugins.loader import load_plugins


def test_load_plugins_imports_sample_callable():
    fixture_root = Path("tests/fixtures/sample_consumer").resolve()
    sys.path.insert(0, str(fixture_root))
    try:
        loaded = load_plugins({"plugins": [{"module": "_custodian.log_scanner:OCLogScanner"}]})
        assert loaded
        assert loaded[0].__name__ == "OCLogScanner"
    finally:
        sys.path.remove(str(fixture_root))


def test_load_plugins_missing_module_error():
    with pytest.raises(ImportError, match="Failed to import plugin module"):
        load_plugins({"plugins": ["does.not.exist:Thing"]})
