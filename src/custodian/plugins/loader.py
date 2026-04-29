from __future__ import annotations

import importlib


def load_plugins(config: dict) -> list:
    """Read config['plugins'] entries and import each target to enable local extensions."""
    loaded = []
    for entry in config.get("plugins", []):
        target = entry["module"] if isinstance(entry, dict) else entry
        if ":" not in target:
            raise ValueError(f"Invalid plugin target '{target}', expected module.path:attr")
        module_path, attr_name = target.split(":", 1)
        try:
            module = importlib.import_module(module_path)
        except Exception as exc:
            raise ImportError(f"Failed to import plugin module '{module_path}' from '{target}'") from exc
        try:
            loaded.append(getattr(module, attr_name))
        except AttributeError as exc:
            raise ImportError(f"Plugin attribute '{attr_name}' not found in module '{module_path}'") from exc
    return loaded
