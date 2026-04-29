from __future__ import annotations

import importlib

from custodian.audit_kit.detector import Detector


def _import_target(target: str):
    """Resolve a 'module.path:attr' string to the attribute object."""
    if ":" not in target:
        raise ValueError(f"Invalid plugin target '{target}', expected module.path:attr")
    module_path, attr_name = target.split(":", 1)
    try:
        module = importlib.import_module(module_path)
    except Exception as exc:
        raise ImportError(f"Failed to import plugin module '{module_path}' from '{target}'") from exc
    try:
        return getattr(module, attr_name)
    except AttributeError as exc:
        raise ImportError(f"Plugin attribute '{attr_name}' not found in module '{module_path}'") from exc


def load_plugins(config: dict) -> list:
    """
    Load entries under config['plugins'] — protocol-style helpers
    (LogScanner, StateScanner, etc.) made available to detectors via
    AuditContext.plugin_modules.

    Each entry is either a string 'module.path:attr' or {'module': '...'}.
    """
    loaded = []
    for entry in config.get("plugins", []):
        target = entry["module"] if isinstance(entry, dict) else entry
        loaded.append(_import_target(target))
    return loaded


def load_detectors(config: dict) -> list[Detector]:
    """
    Load entries under config['detectors'] — callables that return list[Detector].

    Each entry is either a string 'module.path:attr' or {'module': '...'}.
    Each resolved attribute must be a callable; calling it must return a
    list of Detector. This separation from plugins keeps detector
    contributions explicit and discoverable in the .custodian.yaml.
    """
    detectors: list[Detector] = []
    for entry in config.get("detectors", []):
        target = entry["module"] if isinstance(entry, dict) else entry
        contributor = _import_target(target)
        if not callable(contributor):
            raise TypeError(f"Detector contributor '{target}' is not callable")
        produced = contributor()
        if not isinstance(produced, list) or not all(isinstance(d, Detector) for d in produced):
            raise TypeError(f"Detector contributor '{target}' must return list[Detector]")
        detectors.extend(produced)
    return detectors
