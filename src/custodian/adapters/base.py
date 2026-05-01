# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
"""ToolAdapter abstract base — all external-tool adapters implement this."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path
from typing import ClassVar

from custodian.core.finding import Finding


class ToolAdapter(ABC):
    """Contract for every external-tool adapter.

    Subclasses MUST set the ``name`` class attribute and implement
    ``is_available`` and ``run``.

    The runner calls ``is_available`` first; if False it emits a
    TOOL_UNAVAILABLE finding and skips ``run`` entirely — so ``run``
    never has to handle a missing binary.
    """

    name: ClassVar[str]

    @abstractmethod
    def is_available(self) -> bool:
        """Return True iff the underlying tool is installed and executable."""

    @abstractmethod
    def run(self, repo_path: Path, config: dict) -> list[Finding]:
        """Run the tool against ``repo_path`` and return normalized findings.

        Args:
            repo_path: Root of the repository being audited.
            config:    Raw .custodian.yaml dict (old schema for now).

        Returns:
            Zero or more Finding objects.  Never raises — catch tool errors
            and return a TOOL_ERROR finding instead.
        """
