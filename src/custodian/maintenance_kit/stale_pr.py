# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Velascat
from __future__ import annotations


def close_stale_prs(prs: list[dict], stale_pr_days: int) -> list[dict]:
    """Select stale PRs, leaving the close action to consumer-owned integrations."""
    return [pr for pr in prs if pr.get("age_days", 0) >= stale_pr_days]
