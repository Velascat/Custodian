# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 Velascat
from __future__ import annotations


def cleanup_stale_state(records: list[dict], stale_state_days: int) -> list[dict]:
    """Select stale state records for cleanup in caller-controlled workflows."""
    return [record for record in records if record.get("age_days", 0) >= stale_state_days]
