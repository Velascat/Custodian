from __future__ import annotations


def reconcile_stale_running_issues(records: list[dict], max_age_days: int) -> list[dict]:
    """Return stale running records so consumers can decide how to resolve them."""
    return [record for record in records if record.get("age_days", 0) > max_age_days]
