from __future__ import annotations


class OCLogScanner:
    def parse_event(self, line: str) -> dict | None:
        if "event=" not in line:
            return None
        return {"raw": line.strip()}
