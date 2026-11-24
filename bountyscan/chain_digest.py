"""Daily digest for the live chain-exploit payload phase.

Thread-safe file accumulator: one JSON per UTC day at <dir>/YYYY-MM-DD.json, updated in place as the scan
workers process contracts. No email, no dashboard - just the file, so the day-1 numbers are auditable.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_lock = threading.Lock()


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


class Digest:
    def __init__(self, directory):
        self.dir = Path(directory)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except OSError:
            pass

    def _path(self) -> Path:
        return self.dir / (_today() + ".json")

    def _blank(self) -> dict:
        return {"date": _today(), "targets_scanned": 0, "patterns_matched": 0, "generators_run": 0,
                "confirmed": 0, "discarded_second_block": 0, "confirmed_usd": 0.0,
                "skipped_fp_clusters": 0, "confirmed_targets": []}

    def record(self, target: str, matched: int = 0, ran: int = 0, confirmed: int = 0,
               discarded_2nd: int = 0, confirmed_usd: float = 0.0, skipped: bool = False) -> None:
        """Accumulate one contract's chain-payload outcome into today's digest. Best-effort; never raises."""
        try:
            with _lock:
                p = self._path()
                d = self._blank()
                if p.exists():
                    try:
                        d = json.loads(p.read_text(encoding="utf-8"))
                    except Exception:
                        d = self._blank()
                d["targets_scanned"] = d.get("targets_scanned", 0) + 1
                d["patterns_matched"] = d.get("patterns_matched", 0) + int(matched)
                d["generators_run"] = d.get("generators_run", 0) + int(ran)
                d["confirmed"] = d.get("confirmed", 0) + int(confirmed)
                d["discarded_second_block"] = d.get("discarded_second_block", 0) + int(discarded_2nd)
                d["confirmed_usd"] = round(d.get("confirmed_usd", 0.0) + float(confirmed_usd), 2)
                if skipped:
                    d["skipped_fp_clusters"] = d.get("skipped_fp_clusters", 0) + 1
                if confirmed > 0 and target not in d.get("confirmed_targets", []):
                    d.setdefault("confirmed_targets", []).append(target)
                p.write_text(json.dumps(d, indent=2), encoding="utf-8")
        except Exception:
            pass
