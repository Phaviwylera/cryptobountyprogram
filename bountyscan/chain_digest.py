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
                "confirmed": 0, "discarded_second_block": 0, "below_threshold": 0, "confirmed_usd": 0.0,
                "skipped_fp_clusters": 0, "skipped_low_tvl": 0, "confirmed_targets": []}

    def _rmw(self, mutate) -> None:
        """Read-modify-write today's digest under the shared lock. Best-effort; never raises."""
        try:
            with _lock:
                p = self._path()
                d = self._blank()
                if p.exists():
                    try:
                        d = json.loads(p.read_text(encoding="utf-8"))
                    except Exception:
                        d = self._blank()
                mutate(d)
                p.write_text(json.dumps(d, indent=2), encoding="utf-8")
        except Exception:
            pass

    def record(self, target: str, matched: int = 0, ran: int = 0, confirmed: int = 0,
               discarded_2nd: int = 0, confirmed_usd: float = 0.0, skipped: bool = False,
               below_threshold: int = 0) -> None:
        """Accumulate one contract's chain-payload outcome into today's digest. A contract that reaches
        the payload phase is counted as scanned here; a contract dropped earlier by the TVL floor is NOT
        (see record_skip_low_tvl). Best-effort; never raises."""
        def mutate(d):
            d["targets_scanned"] = d.get("targets_scanned", 0) + 1
            d["patterns_matched"] = d.get("patterns_matched", 0) + int(matched)
            d["generators_run"] = d.get("generators_run", 0) + int(ran)
            d["confirmed"] = d.get("confirmed", 0) + int(confirmed)
            d["discarded_second_block"] = d.get("discarded_second_block", 0) + int(discarded_2nd)
            d["below_threshold"] = d.get("below_threshold", 0) + int(below_threshold)
            d["confirmed_usd"] = round(d.get("confirmed_usd", 0.0) + float(confirmed_usd), 2)
            if skipped:
                d["skipped_fp_clusters"] = d.get("skipped_fp_clusters", 0) + 1
            if confirmed > 0 and target not in d.get("confirmed_targets", []):
                d.setdefault("confirmed_targets", []).append(target)
        self._rmw(mutate)

    def record_skip_low_tvl(self, chain: str = "", address: str = "", tvl_usd: float | None = None) -> None:
        """A candidate dropped by the pre-detection TVL floor: counted separately in skipped_low_tvl and
        deliberately NOT counted as scanned (it never reached pattern detection)."""
        self._rmw(lambda d: d.__setitem__("skipped_low_tvl", d.get("skipped_low_tvl", 0) + 1))


class Health:
    """Write-only diagnostic alongside the main digest: <dir>/YYYY-MM-DD.health.json. Tells apart a healthy
    empty run (scanner found nothing) from a broken one (RPC/forge failing, no recent targets). Never read
    by any live system, never affects the scan or finding output; best-effort, never raises."""
    def __init__(self, directory):
        self.dir = Path(directory)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _path(self) -> Path:
        return self.dir / (_today() + ".health.json")

    def _blank(self) -> dict:
        return {"date": _today(), "rpc_calls": 0, "rpc_errors": 0, "forge_runs": 0, "forge_timeouts": 0,
                "forge_errors": 0, "last_target_at": None, "last_finding_at": None}

    def record(self, rpc_calls: int = 0, rpc_errors: int = 0, forge_runs: int = 0, forge_timeouts: int = 0,
               forge_errors: int = 0, target: bool = False, finding: bool = False) -> None:
        try:
            with _lock:
                p = self._path()
                d = self._blank()
                if p.exists():
                    try:
                        d = json.loads(p.read_text(encoding="utf-8"))
                    except Exception:
                        d = self._blank()
                d["rpc_calls"] = d.get("rpc_calls", 0) + int(rpc_calls)
                d["rpc_errors"] = d.get("rpc_errors", 0) + int(rpc_errors)
                d["forge_runs"] = d.get("forge_runs", 0) + int(forge_runs)
                d["forge_timeouts"] = d.get("forge_timeouts", 0) + int(forge_timeouts)
                d["forge_errors"] = d.get("forge_errors", 0) + int(forge_errors)
                now = time.time()
                if target:
                    d["last_target_at"] = now
                if finding:
                    d["last_finding_at"] = now
                p.write_text(json.dumps(d, indent=2), encoding="utf-8")
        except Exception:
            pass
