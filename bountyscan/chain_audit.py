"""Write-only diagnostics for the live window: a per-target audit trail.

Two side files under the digests directory, neither read by any live system and neither able to change
the scan or the finding output (same contract as chain_digest.Health):

  * <date>.targets.json  - one row per target the pipeline SAW: address, protocol name, TVL at scan time,
    which of the 8 patterns matched, how many generators ran, and the outcome. If the window ends with
    0 confirmed, this file is the evidence that it saw N real protocols and 0 drains.
  * protocols.json       - a persistent address -> DeFiLlama protocol name/TVL map, written by discovery
    so the per-target rows can carry the protocol's name.

Everything here is best-effort and never raises; a failure drops a diagnostic line, never a scan.
"""
from __future__ import annotations

import json
import threading
import time
from pathlib import Path

_lock = threading.Lock()
_names_cache: dict = {"path": None, "mtime": None, "map": {}}

# the outcomes a target row can carry
OUTCOMES = ("CONFIRMED", "DISCARDED", "SKIPPED_LOW_TVL", "ERROR")


def _today() -> str:
    return time.strftime("%Y-%m-%d", time.gmtime())


def write_protocol_map(directory, rows) -> None:
    """Merge DeFiLlama rows [{address,name,tvl}] into <dir>/protocols.json (address -> {name, llama_tvl})."""
    try:
        d = Path(directory)
        d.mkdir(parents=True, exist_ok=True)
        p = d / "protocols.json"
        with _lock:
            cur = {}
            if p.exists():
                try:
                    cur = json.loads(p.read_text(encoding="utf-8"))
                except Exception:
                    cur = {}
            for r in rows or []:
                a = (r.get("address") or "").lower()
                if a:
                    cur[a] = {"name": r.get("name"), "llama_tvl": r.get("tvl")}
            p.write_text(json.dumps(cur, indent=2), encoding="utf-8")
    except Exception:
        pass


def load_protocol_names(directory) -> dict:
    """{address_lower: protocol_name} from <dir>/protocols.json, cached by file mtime. Returns {} if absent."""
    try:
        p = Path(directory) / "protocols.json"
        if not p.exists():
            return {}
        mtime = p.stat().st_mtime
        with _lock:
            if _names_cache["path"] == str(p) and _names_cache["mtime"] == mtime:
                return _names_cache["map"]
            raw = json.loads(p.read_text(encoding="utf-8"))
            m = {a.lower(): (v or {}).get("name") for a, v in raw.items()}
            _names_cache.update({"path": str(p), "mtime": mtime, "map": m})
            return m
    except Exception:
        return {}


class TargetAudit:
    """Per-target audit rows in <dir>/<date>.targets.json, keyed by address. record() MERGES fields, so
    the scan phase (name/tvl/patterns/outcome) and the payload phase (generators_run) can each fill their
    part of the same row. Best-effort, never raises; never read by a live system."""

    def __init__(self, directory):
        self.dir = Path(directory)
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
        except Exception:
            pass

    def _path(self) -> Path:
        return self.dir / (_today() + ".targets.json")

    def record(self, address: str, **fields) -> None:
        if not address:
            return
        a = address.lower()
        try:
            with _lock:
                p = self._path()
                d = {}
                if p.exists():
                    try:
                        d = json.loads(p.read_text(encoding="utf-8"))
                    except Exception:
                        d = {}
                row = d.get(a, {"address": a})
                for k, v in fields.items():
                    if v is not None:
                        row[k] = v
                row.setdefault("address", a)
                d[a] = row
                p.write_text(json.dumps(d, indent=2), encoding="utf-8")
        except Exception:
            pass
