"""bountyscan web server: a tech dashboard with Live Scan and Immunefi Scan.

Stdlib only (http.server + threads). One background worker drains the scan queue continuously,
so once Live Scan is started it runs 24/7, contract after contract, and every confirmed
fund-theft finding lands on the Results page with a full report.

Endpoints (JSON):
  GET  /api/status            -> queue counts, worker state, current target
  GET  /api/results           -> confirmed-vulnerable contracts (summary rows)
  GET  /api/result?chain&addr -> one contract's full report (markdown + findings)
  GET  /api/safe              -> recently cleared contracts
  POST /api/live/start        -> begin 24/7 live discovery+scan (body: {chain, from_block?, min_balance?})
  POST /api/live/stop         -> pause the worker
  POST /api/immunefi/scan     -> queue a program's assets (body: {scope_path} or {program, assets:[...]})
  POST /api/enqueue           -> add addresses (body: {addresses:[...], chain})
The UI is served from /.
"""
from __future__ import annotations

import collections
import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__
from .auto import AutoConfig, discover_blocks, run_queue
from .rpc import RPC, RPCError
from .state import Store
from .ui import INDEX_HTML

_FORGE_OK = None


def _forge_ok() -> bool:
    """Cached check of whether the forge binary is available (snapshot is polled often)."""
    global _FORGE_OK
    if _FORGE_OK is None:
        try:
            from .forge_verify import forge_available
            _FORGE_OK = forge_available()
        except Exception:
            _FORGE_OK = False
    return _FORGE_OK


class Worker:
    """Owns the scan loop in a background thread. Thread-safe via a lock around the store."""

    def __init__(self, store: Store, cfg: AutoConfig, rpc: RPC | None):
        self.store = store
        self.cfg = cfg
        self.rpc = rpc
        self.lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self.mode = "idle"               # idle | live | draining
        self.chain = cfg_default_chain()
        self.cursor: int | None = None
        self.min_balance_wei = 0
        self.min_value_usd = 0.0
        self._last_recheck = 0.0
        self.current = None
        self.last_error = None
        self.started_at = None
        self.scanned = 0
        # Parallel scanning: N worker threads each claim + scan a contract. Source fetches are network-
        # bound, so a small pool multiplies backfill throughput. Set BOUNTYSCAN_SCAN_WORKERS=1 for serial.
        self.scan_workers = max(1, min(16, int(os.environ.get("BOUNTYSCAN_SCAN_WORKERS", "4"))))
        self.currents: dict = {}           # active scans: thread name -> {chain, address}
        self._count_lock = threading.Lock()
        self._pool: list = []
        # live progress for the dashboard
        self.stage = "Idle"
        self.stage_at = time.time()
        self._seq = 0
        self.events: collections.deque = collections.deque(maxlen=200)
        self.batches: list[dict] = []     # Immunefi/program scans: {program, items, started}
        self.payload = collections.Counter()   # dynamic payload-attack outcomes this session
        self.payload_running = 0               # findings currently under a forge payload test
        cfg.on_stage = self.set_stage
        cfg.on_event = self.add_event
        cfg.on_payload = self._record_payload
        from .backfill import Backfill
        self.backfill = Backfill(store, rpc, on_event=self.add_event, on_queue=self._backfill_has_work)

    def _backfill_has_work(self) -> None:
        # Backfill queued contracts: make sure the scan worker is running to drain them.
        if self.mode == "idle":
            self.start_drain()

    def set_stage(self, text: str) -> None:
        self.stage = text
        self.stage_at = time.time()

    def add_event(self, kind: str, msg: str) -> None:
        self._seq += 1
        self.events.append({"id": self._seq, "t": time.time(), "kind": kind, "msg": msg})

    def _record_payload(self, event: str, n: int = 1) -> None:
        # event: "start"/"end" bracket a contract's payload attack; otherwise an outcome name.
        if event == "start":
            self.payload_running += n
        elif event == "end":
            self.payload_running = max(0, self.payload_running - n)
        else:
            self.payload[event] += n
            self.payload["total"] += n

    def add_batch(self, program: str, items: list[tuple[str, str]]) -> None:
        self.batches.append({"program": program, "items": [(c.lower(), a.lower()) for c, a in items], "started": time.time()})
        self.batches = self.batches[-10:]

    def _run(self):
        """Coordinator thread: block discovery (live), periodic value re-check, and idle detection.
        The actual contract scanning runs in the parallel _scan_loop pool."""
        while not self._stop.is_set():
            try:
                if self.mode == "live" and self.rpc is not None:
                    self._discover_step()
                if self.rpc is not None and time.time() - self._last_recheck > 600:
                    self._recheck_vulnerable_value()
                idle_now = (self.mode == "draining" and not self.store.pending_count()
                            and not self.backfill.running and not self.currents and self.payload_running == 0)
                if idle_now:
                    self.mode = "idle"
                    self.set_stage("Idle - queue finished")
                    self.add_event("info", "All queued contracts processed.")
                    break
                if self.mode == "live" and not self.currents:
                    self.set_stage(f"Waiting for new blocks on {self.chain}…")
                time.sleep(2.0)
            except ExplorerFatalGuard as exc:
                self.last_error = str(exc)
                self.mode = "idle"
                break
            except Exception as exc:  # never let the coordinator die
                self.last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(5.0)

    def _scan_loop(self):
        """One parallel scan worker: claim the next due contract and scan it, until stopped."""
        while not self._stop.is_set():
            if self.mode not in ("live", "draining"):
                time.sleep(1.0)
                continue
            try:
                row = self.store.claim_one()
            except Exception as exc:
                self.last_error = f"claim: {type(exc).__name__}: {exc}"
                time.sleep(3.0)
                continue
            if not row:
                time.sleep(2.0)
                continue
            try:
                self._scan_once(row)
            except Exception as exc:  # never let a scan thread die
                self.last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(2.0)

    def _discover_step(self):
        try:
            head = self.rpc.block_number()
        except RPCError as exc:
            self.last_error = str(exc)
            return
        if self.cursor is None:
            self.cursor = head - 1
        if head > self.cursor:
            end = min(head, self.cursor + 25)
            with self.lock:
                discover_blocks(self.store, self.rpc, self.chain, self.cursor + 1, end, self.cfg)
            self.cursor = end

    FUNDED_ALERT_USD = 1000.0

    def _recheck_vulnerable_value(self) -> None:
        """Funds often arrive after deployment. Re-read what every vulnerable contract holds;
        alert when one crosses the funded threshold - that is the one worth a PoC and a report."""
        from .auto import recheck_value
        from .sources import chain_id_of
        self._last_recheck = time.time()
        for row in self.store.by_status("vulnerable")[:100]:
            try:
                if chain_id_of(row["chain"]) != chain_id_of(self.chain):
                    continue      # this RPC only reads its own chain
                old, new = recheck_value(self.store, row, self.rpc)
            except Exception:
                continue
            if new is not None and new >= self.FUNDED_ALERT_USD and (old or 0) < self.FUNDED_ALERT_USD:
                self.add_event("funded", f"FUNDED - vulnerable {row['address']}"
                               + (f" ({row['name']})" if row["name"] else "") + f" now holds ${new:,.0f}. Prioritise this one.")

    def _scan_once(self, row) -> None:
        tn = threading.current_thread().name
        self.currents[tn] = {"chain": row["chain"], "address": row["address"]}
        self.current = self.currents[tn]
        from .auto import process
        self.cfg.min_balance_wei = self.min_balance_wei
        self.cfg.min_value_usd = self.min_value_usd
        try:
            status = process(self.store, row, self.cfg)
        except Exception as exc:
            self.store.update(row["chain"], row["address"], status="error", error=str(exc)[:300])
            status = "error"
        with self._count_lock:
            self.scanned += 1
        with self.lock:   # serialize the shared summary-file write across scan threads
            from .contract_report import write_summary
            write_summary(self.store, self.cfg.out_dir)
        self.currents.pop(tn, None)
        self.current = {"chain": row["chain"], "address": row["address"], "status": status}
        done = self.store.fetch_one(row["chain"], row["address"])
        name = (done["name"] if done and done["name"] else "")
        label = f"{row['address']}" + (f" ({name})" if name else "")
        worth = ""
        if done and done["value_usd"] is not None:
            worth = f" Holds ${done['value_usd']:,.2f}."
        text = {
            "vulnerable": f"VULNERABLE - {label}: {done['findings'] if done else '?'} confirmed fund-theft finding(s), worst {done['max_severity'] if done else '?'}.{worth} Report saved.",
            "safe": f"SAFE - {label}: no fund-theft pattern" + (f" {done['error']}" if done and done['error'] else "") + f".{worth}",
            "unverified": f"Not verified on the explorer yet - {label}. Will retry automatically.",
            "unverified_final": f"Gave up - {label} was never verified.",
            "no_code": f"Skipped - {label} has no code (self-destructed or EOA).",
            "low_value": f"Skipped - {label} holds less than the minimum value.{worth}",
            "error": f"Error - {label}: {done['error'] if done else ''}",
        }.get(status, f"{status} - {label}")
        self.add_event(status, text)

    def ensure_thread(self):
        self._stop.clear()   # a Start right after Stop must cancel the pending stop
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, daemon=True, name="bountyscan-worker")
            self._thread.start()
        # (re)start the parallel scan pool
        self._pool = [t for t in self._pool if t.is_alive()]
        while len(self._pool) < self.scan_workers:
            t = threading.Thread(target=self._scan_loop, daemon=True, name=f"bscan-{len(self._pool)+1}")
            t.start()
            self._pool.append(t)

    def start_live(self, chain, from_block, min_balance_wei, min_value_usd: float = 0.0):
        if self.rpc is None:
            raise RuntimeError("live scan needs an RPC endpoint (set RPC_URL)")
        self.chain = chain
        self.cursor = (from_block - 1) if from_block is not None else None
        self.min_balance_wei = min_balance_wei
        self.min_value_usd = max(0.0, float(min_value_usd or 0))
        self.mode = "live"
        self.started_at = self.started_at or time.time()
        self.set_stage(f"Starting live scan on {chain}…")
        self.add_event("info", f"Live scan started on {chain}" + (f" from block {from_block:,}" if from_block else " at the chain head") + ".")
        self.ensure_thread()

    def start_drain(self):
        if self.mode != "live":   # live mode already drains the queue too
            self.mode = "draining"
        self.started_at = self.started_at or time.time()
        self.ensure_thread()

    def stop(self):
        self.mode = "idle"
        self._stop.set()
        self.set_stage("Stopped")
        self.add_event("info", "Scanning stopped. The current contract finishes, then the worker pauses.")

    def _batch_progress(self) -> list[dict]:
        out = []
        for b in self.batches:
            statuses = []
            for c, a in b["items"]:
                r = self.store.fetch_one(c, a)
                statuses.append(r["status"] if r else "queued")
            done = sum(s not in ("queued", "unverified") for s in statuses)
            out.append({"program": b["program"], "total": len(statuses), "done": done,
                        "waiting_verification": statuses.count("unverified"),
                        "vulnerable": statuses.count("vulnerable"), "safe": statuses.count("safe")})
        return out

    def snapshot(self):
        # Do NOT take self.lock here: the worker holds it for a whole scan (network fetches,
        # verification) which can take tens of seconds and would freeze the dashboard.
        # The Store has its own short internal lock, which is all a read needs.
        counts = self.store.counts()
        return {
            "mode": self.mode,
            "chain": self.chain,
            "cursor": self.cursor,
            "current": self.current,
            "scanned_this_session": self.scanned,
            "pending": counts.get("queued", 0) + counts.get("unverified", 0),
            "counts": counts,
            "rpc": self.rpc.url if self.rpc else None,
            "last_error": self.last_error,
            "started_at": self.started_at,
            "verify": self.cfg.verify,
            "version": __version__,
            "stage": self.stage,
            "stage_age": round(time.time() - self.stage_at, 1),
            "events": list(self.events)[-60:],
            "batches": self._batch_progress(),
            "value": self.store.value_stats(),
            "backfill": self.backfill.snapshot(),
            "min_value_usd": self.min_value_usd,
            "payload": {"counts": dict(self.payload), "running": self.payload_running,
                        "forge": bool(_forge_ok())},
            "scan_workers": self.scan_workers,
            "active_scans": list(self.currents.values()),
        }


class ExplorerFatalGuard(RuntimeError):
    pass


def cfg_default_chain():
    return os.environ.get("BOUNTYSCAN_CHAIN", "ethereum")


class Handler(BaseHTTPRequestHandler):
    worker: Worker = None  # set on the class before serving
    server_version = "bountyscan/0.3"

    def log_message(self, *a):  # quiet; the worker prints its own progress
        pass

    def _send(self, code, payload, ctype="application/json", filename=None):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        if filename:
            self.send_header("Content-Disposition", f'attachment; filename="{filename}"')
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def _all_reports_text(self) -> str:
        """Every confirmed threat's full report + findings.json, concatenated into one text document."""
        import time as _t
        rows = self.worker.store.by_status("vulnerable")
        out = ["=" * 100,
               f"BOUNTYSCAN - ALL CONFIRMED THREATS  (rules v{__version__})",
               f"{len(rows)} contract(s)  -  generated {_t.strftime('%Y-%m-%d %H:%M:%S UTC', _t.gmtime())}",
               "Each entry carries its full report (what is wrong / how it is exploited / how to fix) and findings.json.",
               "These are the contracts confirmed by the independent second verification pass.",
               "=" * 100]
        total = 0.0
        for i, r in enumerate(rows, 1):
            keys = r.keys()
            v = (r["value_usd"] if "value_usd" in keys and r["value_usd"] else 0) or 0
            total += v
            out += ["\n" + "#" * 100,
                    f"# #{i}  {r['address']}  chain={r['chain']}  severity={r['max_severity']}  "
                    f"findings={r['findings']}  value_usd={v:.2f}  name={r['name'] or ''}",
                    "#" * 100 + "\n"]
            rep = r["report"]
            if rep and Path(rep).exists():
                out.append(Path(rep).read_text(encoding="utf-8"))
                fj = Path(rep).parent / "findings.json"
                if fj.exists():
                    out += ["\n--- findings.json ---", fj.read_text(encoding="utf-8")]
            else:
                out.append("[report file not on disk]")
        out += ["\n" + "=" * 100,
                f"TOTAL value_usd across all threats: ${total:,.2f}",
                "NOTE: value_usd is the contract's holdings heuristic, NOT the directly stealable amount."]
        return "\n".join(out)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode() or "{}")
        except json.JSONDecodeError:
            return {}

    # ---- routing ------------------------------------------------------------
    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        w = self.worker
        if u.path in ("/", "/index.html"):
            return self._send(200, INDEX_HTML.encode(), "text/html; charset=utf-8")
        if u.path in ("/live", "/live/"):
            from .live_page import LIVE_HTML
            return self._send(200, LIVE_HTML.encode(), "text/html; charset=utf-8")
        if u.path == "/api/live/feed":
            import time as _t
            fw = w.store.fund_watch_map()
            now = _t.time()
            out = []
            for r in w.store.watch_targets(60):     # live launches + confirmed exploits + value-holders + receiving
                f = fw.get((r["chain"], r["address"]))
                last_wei = (f["last_wei"] if f else None) or (str(r["balance_wei"]) if r["balance_wei"] else "0")
                first_wei = int(f["first_wei"] or 0) if f else None
                receiving = bool(f and int(f["last_wei"] or 0) > (first_wei or 0))
                out.append({
                    "chain": r["chain"], "address": r["address"], "name": r["name"],
                    "severity": r["max_severity"], "findings": r["findings"],
                    "value_usd": r["value_usd"] if "value_usd" in r.keys() else None,
                    "age_sec": now - (r["updated"] or now),
                    "wei": str(last_wei), "inflows": (f["inflows"] if f else 0), "receiving": receiving,
                })
            return self._send(200, {"contracts": out, "mode": w.mode, "ts": now})
        if u.path == "/api/status":
            return self._send(200, w.snapshot())
        if u.path == "/api/meta":
            from .detectors import DETECTORS
            return self._send(200, {"version": __version__,
                                    "detectors": [{"id": d.id, "severity": d.severity, "title": d.title} for d in DETECTORS]})
        if u.path == "/api/results":
            return self._send(200, {"results": [self._row(r) for r in w.store.by_status("vulnerable")]})
        if u.path in ("/api/report/all.txt", "/download/reports.txt"):
            import time as _t
            fn = f"bountyscan_threats_{_t.strftime('%Y%m%d')}.txt"
            return self._send(200, self._all_reports_text().encode("utf-8"),
                              "text/plain; charset=utf-8", filename=fn)
        if u.path == "/api/safe":
            return self._send(200, {"safe": [self._row(r) for r in w.store.by_status("safe")[:200]]})
        if u.path == "/api/errors":
            return self._send(200, {"errors": [self._row(r) for r in w.store.by_status("error")[:200]]})
        if u.path == "/api/result":
            chain = (q.get("chain") or [""])[0].lower()
            addr = (q.get("addr") or [""])[0].lower()
            row = w.store.fetch_one(chain, addr)
            if not row or not row["report"]:
                return self._send(404, {"error": "no report"})
            rep = Path(row["report"])
            findings = rep.parent / "findings.json"
            return self._send(200, {
                "row": self._row(row),
                "markdown": rep.read_text(encoding="utf-8") if rep.exists() else "",
                "findings": json.loads(findings.read_text(encoding="utf-8")) if findings.exists() else {},
            })
        return self._send(404, {"error": "not found"})

    def do_HEAD(self):
        self.do_GET()

    def do_POST(self):
        u = urlparse(self.path)
        w = self.worker
        b = self._body()
        try:
            if u.path == "/api/live/start":
                chain = b.get("chain", cfg_default_chain())
                fb = b.get("from_block")
                mb = int(float(b.get("min_balance", 0) or 0) * 10**18)
                w.start_live(chain, fb, mb, float(b.get("min_value_usd", 0) or 0))
                return self._send(200, {"ok": True, "mode": w.mode, "min_value_usd": w.min_value_usd})
            if u.path == "/api/live/stop":
                w.stop()
                return self._send(200, {"ok": True, "mode": w.mode})
            if u.path == "/api/backfill/start":
                days = max(1, min(3650, int(b.get("days", 730) or 730)))   # default 2 years
                min_txs = max(0, int(b.get("min_txs", 10) or 0))
                w.backfill.start(b.get("chain", cfg_default_chain()), days, min_txs)
                w.start_drain()
                return self._send(200, {"ok": True, "backfill": w.backfill.snapshot()})
            if u.path == "/api/requeue":
                # Re-verify already-judged contracts, so nothing stays flagged on stale rules - even a
                # contract manually marked vulnerable before gets re-scanned by the current pipeline.
                scope = (b.get("scope") or "vulnerable").lower()
                n = w.store.requeue_status("vulnerable", 2e9)
                if scope == "all":
                    n += w.store.requeue_status("safe", 1.5e9)
                w.start_drain()
                w.add_event("info", f"Re-checking {n} already-judged contract(s) ({scope}) against the current rules.")
                return self._send(200, {"ok": True, "requeued": n, "scope": scope})
            if u.path == "/api/backfill/stop":
                w.backfill.stop()
                return self._send(200, {"ok": True, "backfill": w.backfill.snapshot()})
            if u.path == "/api/enqueue":
                from .sources import ADDRESS_RE
                chain = b.get("chain", cfg_default_chain())
                items = [(chain, a.strip()) for a in b.get("addresses", []) if ADDRESS_RE.match(a.strip())]
                added = sum(w.store.enqueue(c, a, "web") for c, a in items)
                if items:
                    w.add_batch("manual list", items)
                    w.add_event("info", f"Queued {len(items)} contract(s) ({added} new).")
                w.start_drain()
                return self._send(200, {"ok": True, "added": added, "total": len(items)})
            if u.path == "/api/immunefi/scan":
                added, program = self._queue_immunefi(b)
                w.start_drain()
                total = w.batches[-1]["items"].__len__() if w.batches else 0
                return self._send(200, {"ok": True, "added": added, "program": program, "total": total})
            return self._send(404, {"error": "not found"})
        except Exception as exc:
            return self._send(400, {"error": str(exc)})

    def _queue_immunefi(self, b) -> tuple[int, str]:
        from .program import load_scope
        if b.get("scope_path"):
            scope = load_scope(Path(b["scope_path"]))
        else:
            scope = {"program": b.get("program", "manual"), "assets": b.get("assets", [])}
        items = [(a["chain"], a["address"]) for a in scope["assets"] if "address" in a and a.get("chain")]
        added = sum(self.worker.store.enqueue(c, a, f"immunefi:{scope['program']}") for c, a in items)
        if items:
            self.worker.add_batch(scope["program"], items)
            self.worker.add_event("info", f"Program '{scope['program']}': queued {len(items)} in-scope contract(s) ({added} new).")
        return added, scope["program"]

    @staticmethod
    def _row(r):
        bal = None
        if r["balance_wei"]:
            try:
                bal = int(r["balance_wei"]) / 10**18
            except ValueError:
                bal = None
        keys = r.keys()
        try:
            holdings = json.loads(r["holdings"]) if "holdings" in keys and r["holdings"] else []
        except ValueError:
            holdings = []
        return {
            "chain": r["chain"], "address": r["address"], "name": r["name"], "status": r["status"],
            "max_severity": r["max_severity"], "findings": r["findings"], "balance": bal,
            "value_usd": r["value_usd"] if "value_usd" in keys else None, "holdings": holdings,
            "origin": r["origin"], "error": r["error"],
        }


def serve(host: str, port: int, out_dir: Path, cache_dir: Path, state: Path,
          api_key: str | None, rpc_url: str | None, verify: bool = True):
    store = Store(state)
    # New detection rules -> re-judge every VULNERABLE verdict the old rules produced (front of the queue),
    # so false positives fixed in a release disappear from the results without any manual step.
    rejudge = 0
    if store.get_meta("rules_version") != __version__:
        rejudge = store.requeue_status("vulnerable", 2e9)
        store.set_meta("rules_version", __version__)
    rpc = RPC(rpc_url) if rpc_url else None
    cfg = AutoConfig(out_dir=out_dir, cache_dir=cache_dir, api_key=api_key, rpc=rpc, verify=verify, quiet=True)
    Handler.worker = Worker(store, cfg, rpc)
    # Isolated live fund-watch: polls native balances of freshly-flagged contracts for inflow (Live Scan page).
    try:
        from .fundwatch import FundWatcher
        FundWatcher(store, rpc_url, chain=cfg_default_chain()).start()
    except Exception:
        pass
    if rejudge:
        Handler.worker.add_event("info", f"Rules updated to v{__version__}: re-checking {rejudge} VULNERABLE contract(s) first.")
    # BOUNTYSCAN_AUTOSTART=live resumes the 24/7 live scan after any restart or reboot;
    # =drain resumes working through whatever is already queued.
    autostart = os.environ.get("BOUNTYSCAN_AUTOSTART", "").lower()
    if autostart == "live" and rpc is not None:
        Handler.worker.start_live(cfg_default_chain(), None,
                                  int(float(os.environ.get("BOUNTYSCAN_MIN_BALANCE", "0")) * 10**18),
                                  float(os.environ.get("BOUNTYSCAN_MIN_VALUE_USD", "0")))
    elif autostart in ("live", "drain"):
        Handler.worker.start_drain()
    # Resume an unfinished backfill after a restart (or start one from BOUNTYSCAN_BACKFILL_DAYS).
    bf = Handler.worker.backfill.state
    if bf and not bf.get("done") and not bf.get("paused"):
        Handler.worker.backfill.start(bf["chain"], bf["days"], bf["min_txs"])
        Handler.worker.start_drain()
    elif os.environ.get("BOUNTYSCAN_BACKFILL_DAYS") and not bf:
        Handler.worker.backfill.start(cfg_default_chain(), int(os.environ["BOUNTYSCAN_BACKFILL_DAYS"]),
                                      int(os.environ.get("BOUNTYSCAN_BACKFILL_MIN_TXS", "10")))
        Handler.worker.start_drain()
    # Never leave queued work stranded after a restart (e.g. backfill listing finished, queue not empty).
    if Handler.worker.mode == "idle" and store.pending_count():
        Handler.worker.start_drain()
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"bountyscan dashboard on http://{host}:{port}  (rpc={'set' if rpc else 'none'}, verify={verify})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        Handler.worker.stop()
        httpd.shutdown()
