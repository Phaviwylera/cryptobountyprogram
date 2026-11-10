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

import json
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .auto import AutoConfig, discover_blocks, run_queue
from .rpc import RPC, RPCError
from .state import Store
from .ui import INDEX_HTML


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
        self.current = None
        self.last_error = None
        self.started_at = None
        self.scanned = 0

    def _run(self):
        while not self._stop.is_set():
            try:
                if self.mode == "live" and self.rpc is not None:
                    self._discover_step()
                did = self._scan_step()
                if not did:
                    time.sleep(3.0)
            except ExplorerFatalGuard as exc:
                self.last_error = str(exc)
                self.mode = "idle"
                break
            except Exception as exc:  # never let the worker die
                self.last_error = f"{type(exc).__name__}: {exc}"
                time.sleep(5.0)
        self.current = None

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

    def _scan_step(self) -> bool:
        with self.lock:
            rows = self.store.due(1)
            if not rows:
                return False
            row = rows[0]
            self.current = {"chain": row["chain"], "address": row["address"]}
            from .auto import process
            self.cfg.min_balance_wei = self.min_balance_wei
            try:
                status = process(self.store, row, self.cfg)
            except Exception as exc:
                self.store.update(row["chain"], row["address"], status="error", error=str(exc)[:300])
                status = "error"
            self.scanned += 1
            from .contract_report import write_summary
            write_summary(self.store, self.cfg.out_dir)
        self.current = {"chain": row["chain"], "address": row["address"], "status": status}
        return True

    def ensure_thread(self):
        if self._thread is None or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, daemon=True, name="bountyscan-worker")
            self._thread.start()

    def start_live(self, chain, from_block, min_balance_wei):
        if self.rpc is None:
            raise RuntimeError("live scan needs an RPC endpoint (set RPC_URL)")
        self.chain = chain
        self.cursor = (from_block - 1) if from_block is not None else None
        self.min_balance_wei = min_balance_wei
        self.mode = "live"
        self.started_at = self.started_at or time.time()
        self.ensure_thread()

    def start_drain(self):
        self.mode = "draining"
        self.started_at = self.started_at or time.time()
        self.ensure_thread()

    def stop(self):
        self.mode = "idle"
        self._stop.set()

    def snapshot(self):
        with self.lock:
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

    def _send(self, code, payload, ctype="application/json"):
        body = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

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
        if u.path == "/api/status":
            return self._send(200, w.snapshot())
        if u.path == "/api/results":
            return self._send(200, {"results": [self._row(r) for r in w.store.by_status("vulnerable")]})
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
                mb = int(float(b.get("min_balance", 0)) * 10**18)
                w.start_live(chain, fb, mb)
                return self._send(200, {"ok": True, "mode": w.mode})
            if u.path == "/api/live/stop":
                w.stop()
                return self._send(200, {"ok": True, "mode": w.mode})
            if u.path == "/api/enqueue":
                chain = b.get("chain", cfg_default_chain())
                added = 0
                for a in b.get("addresses", []):
                    from .sources import ADDRESS_RE
                    a = a.strip()
                    if ADDRESS_RE.match(a):
                        added += w.store.enqueue(chain, a, "web")
                w.start_drain()
                return self._send(200, {"ok": True, "added": added})
            if u.path == "/api/immunefi/scan":
                added, program = self._queue_immunefi(b)
                w.start_drain()
                return self._send(200, {"ok": True, "added": added, "program": program})
            return self._send(404, {"error": "not found"})
        except Exception as exc:
            return self._send(400, {"error": str(exc)})

    def _queue_immunefi(self, b) -> tuple[int, str]:
        from .program import load_scope
        if b.get("scope_path"):
            scope = load_scope(Path(b["scope_path"]))
        else:
            scope = {"program": b.get("program", "manual"), "assets": b.get("assets", [])}
        added = 0
        for a in scope["assets"]:
            if "address" in a:
                added += self.worker.store.enqueue(a["chain"], a["address"], f"immunefi:{scope['program']}")
        return added, scope["program"]

    @staticmethod
    def _row(r):
        bal = None
        if r["balance_wei"]:
            try:
                bal = int(r["balance_wei"]) / 10**18
            except ValueError:
                bal = None
        return {
            "chain": r["chain"], "address": r["address"], "name": r["name"], "status": r["status"],
            "max_severity": r["max_severity"], "findings": r["findings"], "balance": bal,
            "origin": r["origin"], "error": r["error"],
        }


def serve(host: str, port: int, out_dir: Path, cache_dir: Path, state: Path,
          api_key: str | None, rpc_url: str | None, verify: bool = True):
    store = Store(state)
    rpc = RPC(rpc_url) if rpc_url else None
    cfg = AutoConfig(out_dir=out_dir, cache_dir=cache_dir, api_key=api_key, rpc=rpc, verify=verify, quiet=True)
    Handler.worker = Worker(store, cfg, rpc)
    # BOUNTYSCAN_AUTOSTART=live resumes the 24/7 live scan after any restart or reboot;
    # =drain resumes working through whatever is already queued.
    autostart = os.environ.get("BOUNTYSCAN_AUTOSTART", "").lower()
    if autostart == "live" and rpc is not None:
        Handler.worker.start_live(cfg_default_chain(), None,
                                  int(float(os.environ.get("BOUNTYSCAN_MIN_BALANCE", "0")) * 10**18))
    elif autostart in ("live", "drain"):
        Handler.worker.start_drain()
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"bountyscan dashboard on http://{host}:{port}  (rpc={'set' if rpc else 'none'}, verify={verify})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nshutting down")
        Handler.worker.stop()
        httpd.shutdown()
