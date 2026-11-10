import json
import tempfile
import threading
import unittest
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

from bountyscan.auto import AutoConfig
from bountyscan.server import Handler, Worker
from bountyscan.state import Store


class ServerSmokeTests(unittest.TestCase):
    """Boot the real HTTP server on an ephemeral port; exercise the API without any network scan."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        root = Path(cls.tmp.name)
        store = Store(root / "state.db")
        cfg = AutoConfig(out_dir=root / "out", cache_dir=root / "cache", verify=False, quiet=True)
        Handler.worker = Worker(store, cfg, rpc=None)
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.port = cls.httpd.server_address[1]
        cls.t = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.t.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        Handler.worker.store.db.close()
        cls.tmp.cleanup()

    def get(self, path):
        with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=5) as r:
            return r.status, r.read()

    def post(self, path, body):
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}",
                                     data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())

    def test_index_served(self):
        status, body = self.get("/")
        self.assertEqual(status, 200)
        self.assertIn(b"bountyscan", body)
        self.assertIn(b"LIVE SCAN", body.upper())
        self.assertIn(b"IMMUNEFI SCAN", body.upper())

    def test_status_api(self):
        status, body = self.get("/api/status")
        self.assertEqual(status, 200)
        d = json.loads(body)
        self.assertIn(d["mode"], ("idle", "draining", "live"))
        self.assertIn("counts", d)
        self.assertIn("pending", d)

    def test_enqueue_and_results_endpoints(self):
        status, d = self.post("/api/enqueue", {"chain": "ethereum", "addresses": ["0x" + "ab" * 20]})
        self.assertEqual(status, 200)
        self.assertEqual(d["added"], 1)
        # results/safe/errors endpoints respond with lists
        for ep, key in [("/api/results", "results"), ("/api/safe", "safe"), ("/api/errors", "errors")]:
            _, body = self.get(ep)
            self.assertIn(key, json.loads(body))

    def test_status_responds_while_a_scan_is_running(self):
        # The worker holds its lock for an entire (slow, networked) scan. The dashboard must not freeze.
        with Handler.worker.lock:
            status, body = self.get("/api/status")
            self.assertEqual(status, 200)
            _, body = self.get("/api/results")
            self.assertIn("results", json.loads(body))

    def test_live_start_without_rpc_errors_cleanly(self):
        # worker has no rpc; starting live scan should 400, not crash
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/api/live/start",
                                     data=b"{}", headers={"Content-Type": "application/json"})
        try:
            urllib.request.urlopen(req, timeout=5)
            self.fail("expected an error")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 400)


if __name__ == "__main__":
    unittest.main()
