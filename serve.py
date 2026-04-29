#!/usr/bin/env python3
"""
DriftWatch Local Server
-----------------------
Replaces `python -m http.server` with a server that:
  - Serves the dashboard at http://localhost:8080
  - Runs the drift detector when the UI clicks "Run Scan Now"
  - Streams live log output back to the browser

Run from project root:
    python serve.py
"""

import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.resolve()
DASHBOARD_DIR = PROJECT_ROOT / "dashboard"
DETECTOR_SCRIPT = PROJECT_ROOT / "scripts" / "drift_detector.py"

# Track running scan so we don't run two at once
_scan_lock = threading.Lock()
_scan_running = False
_scan_log: list[str] = []


def run_detector():
    global _scan_running, _scan_log
    _scan_log = ["[INFO] Starting drift scan..."]

    env = os.environ.copy()
    env["AWS_REGION"] = env.get("AWS_REGION", "ap-south-1")
    env["DRIFT_REPORT_PATH"] = str(DASHBOARD_DIR / "drift-report.json")

    try:
        proc = subprocess.Popen(
            [sys.executable, str(DETECTOR_SCRIPT)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(PROJECT_ROOT),
            env=env,
        )
        for line in proc.stdout:
            line = line.rstrip()
            _scan_log.append(line)
            print(line)   # also print to terminal
        proc.wait()
        if proc.returncode == 0:
            _scan_log.append("[INFO] ✅ Scan complete — no drift detected.")
        elif proc.returncode == 2:
            _scan_log.append("[WARNING] 🚨 Scan complete — drift detected! Dashboard updated.")
        else:
            _scan_log.append(f"[ERROR] Scan exited with code {proc.returncode}")
    except Exception as exc:
        _scan_log.append(f"[ERROR] Failed to run detector: {exc}")
    finally:
        _scan_running = False


class DriftWatchHandler(http.server.SimpleHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(DASHBOARD_DIR), **kwargs)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)

        # ── API: trigger a scan ──────────────────────────────────────────────
        if parsed.path == "/api/scan":
            self._handle_scan_trigger()
            return

        # ── API: stream scan logs (SSE) ──────────────────────────────────────
        if parsed.path == "/api/scan/logs":
            self._handle_scan_logs()
            return

        # ── API: scan status ─────────────────────────────────────────────────
        if parsed.path == "/api/scan/status":
            self._json({"running": _scan_running, "log_lines": len(_scan_log)})
            return

        # ── Static files (dashboard) ─────────────────────────────────────────
        super().do_GET()

    def _handle_scan_trigger(self):
        global _scan_running, _scan_log
        if _scan_running:
            self._json({"started": False, "message": "Scan already running"})
            return
        acquired = _scan_lock.acquire(blocking=False)
        if not acquired:
            self._json({"started": False, "message": "Scan already running"})
            return
        _scan_running = True
        _scan_log = []
        thread = threading.Thread(target=self._run_and_release, daemon=True)
        thread.start()
        self._json({"started": True, "message": "Scan started"})

    def _run_and_release(self):
        try:
            run_detector()
        finally:
            try:
                _scan_lock.release()
            except RuntimeError:
                pass

    def _handle_scan_logs(self):
        """Server-Sent Events endpoint — streams log lines to browser."""
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()

        sent = 0
        try:
            while True:
                current = _scan_log[:]
                if len(current) > sent:
                    for line in current[sent:]:
                        data = json.dumps({"line": line, "running": _scan_running})
                        self.wfile.write(f"data: {data}\n\n".encode())
                        self.wfile.flush()
                    sent = len(current)

                if not _scan_running and sent >= len(_scan_log):
                    # Send a final "done" event
                    self.wfile.write(b"event: done\ndata: {}\n\n")
                    self.wfile.flush()
                    break

                time.sleep(0.3)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, data: dict):
        body = json.dumps(data).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        # Suppress noisy request logs — only show scan output
        pass


def main():
    port = int(os.environ.get("PORT", 8080))
    server = http.server.ThreadingHTTPServer(("localhost", port), DriftWatchHandler)
    print(f"""
╔══════════════════════════════════════════════════╗
║          DriftWatch Local Server                 ║
╠══════════════════════════════════════════════════╣
║  Dashboard  →  http://localhost:{port}             ║
║  Run scan   →  click "Run Scan Now" in browser   ║
║  Stop       →  Ctrl+C                            ║
╚══════════════════════════════════════════════════╝
""")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nServer stopped.")


if __name__ == "__main__":
    main()