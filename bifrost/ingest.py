#!/usr/bin/env python3
"""
Bifrost HTTP Ingest Endpoint v0.1.0

Listens on http://127.0.0.1:8765/ingest for events
from the Go collector agent. Validates the envelope
structure and feeds events directly into the guardian
event queue for processing by the Bifrost pipeline.

This is the bridge between the Go agent and Python.
"""

import json
import logging
import threading
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from queue import Queue

from bifrost.event_queue import safe_enqueue

log = logging.getLogger("heimdall.ingest")


class IngestHandler(BaseHTTPRequestHandler):

    # Injected by IngestServer before starting
    event_queue: Queue = None
    ingest_token: str = None

    def log_message(self, format, *args):
        # Suppress default HTTP server logs
        # Guardian handles all logging
        pass

    def do_GET(self):
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({
                    "status": "ok",
                    "component": "bifrost_ingest",
                    "queue_size": self.event_queue.qsize()
                    if self.event_queue else 0
                }).encode()
            )
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        if self.path != "/ingest":
            self.send_response(404)
            self.end_headers()
            return

        # HMAC token authentication
        # Prevents local malware from injecting spoofed events
        if self.ingest_token:
            provided = self.headers.get("X-Bifrost-Token", "")
            import hmac as _hmac
            if not _hmac.compare_digest(provided, self.ingest_token):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"unauthorized"}')
                return

        try:
            length = int(self.headers.get("Content-Length", 0))
            if length == 0:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b'{"error":"empty body"}')
                return

            body = self.rfile.read(length)
            envelope = json.loads(body.decode())

            # Validate required fields
            required = ["source", "timestamp", "boundary", "raw"]
            missing = [f for f in required if f not in envelope]
            if missing:
                self.send_response(400)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(
                    json.dumps({
                        "error": f"missing fields: {missing}"
                    }).encode()
                )
                return

            # Normalize timestamp
            if not envelope.get("timestamp"):
                envelope["timestamp"] = (
                    datetime.now(timezone.utc).isoformat()
                )

            if self.event_queue:
                if safe_enqueue(
                    self.event_queue,
                    envelope,
                    envelope.get("source", "ingest"),
                    log,
                ):
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"status":"queued"}')
                    log.debug(
                        "Ingest: [%s] %s event queued.",
                        envelope["boundary"],
                        envelope["source"],
                    )
                else:
                    self.send_response(503)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(b'{"error":"queue_full"}')
                    log.warning("Ingest queue full. Event dropped.")
            else:
                self.send_response(503)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"error":"queue_not_ready"}')

        except json.JSONDecodeError as e:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": f"invalid json: {e}"}).encode()
            )
        except Exception as e:
            log.error(f"Ingest handler error: {e}")
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(
                json.dumps({"error": "internal error"}).encode()
            )


class IngestServer(threading.Thread):
    """
    HTTP ingest server running in a background thread.
    Receives events from the Go collector agent and
    feeds them into the guardian event queue.

    Runs on http://127.0.0.1:8765
    Only accessible from localhost — not exposed externally.
    """

    HOST = "127.0.0.1"
    PORT = 8765

    def __init__(self, event_queue: Queue):
        super().__init__(daemon=True, name="bifrost.ingest")
        self.event_queue = event_queue
        self.server = None

        # Inject queue into handler class
        IngestHandler.event_queue = event_queue

    def run(self):
        try:
            self.server = HTTPServer(
                (self.HOST, self.PORT),
                IngestHandler
            )
            log.info(
                f"Ingest server listening on "
                f"http://{self.HOST}:{self.PORT}/ingest"
            )
            self.server.serve_forever()
        except Exception as e:
            log.error(f"Ingest server failed: {e}")

    def stop(self):
        if self.server:
            self.server.shutdown()
            log.info("Ingest server stopped.")


def test_ingest_endpoint():
    """
    Quick test — sends a sample event to the ingest endpoint
    and verifies it is accepted. Run after guardian starts.
    """
    import urllib.request
    import urllib.error

    test_event = {
        "source": "test",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "boundary": "HONEYPOT",
        "raw": {
            "src_ip": "87.251.64.176",
            "eventid": "cowrie.login.failed",
            "username": "root",
            "password": "admin"
        }
    }

    try:
        payload = json.dumps(test_event).encode()
        req = urllib.request.Request(
            "http://127.0.0.1:8765/ingest",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=3) as resp:
            result = json.loads(resp.read())
            print(f"[+] Ingest test passed: {result}")
            return True
    except Exception as e:
        print(f"[!] Ingest test failed: {e}")
        return False


if __name__ == "__main__":
    from queue import Queue
    import time

    logging.basicConfig(level=logging.INFO)

    q = Queue(maxsize=10000)
    server = IngestServer(q)
    server.start()

    print("[*] Ingest server running. Testing...")
    time.sleep(1)

    test_ingest_endpoint()

    print("[*] Checking health endpoint...")
    import urllib.request
    try:
        with urllib.request.urlopen(
            "http://127.0.0.1:8765/health", timeout=3
        ) as resp:
            print(f"[+] Health: {json.loads(resp.read())}")
    except Exception as e:
        print(f"[!] Health check failed: {e}")

    print(f"[*] Queue size: {q.qsize()}")
    print("[*] Press Ctrl+C to stop.")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        server.stop()
        print("[*] Done.")
