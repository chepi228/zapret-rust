"""Native HTTP/2, DoH, provider, ICMP and actual Chromium loopback evidence.

No system trust, adapter, service, bypass, browser profile or public endpoint is modified.
The optional h2 fixture dependency may live in dist/native/test-python.
"""
import argparse
import contextlib
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import parse_qs, urlsplit

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "dist/native/test-python"))


def invoke(binary, kind, args):
    completed = subprocess.run([str(binary), "--diagnostics", kind, str(ROOT), json.dumps(args)],
                               capture_output=True, timeout=60)
    assert completed.returncode == 0, completed.stderr.decode(errors="replace")
    return json.loads(completed.stdout)


class HttpHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def do_GET(self):
        with self.server.lock:
            self.server.requests.append((self.path, dict(self.headers)))
        body = b"<!doctype html><title>loopback fixture</title><p>native browser proof</p>"
        content_type = "text/html; charset=utf-8"
        status = 200
        if self.path.startswith("/doh"):
            assert self.headers["Accept"] == "application/dns-json"
            query = parse_qs(urlsplit(self.path).query)
            record = {"type": 28, "data": "::1"} if query["type"] == ["AAAA"] else {"type": 1, "data": "127.0.0.1"}
            body = json.dumps({"Status": 0, "Answer": [record]}).encode()
        elif self.path.startswith("/primary-fail"):
            body = b'{"success":false,"message":"fixture"}'
        elif self.path.startswith("/fallback"):
            body = b'{"ip":"203.0.113.12","country":"RU","city":"Fixture","org":"AS64501 Fallback ISP","loc":"55.7,37.6"}'
        elif self.path == "/reload-video":
            body = b'<!doctype html><script>setTimeout(() => location.replace("/playback"), 400)</script>'
        elif self.path == "/playback":
            body = b'<!doctype html><video playsinline src="/playback.webm"></video>'
        elif self.path == "/short-playback":
            body = b'<!doctype html><video playsinline src="/playback.webm#t=0,1"></video>'
        elif self.path == "/broken-playback":
            body = b'<!doctype html><video src="/small"></video>'
        elif self.path == "/playback.webm":
            # Eight seconds of synthetic VP8 video. No external media or codec tools are needed.
            body = Path(__file__).with_name("playback.webm").read_bytes()
            content_type = "video/webm"
        elif self.path.startswith("/http-error"):
            status = 403
        elif self.path.startswith("/redirect"):
            self.send_response(302)
            self.send_header("Location", "/small")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        elif self.path.startswith("/truncated"):
            self.send_response(200)
            self.send_header("Content-Length", "99999")
            self.end_headers()
            self.wfile.write(b"abc")
            self.wfile.flush()
            self.close_connection = True
            return
        elif self.path.startswith("/stall"):
            self.send_response(200)
            self.send_header("Content-Length", "99999")
            self.end_headers()
            self.wfile.write(b"abc")
            self.wfile.flush()
            self.connection.settimeout(8)
            try:
                while self.connection.recv(1024):
                    pass
            except OSError:
                pass
            self.close_connection = True
            return
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@contextlib.contextmanager
def http_fixture(tls=None):
    class Server(http.server.ThreadingHTTPServer):
        def handle_error(self, request, address):
            if not isinstance(sys.exc_info()[1], (ConnectionResetError, ConnectionAbortedError, BrokenPipeError)):
                self.errors.append(repr(sys.exc_info()[1]))
    server = Server(("127.0.0.1", 0), HttpHandler)
    server.daemon_threads = True
    server.requests = []
    server.lock = threading.Lock()
    server.errors = []
    if tls:
        server.socket = tls.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


class H2Handler(socketserver.BaseRequestHandler):
    def handle(self):
        from h2.connection import H2Connection
        from h2.config import H2Configuration
        from h2.events import RequestReceived
        try:
            with self.server.tls.wrap_socket(self.request, server_side=True) as stream:
                stream.settimeout(3)
                if stream.selected_alpn_protocol() != "h2":
                    self.server.other_protocol_data.append(stream.recv(4096))
                    return
                conn = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
                conn.initiate_connection()
                stream.sendall(conn.data_to_send())
                while data := stream.recv(65536):
                    for event in conn.receive_data(data):
                        if isinstance(event, RequestReceived):
                            headers = dict(event.headers)
                            self.server.requests.append(headers)
                            assert headers[":method"] == "HEAD"
                            if headers[":path"] == "/redirect":
                                response = [(":status", "302"), ("location", "/good")]
                            else:
                                response = [(":status", "503"), ("content-length", "99999")]
                            conn.send_headers(event.stream_id, response, end_stream=True)
                    stream.sendall(conn.data_to_send())
        except (OSError, ssl.SSLError):
            pass


@contextlib.contextmanager
def h2_fixture(tls, host="127.0.0.1", port=0):
    class Server(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True
        address_family = socket.AF_INET6 if ":" in host else socket.AF_INET
    server = Server((host, port), H2Handler)
    server.tls = tls
    server.requests = []
    server.other_protocol_data = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    passed = []
    skipped = []

    def check(condition, name):
        assert condition, name
        passed.append(name)
        print("ok", name, flush=True)

    with tempfile.TemporaryDirectory(prefix="zapret-net-protocol-") as temporary:
        temp = Path(temporary)
        openssl = shutil.which("openssl") or str(Path(os.environ.get("ProgramFiles", "")) / "Git/usr/bin/openssl.exe")
        cert, key = temp / "cert.pem", temp / "key.pem"
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
                        "-keyout", str(key), "-out", str(cert)], capture_output=True, check=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        tls.set_alpn_protocols(["h2"])
        try:
            import h2
        except ImportError:
            skipped.append("HTTP/2 fixture needs optional Python h2 package")
        else:
            with h2_fixture(tls) as server:
                url = f"https://localhost:{server.server_address[1]}/redirect"
                options = {"url": url, "modes": ["Http2"], "curl_path": "", "browser_path": "", "timeout_ms": 6000}
                untrusted = invoke(args.binary, "webcheck", options)["rows"][0]
                check(untrusted["state"] == "FAIL" and not untrusted["complete"], "native H2 rejects untrusted system certificate")
                trusted = invoke(args.binary, "webcheck", {**options, "ca_file": str(cert)})["rows"][0]
                check(trusted["state"] == "HTTP_ERROR" and trusted["status_code"] == 503 and trusted["complete"]
                      and trusted["observed_protocol"] == "h2" and trusted["protocol_confirmed"], "native H2 validates ALPN, complete HEAD and separate HTTP status")
                check(trusted["final_url"].endswith("/good") and len(server.requests) == 2
                      and all(row[":authority"] == f"localhost:{server.server_address[1]}" for row in server.requests),
                      "native H2 follows bounded redirect preserving authority")
            tls.set_alpn_protocols(["http/1.1"])
            with h2_fixture(tls) as server:
                mismatch = invoke(args.binary, "webcheck", {**options, "url": f"https://127.0.0.1:{server.server_address[1]}/", "ca_file": str(cert)})["rows"][0]
                check(mismatch["reason"] == "ProtocolMismatch" and not mismatch["protocol_confirmed"]
                      and not mismatch["complete"], "native H2 does not invent support when server ALPN differs")
            peers = list(dict.fromkeys(
                addr[0] for _, _, _, _, addr in socket.getaddrinfo("localhost", 0, type=socket.SOCK_STREAM)
            ))
            if {"::1", "127.0.0.1"}.issubset(peers):
                h2_tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                h2_tls.load_cert_chain(cert, key)
                h2_tls.set_alpn_protocols(["h2"])
                alternate = "127.0.0.1" if peers[0] == "::1" else "::1"
                with h2_fixture(tls, peers[0]) as first, h2_fixture(h2_tls, alternate, first.server_address[1]) as second:
                    url = f"https://localhost:{first.server_address[1]}/good"
                    row = invoke(args.binary, "webcheck", {**options, "url": url, "ca_file": str(cert)})["rows"][0]
                    check(row["complete"] and row["observed_protocol"] == "h2" and row["status_code"] == 503
                          and first.other_protocol_data == [b""] and len(second.requests) == 1,
                          "a trusted TLS peer without h2 leaves the HEAD request to the alternate address")
            else:
                skipped.append("mixed HTTP/2 fixture needs dual-stack localhost")
        with http_fixture() as server:
            base = f"http://127.0.0.1:{server.server_port}"
            dns = invoke(args.binary, "dns", {"host": "127.0.0.1", "compare": True, "no_hosts": False,
                                              "doh_urls": [base + "/doh"], "timeout_ms": 1000})
            check(dns["checked"] == 1 and dns["suspect"] == [] and dns["rows"][0]["conclusion"] == "SharedAddress",
                  "native DoH validates JSON addresses and requires comparable system evidence")
            dns6 = invoke(args.binary, "dns", {"host": "::1", "compare": True, "no_hosts": False,
                                               "doh_urls": [base + "/doh"], "timeout_ms": 1000})
            row6 = dns6["rows"][0]
            check(row6["conclusion"] == "SharedAddress" and row6["doh_addresses"] == ["127.0.0.1", "::1"]
                  and [r["query_type"] for r in row6["doh_attempts"]] == ["A", "AAAA"],
                  "IPv6-only system answers are compared with AAAA records")
            provider = invoke(args.binary, "provider", {"primary_url": base + "/primary-fail", "fallback_url": base + "/fallback", "timeout_ms": 1000})
            row = provider["rows"][0]
            check(row["provider"]["isp"] == "Fallback ISP" and row["provider"]["masked_ip"] == "203.0.113.x"
                  and len(row["observations"]) == 2, "provider fallback retains failed source and masks report address")
            capabilities = invoke(args.binary, "webcheck", {"capabilities_only": True})
            if capabilities["browser_path"]:
                options = {"url": base + "/small", "modes": ["BrowserAuto", "BrowserTcp"], "curl_path": "", "timeout_ms": 5000, "visits": 2}
                browser = invoke(args.binary, "webcheck", options)
                check(len(browser["rows"]) == 4 and all(row["state"] == "OK" and row["complete"]
                      and row["observed_protocol"] == "http/1.1" and row["encoded_bytes"] is not None
                      and row["cleanup_complete"] for row in browser["rows"]), "actual browser completes two uncached navigations in both owned modes")
                for path, expected in [("/http-error", "HTTP_ERROR"), ("/redirect", "OK"), ("/truncated", "FAIL")]:
                    row = invoke(args.binary, "webcheck", {**options, "url": base + path, "modes": ["BrowserTcp"], "visits": 1})["rows"][0]
                    check(row["state"] == expected and row["cleanup_complete"], "actual browser " + path + " preserves state and owned cleanup")
                playback = {**options, "modes": ["BrowserPlayback"], "visits": 1}
                row = invoke(args.binary, "webcheck", {**playback, "url": base + "/playback", "timeout_ms": 16000})["rows"][0]
                check(row["state"] == "OK" and row["complete"] and row["cleanup_complete"]
                      and row["reason"] == "PlaybackObserved" and row["playback"]["played_ms"] >= 5000
                      and row["playback"]["presented_frames"] >= 10 and not row["protocol_confirmed"],
                      "actual browser plays five seconds of decoded video in an isolated profile")
                row = invoke(args.binary, "webcheck", {**playback, "timeout_ms": 2800})["rows"][0]
                check(row["state"] == "UNKNOWN" and row["reason"] == "NoVideo" and not row["complete"]
                      and row["playback"]["presented_frames"] == 0 and row["cleanup_complete"],
                      "a completed page without video never passes the playback check")
                row = invoke(args.binary, "webcheck", {**playback, "url": base + "/short-playback", "timeout_ms": 4200})["rows"][0]
                check(row["reason"] == "PlaybackUnconfirmed" and not row["complete"] and row["cleanup_complete"]
                      and 0 < row["playback"]["played_ms"] < 2500 and row["playback"]["presented_frames"] > 0,
                      "starting a one-second media fragment does not confirm five seconds of playback")
                row = invoke(args.binary, "webcheck", {**playback, "url": base + "/broken-playback", "timeout_ms": 6000})["rows"][0]
                check(row["reason"] == "MediaError" and not row["complete"] and row["cleanup_complete"],
                      "a video element with an invalid media file reports the browser's decode or source error")
                row = invoke(args.binary, "webcheck", {**playback, "url": base + "/http-error"})["rows"][0]
                check(row["state"] == "HTTP_ERROR" and row["status_code"] == 403 and not row["complete"],
                      "a fully downloaded HTTP error never completes a playback observation")
                row = invoke(args.binary, "webcheck", {**playback, "url": base + "/reload-video", "timeout_ms": 16000})["rows"][0]
                check(row["state"] == "OK" and row["complete"] and row["cleanup_complete"]
                      and row["playback"]["document_url"] == base + "/playback",
                      "a client-side navigation restarts the video measurement on its final document")
                started = time.monotonic()
                row = invoke(args.binary, "webcheck", {**options, "url": base + "/stall", "modes": ["BrowserTcp"], "visits": 1})["rows"][0]
                check(row["state"] == "FAIL" and not row["complete"] and row["cleanup_complete"]
                      and time.monotonic() - started < 15, "actual browser timeout retains partial status and kills only owned tree")
                with http_fixture(tls) as secure:
                    row = invoke(args.binary, "webcheck", {**options, "url": f"https://127.0.0.1:{secure.server_port}/small", "modes": ["BrowserTcp"], "visits": 1})["rows"][0]
                    check(row["state"] == "FAIL" and not row["complete"] and row["cleanup_complete"],
                          "actual browser retains ordinary certificate rejection without global trust changes")
            else:
                skipped.append("No installed supported Chromium browser")
            check(not server.errors, "local HTTP fixtures finish without unexpected handler failures")
        latency = invoke(args.binary, "latency", {"addresses": ["127.0.0.1", "::1"], "protocol": "icmp", "count": 1, "interval_ms": 0, "timeout_ms": 1000})
        check(len(latency["rows"]) == 2 and all(row["outcome"] == "Success" and row["ms"] is not None for row in latency["rows"]),
              "native ICMP obtains real IPv4 and IPv6 loopback replies")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps({"schema": 1, "passed": passed, "skipped": skipped}, indent=2) + "\n", encoding="utf-8")
    print(f"PASS {len(passed)} checks; skipped {len(skipped)}; report {args.output}", flush=True)


if __name__ == "__main__":
    main()
