"""Real loopback acceptance and a bounded comparison with the project's curl batch."""

import argparse
import contextlib
import ctypes
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import socketserver
import ssl
import statistics
import subprocess
import tempfile
import threading
import time
from urllib.parse import urlsplit

WORKER_PREFIX = []


class Fixture(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = 128

    def __init__(self, address, tls=None):
        super().__init__(address, Handler)
        self.tls = tls
        self.requests = []
        self.active = 0
        self.lock = threading.Lock()
        self.stop_event = threading.Event()
        self.errors = []

    def handle_error(self, request, client_address):
        import traceback
        self.errors.append(traceback.format_exc())


class Fixture6(Fixture):
    address_family = socket.AF_INET6


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.lock:
            self.server.active += 1
        try:
            stream = self.request
            stream.settimeout(3)
            if self.server.tls:
                stream = self.server.tls.wrap_socket(stream, server_side=True)
            with stream:
                self.serve(stream)
        except (OSError, ssl.SSLError):
            pass  # Limit, timeout and certificate rejection close connections deliberately.
        finally:
            with self.server.lock:
                self.server.active -= 1

    def serve(self, stream):
        data = bytearray()
        while b"\r\n\r\n" not in data:
            part = stream.recv(8192)
            if not part:
                return
            data.extend(part)
            if len(data) > 32768:
                raise AssertionError("oversized fixture request")
        header, body = bytes(data).split(b"\r\n\r\n", 1)
        lines = header.decode("ascii").split("\r\n")
        method, target, _ = lines[0].split(" ")
        headers = dict(line.split(": ", 1) for line in lines[1:])
        headers = {key.lower(): value for key, value in headers.items()}
        length = int(headers.get("content-length", "0"))
        while len(body) < length:
            chunk = stream.recv(min(8192, length - len(body)))
            if not chunk:
                return
            body += chunk
        with self.server.lock:
            self.server.requests.append({"method": method, "target": target,
                                         "headers": headers, "post_bytes": len(body)})
        path = urlsplit(target).path
        if path == "/headers-stall":
            return self.wait_closed(stream)
        if path == "/malformed":
            stream.sendall(b"THIS IS NOT HTTP\r\n\r\n")
            return
        if path == "/oversized":
            stream.sendall(b"HTTP/1.1 200 OK\r\nX-Huge: " + b"x" * 65536 + b"\r\n\r\n")
            return
        if path == "/empty":
            stream.sendall(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
            return
        if path == "/denied":
            stream.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 3\r\n\r\nno!")
            return
        if path == "/redirect":
            stream.sendall(b"HTTP/1.1 302 Found\r\nLocation: /small\r\nContent-Length: 0\r\n\r\n")
            return
        if path == "/interim":
            stream.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")
        if path == "/chunked":
            stream.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            for _ in range(128):
                stream.sendall(b"2000\r\n" + b"x" * 8192 + b"\r\n")
                time.sleep(0.001)
            stream.sendall(b"0\r\n\r\n")
            return
        if path == "/chunked-short":
            stream.sendall(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\nX-End: yes\r\n\r\n")
            return
        length = 128 if path in ("/small", "/interim") else 2_097_152
        stream.sendall(f"HTTP/1.1 200 OK\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n".encode())
        if path in ("/stall", "/truncated"):
            stream.sendall(b"x" * 8192)
            if path == "/stall":
                self.wait_closed(stream)
            return
        if path == "/exact":
            stream.sendall(b"x" * 65536)
            return self.wait_closed(stream)
        for offset in range(0, length, 8192):
            stream.sendall(b"x" * min(8192, length - offset))
            time.sleep(0.001)

    def wait_closed(self, stream):
        stream.settimeout(0.05)
        cutoff = time.monotonic() + 3
        while time.monotonic() < cutoff and not self.server.stop_event.is_set():
            try:
                if not stream.recv(1):
                    return
            except socket.timeout:
                continue


@contextlib.contextmanager
def server(tls=None, ipv6=False):
    fixture = (Fixture6 if ipv6 else Fixture)(("::1" if ipv6 else "127.0.0.1", 0), tls)
    thread = threading.Thread(target=fixture.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    try:
        yield fixture
    finally:
        fixture.stop_event.set()
        fixture.shutdown()
        fixture.server_close()
        thread.join(2)


def measure(command, input_data=None):
    """Sample the owned root process only. CPU excludes its child processes."""
    started = time.perf_counter()
    environment = os.environ.copy()
    if Path(command[0]).name.lower() == "powershell.exe":
        # Python can inherit PowerShell 7 module paths. Let Windows PowerShell 5.1
        # reconstruct its own defaults when launched through this intermediary.
        environment.pop("PSMODULEPATH", None)
    process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE, env=environment)
    peak = [0]
    stopped = threading.Event()
    if os.name == "nt":
        from ctypes import wintypes

        class Memory(ctypes.Structure):
            _fields_ = [("cb", wintypes.DWORD), ("faults", wintypes.DWORD)] + [
                (name, ctypes.c_size_t) for name in
                ("peak", "working", "pool_peak_paged", "pool_paged", "pool_peak_nonpaged",
                 "pool_nonpaged", "pagefile", "peak_pagefile", "private")]

        psapi = ctypes.WinDLL("psapi", use_last_error=True)
        psapi.GetProcessMemoryInfo.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD]
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.c_void_p] * 4

        def sample():
            while not stopped.is_set():
                memory = Memory()
                memory.cb = ctypes.sizeof(memory)
                if psapi.GetProcessMemoryInfo(int(process._handle), ctypes.byref(memory), memory.cb):
                    peak[0] = max(peak[0], memory.peak)
                stopped.wait(0.005)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
    try:
        stdout, stderr = process.communicate(input=input_data, timeout=20)
    except BaseException:
        process.kill()
        process.communicate()
        raise
    finally:
        stopped.set()
        if os.name == "nt":
            sampler.join(1)
    metrics = {"wall_ms": (time.perf_counter() - started) * 1000,
               "root_peak_working_set_bytes": peak[0] or None, "root_cpu_ms": None}
    if os.name == "nt":
        times = [ctypes.c_ulonglong() for _ in range(4)]
        if kernel.GetProcessTimes(int(process._handle), *(ctypes.byref(value) for value in times)):
            metrics["root_cpu_ms"] = (times[2].value + times[3].value) / 10000
    return process.returncode, stdout, stderr, metrics


def invoke(binary, jobs, *options):
    payload = "".join(json.dumps(job) + "\n" for job in jobs).encode()
    code, stdout, stderr, metrics = measure([str(binary), *WORKER_PREFIX, *options], payload)
    if code != 0:
        raise AssertionError(f"worker exit {code}: {stderr.decode(errors='replace')}")
    rows = [json.loads(line) for line in stdout.splitlines()]
    if len(rows) != len(jobs) or {row["id"] for row in rows} != {job["id"] for job in jobs}:
        raise AssertionError("results must include every job id exactly once")
    return {row["id"]: row for row in rows}, metrics


def job(name, base, path, **kwargs):
    return {"version": 1, "id": name, "url": base + path, **kwargs}


def check(condition, name, passed):
    if not condition:
        raise AssertionError(name)
    passed.append(name)
    print("ok " + name, flush=True)


def benchmark(binary, base, temporary, rounds):
    jobs = [job(f"bench-{index}", base, "/large", post_bytes=0) for index in range(64)]
    input_file = temporary / "bench.jsonl"
    input_file.write_text("".join(json.dumps(item) + "\n" for item in jobs), encoding="utf-8")
    baseline = Path(__file__).resolve().parents[3] / "dev/rust-probe/curl-baseline.ps1"
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    samples = {"rust": [], "powershell_curl": []}
    for iteration in range(rounds):
        for arm in (["rust", "powershell_curl"] if iteration % 2 == 0 else ["powershell_curl", "rust"]):
            if arm == "rust":
                rows, metrics = invoke(binary, jobs, "--parallel", "16")
                assert all(row["target_reached"] and row["body_bytes"] == 65536 for row in rows.values())
                metrics["network_ms"] = max(row["started_ms"] + row["total_ms"] for row in rows.values())
                metrics["body_bytes"] = sum(row["body_bytes"] for row in rows.values())
                metrics["decoded_body_bytes"] = sum(row["received_body_bytes"] for row in rows.values())
                metrics["request_child_launches"] = 0
            else:
                command = [str(powershell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-File", str(baseline), "-InputFile", str(input_file), "-Parallel", "16"]
                code, output, error, metrics = measure(command)
                assert code == 0, error.decode(errors="replace")
                result = json.loads(output.decode("utf-8-sig"))
                rows = result["Rows"]
                assert len(rows) == len(jobs) and all(row["TargetReached"] and row["BodyBytes"] == 65536 for row in rows)
                metrics["network_ms"] = result["NetworkMs"]
                metrics["body_bytes"] = sum(row["BodyBytes"] for row in rows)
                metrics["decoded_body_bytes"] = sum(row["Down"] for row in rows)
                metrics["request_child_launches"] = len(rows)
                metrics["source_sha256"] = result["SourceHash"]
            samples[arm].append(metrics)
    medians = {arm: {key: statistics.median(row[key] for row in values) for key in
                    ("wall_ms", "network_ms", "root_cpu_ms", "root_peak_working_set_bytes", "body_bytes", "decoded_body_bytes")}
               for arm, values in samples.items()}
    return {"rounds": rounds, "jobs_per_round": 64, "parallel": 16,
            "scope": "loopback HTTP/1.1; cold root processes; network_ms excludes PS initialization; root CPU/memory excludes child processes; launch counts follow runner implementation",
            "samples": samples, "medians": medians}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--benchmark-rounds", type=int, default=3, choices=range(1, 8))
    parser.add_argument("--subcommand", choices=["probe"], help="Run the integrated native application worker")
    args = parser.parse_args()
    args.binary = args.binary.resolve()
    WORKER_PREFIX[:] = [args.subcommand] if args.subcommand else []
    passed = []
    report = {"schema": 1, "captured_utc": datetime.now(timezone.utc).isoformat(),
              "platform": platform.platform(), "passed": passed, "skipped": []}
    openssl = shutil.which("openssl") or str(Path(os.environ.get("ProgramFiles", "")) / "Git/usr/bin/openssl.exe")
    with tempfile.TemporaryDirectory(prefix="zapret-rust-probe-") as name, server() as http:
        temporary = Path(name)
        base = f"http://127.0.0.1:{http.server_address[1]}"
        cases = [job(path[1:], base, path) for path in
                 ("/small", "/large", "/chunked", "/chunked-short", "/truncated", "/empty", "/denied", "/redirect", "/interim", "/malformed", "/oversized", "/exact")]
        cases += [job("post", base, "/small", post_bytes=65536),
                  job("timeout", base, "/stall", timeout_ms=200),
                  job("header-timeout", base, "/headers-stall", timeout_ms=200)]
        rows, _ = invoke(args.binary, cases)
        check(rows["small"]["body_complete"] and rows["small"]["body_bytes"] == 128, "complete short response", passed)
        for name in ("large", "chunked", "exact"):
            row = rows[name]
            check(row["termination"] == "BodyLimit" and row["body_bytes"] == 65536
                  and row["target_reached"] and not row["body_complete"], name + " stops at body budget", passed)
        check(rows["chunked-short"]["body_complete"] and rows["chunked-short"]["body_bytes"] == 3,
              "chunked trailers complete correctly", passed)
        check(rows["truncated"]["termination"] == "TransferError" and rows["truncated"]["body_bytes"] == 8192,
              "premature EOF retains partial body", passed)
        check(rows["empty"]["status_code"] == 204 and rows["empty"]["body_complete"], "empty HTTP response", passed)
        check(rows["denied"]["status_code"] == 403 and rows["denied"]["body_complete"], "HTTP error status remains explicit", passed)
        check(rows["redirect"]["status_code"] == 302, "redirect remains an observed response", passed)
        check(rows["interim"]["status_code"] == 200 and rows["interim"]["body_bytes"] == 128,
              "interim response does not replace final status", passed)
        for name in ("malformed", "oversized"):
            check(rows[name]["termination"] == "HttpFailure" and rows[name]["status_code"] is None,
                  name + " headers fail", passed)
        check(rows["timeout"]["termination"] == "Timeout" and rows["timeout"]["stage"] == "Body"
              and rows["timeout"]["body_bytes"] == 8192, "body timeout retains stage and byte count", passed)
        check(rows["header-timeout"]["termination"] == "Timeout" and rows["header-timeout"]["stage"] == "Http",
              "header timeout retains completed TCP", passed)
        post = next(item for item in http.requests if item["method"] == "POST")
        check(post["post_bytes"] == 65536 and rows["post"]["body_complete"], "fixture receives full 64 KiB POST", passed)
        check(post["headers"]["range"] == "bytes=0-65535", "body budget is also requested as Range", passed)
        check(all(row["tcp_ms"] is not None and not row["certificate_validated"] for row in rows.values()),
              "HTTP retains TCP timing without TLS claims", passed)
        bounded, _ = invoke(args.binary, [job("one-byte", base, "/large", body_limit=1),
                                         job("one-mib", base, "/large", body_limit=1048576)])
        check(bounded["one-byte"]["body_bytes"] == 1 and bounded["one-byte"]["termination"] == "BodyLimit"
              and bounded["one-mib"]["body_bytes"] == 1048576 and bounded["one-mib"]["termination"] == "BodyLimit",
              "custom body budgets include supported boundaries", passed)
        check(all(row["received_body_bytes"] >= row["body_bytes"] for row in bounded.values())
              and bounded["one-byte"]["received_body_bytes"] > 1,
              "decoded bytes expose HTTP buffering beyond accepted budget", passed)

        pending = [job("active", base, "/stall")] + [job(f"queued-{index}", base, "/small") for index in range(5)]
        deadline_rows, metrics = invoke(args.binary, pending, "--parallel", "1", "--deadline-ms", "100")
        check(all(row["termination"] == "Deadline" for row in deadline_rows.values())
              and deadline_rows["active"]["body_bytes"] == 8192
              and all(row["stage"] == "Queued" for key, row in deadline_rows.items() if key != "active")
              and metrics["wall_ms"] < 1500, "batch deadline includes queued jobs and preserves active progress", passed)
        invalid = [job("duplicate", base, "/small"), job("duplicate", base, "/small")]
        before = len(http.requests)
        code, output, _, _ = measure([str(args.binary), *WORKER_PREFIX], "".join(json.dumps(item) + "\n" for item in invalid).encode())
        check(code == 2 and not output and len(http.requests) == before, "invalid batch is rejected before network activity", passed)
        for field, value in (("version", 2), ("body_limit", 0), ("timeout_ms", 60001), ("unexpected", True),
                             ("url", "file:///C:/Windows/win.ini"), ("url", "http://user:pass@localhost/")):
            invalid = job("bad", base, "/small", **{field: value}) if field != "url" else {**job("bad", base, "/small"), "url": value}
            code, output, _, _ = measure([str(args.binary), *WORKER_PREFIX], (json.dumps(invalid) + "\n").encode())
            check(code == 2 and not output, f"reject invalid {field}={value}", passed)
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            refused, _ = invoke(args.binary, [job("refused", f"http://127.0.0.1:{reserved.getsockname()[1]}", "/")])
            check(refused["refused"]["termination"] == "TcpFailure" and refused["refused"]["stage"] == "Tcp",
                  "TCP refusal is separate from TLS", passed)
        dns_base = base.replace("127.0.0.1", "localhost")
        dns, _ = invoke(args.binary, [job("dns", dns_base, "/small")])
        check(dns["dns"]["body_complete"] and dns["dns"]["dns_source"] == "system"
              and dns["dns"]["resolved_addresses"], "system DNS and address fallback reach localhost", passed)
        # A DNS label exceeding 63 bytes is rejected by the system resolver.
        invalid_host = "a" * 64 + ".invalid"
        dns_failed, _ = invoke(args.binary, [job("dns-failure", "http://" + invalid_host, "/")])
        check(dns_failed["dns-failure"]["termination"] == "DnsFailure"
              and dns_failed["dns-failure"]["stage"] == "Dns" and not dns_failed["dns-failure"]["tcp_attempts"],
              "DNS failure remains separate from TCP", passed)
        try:
            ipv6 = server(ipv6=True)
            with ipv6 as six:
                six_base = f"http://[::1]:{six.server_address[1]}"
                rows6, _ = invoke(args.binary, [job("ipv6", six_base, "/small")])
                check(rows6["ipv6"]["body_complete"] and rows6["ipv6"]["remote_address"].startswith("[::1]"),
                      "IPv6 loopback", passed)
        except OSError as error:
            report["skipped"].append("IPv6 unavailable: " + str(error))

        cert, key = temporary / "cert.pem", temporary / "key.pem"
        subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-noenc", "-days", "1",
                        "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1,IP:::1",
                        "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.load_cert_chain(cert, key)
        sni_names = []
        tls.set_servername_callback(lambda sock, name, context: sni_names.append(name))
        with server(tls=tls) as https:
            tls_base = f"https://localhost:{https.server_address[1]}"
            tls_job = job("tls", tls_base, "/small", connect_ip="127.0.0.1")
            untrusted, _ = invoke(args.binary, [tls_job])
            check(untrusted["tls"]["termination"] == "TlsFailure" and untrusted["tls"]["tcp_ms"] is not None
                  and not untrusted["tls"]["certificate_validated"], "default trust rejects self-signed TLS", passed)
            trusted, _ = invoke(args.binary, [tls_job], "--ca-file", str(cert))
            check(trusted["tls"]["body_complete"] and trusted["tls"]["certificate_validated"]
                  and trusted["tls"]["tls_ms"] is not None and trusted["tls"]["trust_source"] == "SystemPlusExtraCa",
                  "process-local CA permits validated TLS", passed)
            check("localhost" in sni_names and https.requests[-1]["headers"]["host"] == f"localhost:{https.server_address[1]}",
                  "selected IP preserves original SNI and Host", passed)
            mismatch = job("mismatch", tls_base.replace("localhost", "wrong.invalid"), "/small", connect_ip="127.0.0.1")
            wrong, _ = invoke(args.binary, [mismatch], "--ca-file", str(cert))
            check(wrong["mismatch"]["termination"] == "TlsFailure" and not wrong["mismatch"]["certificate_validated"],
                  "extra CA preserves hostname verification", passed)
        with server() as silent:
            silent_base = f"https://127.0.0.1:{silent.server_address[1]}"
            stalled, metrics = invoke(args.binary, [job("tls-stall", silent_base, "/", timeout_ms=150)])
            check(stalled["tls-stall"]["stage"] == "Tls" and stalled["tls-stall"]["termination"] == "Timeout"
                  and metrics["wall_ms"] < 1500, "TLS timeout retains completed TCP stage", passed)
        report["benchmark"] = benchmark(args.binary, base, temporary, args.benchmark_rounds)
        cutoff = time.monotonic() + 2
        while http.active and time.monotonic() < cutoff:
            time.sleep(0.01)
        check(http.active == 0, "all HTTP fixture connections close", passed)
        check(not http.errors, "fixture handlers complete without unexpected exceptions", passed)
    sources = Path(__file__).resolve().parents[1]
    report["source_sha256"] = {str(path.relative_to(sources)): hashlib.sha256(path.read_bytes()).hexdigest()
                               for path in sorted(sources.rglob("*.rs"))}
    report["cargo_lock_sha256"] = hashlib.sha256((sources.parent / "Cargo.lock").read_bytes()).hexdigest()
    report["binary_sha256"] = hashlib.sha256(args.binary.read_bytes()).hexdigest()
    report["binary_bytes"] = args.binary.stat().st_size
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report["benchmark"]["medians"], indent=2), flush=True)
    print(f"PASS {len(passed)} checks; report {args.output}", flush=True)


if __name__ == "__main__":
    main()
