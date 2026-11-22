"""Exercise a native ZIP through normal entry points in a private TEMP package.

Never starts a bypass or changes services, tasks, adapters, hosts or certificates.
Only winws2 --dry-run and loopback HTTP/ICMP/Telegram requests are executed.
"""

import argparse
import ctypes
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import time
import zipfile
import uuid
import xml.etree.ElementTree as ET


def digest(data):
    return hashlib.sha256(data).hexdigest().upper()


@contextmanager
def fixture():
    class Handler(BaseHTTPRequestHandler):
        def do_HEAD(self):
            self.send_response(200)
            self.send_header("Content-Length", "7")
            self.end_headers()

        def do_GET(self):
            self.do_HEAD()
            self.wfile.write(b"fixture")

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/", server.server_port
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)


def main():
    sys.stdout.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    archive = args.archive.resolve()
    passed = []
    observations = {}

    def check(condition, name):
        if not condition:
            raise AssertionError(name)
        passed.append(name)
        print("ok", name, flush=True)

    with tempfile.TemporaryDirectory(prefix="zapret-rust-native-smoke-") as temporary:
        stage = Path(temporary) / "package with spaces"
        with zipfile.ZipFile(archive) as source:
            names = source.namelist()
            check(all(name.startswith("zapret-rust/") and ".." not in Path(name).parts for name in names), "ZIP has a single safe package root")
            check(not any(name.lower().endswith((".ps1", ".cs")) for name in names), "ZIP excludes production PowerShell and C#")
            check([name for name in names if "/runtime/" in name] == ["zapret-rust/runtime/.keep"], "ZIP excludes machine runtime")
            check(not any(part in name.split("/") for name in names for part in ["dev", "native", ".git", "dist"]), "ZIP excludes developer sources and tools")
            check(not any(name in names for name in ["zapret-rust/zapret.bat", "zapret-rust/bin/zapret.exe", "zapret-rust/bin/zapret-worker.exe", "zapret-rust/bin/zapret-recovery.exe", "zapret-rust/bin/tgws/TgWsProxy_windows.exe"]), "ZIP contains only current zapret-rust entries and its integrated Telegram core")
            source.extractall(stage)
        root = stage / "zapret-rust"
        executable = root / "bin/zapret-rust.exe"
        recovery = root / "bin/zapret-rust-recovery.exe"
        catalog = json.loads((root / "package-manifest.json").read_text(encoding="utf-8"))
        expected_version = "zapret-rust " + catalog["version"]
        files = {str(path.relative_to(root)).replace("\\", "/"): digest(path.read_bytes())
                 for path in root.rglob("*") if path.is_file() and str(path.relative_to(root)).replace("\\", "/") not in {"package-manifest.json", "runtime/.keep"}}
        check(files == catalog["files"] and (root / "runtime/.keep").stat().st_size == 0, "catalog authenticates payloads and runtime placeholder is empty")
        check(executable.read_bytes() == recovery.read_bytes(), "recovery entry contains the same native application")
        background = root / "bin/zapret-rust-worker.exe"
        image = background.read_bytes()
        pe = int.from_bytes(image[0x3c:0x40], "little")
        check(int.from_bytes(image[pe + 24 + 68:pe + 24 + 70], "little") == 2,
              "scheduled background host uses the Windows GUI subsystem")
        result = subprocess.run([str(background), "--self-check"], cwd=root, capture_output=True, timeout=5)
        check(result.returncode == 0 and json.loads(result.stdout)["console_window"] is False,
              "native background host starts without creating a console")

        for screen, last_key in [("main", 9), ("settings", 11), ("tools", 12), ("test", 5)]:
            preview = subprocess.run(
                [str(executable), "--root", str(stage / "missing-root"), "menu-preview",
                 "--screen", screen, "--width", "55", "--height", "16"],
                cwd=stage, capture_output=True, timeout=10,
            )
            text = preview.stdout.decode("utf-8")
            title = "Автоподбор стратегии" if screen == "test" else "zapret-rust v2.2"
            check(preview.returncode == 0 and title in text and text.startswith("╭")
                  and "\x1b" not in text and all(len(line) == 53 for line in text.splitlines())
                  and all(f" {key:>2}  " in text for key in range(last_key + 1)),
                  f"{screen} keeps the styled frame and all actions without a package root or ANSI in pipes")
            if screen == "main":
                check(len(text.splitlines()) + 2 <= 16, "main menu fits a short 55-column console")
        check(not (root / "runtime/settings.ini").exists() and not (stage / "missing-root").exists(),
              "presentation preview does not initialize settings or touch a live package")

        def run(*command, input_data=None, expected=0, timeout=30):
            result = subprocess.run([str(executable), "--root", str(root), "--json", *command],
                                    cwd=root, input=input_data, capture_output=True, timeout=timeout)
            if result.returncode != expected:
                raise AssertionError(f"{command}: exit {result.returncode}\n{result.stderr.decode(errors='replace')}\n{result.stdout.decode(errors='replace')[:1000]}")
            return json.loads(result.stdout) if result.stdout else None

        for kind in ["notify", "telegram"]:
            definition = run("platform-worker", "task-spec", "--arguments-json", json.dumps({"kind": kind}))["xml"]
            task = ET.fromstring(definition.encode("utf-16"))
            command = task.find(".//{*}Exec/{*}Command").text
            parameters = task.find(".//{*}Exec/{*}Arguments").text
            check(Path(command) == background and "conhost" not in parameters and "--headless" not in parameters,
                  f"{kind} task uses the native background host directly")

        integrity = run("integrity")
        check(integrity.get("ok") is True, "ordinary CLI verifies bundled engine and Telegram integrity")
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            telegram_port = reservation.getsockname()[1]
        telegram_config = root / "runtime/tgws/TgWsProxy/config.json"
        telegram_config.parent.mkdir(parents=True, exist_ok=True)
        telegram_config.write_text(json.dumps({
            "dc_ip": [], "cfproxy": False, "pool_size": 0,
        }), encoding="utf-8")
        telegram_secret = "11111111111111111111111111111111"
        (root / "runtime/settings.ini").write_text("telegram=on\n", encoding="utf-8")
        (root / "runtime/telegram.txt").write_text(
            f"port={telegram_port}\nsecret={telegram_secret}\n", encoding="utf-8",
        )
        with subprocess.Popen([str(background), "--root", str(root), "telegram", "supervise"],
                              cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as supervisor:
            try:
                deadline = time.monotonic() + 10
                while time.monotonic() < deadline:
                    telegram = run("telegram", "status", timeout=5)
                    if telegram.get("running") or supervisor.poll() is not None:
                        break
                    time.sleep(0.1)
                check(telegram.get("running") and telegram.get("current")
                      and telegram.get("backend") == "rust"
                      and telegram.get("active_port") == telegram_port
                      and Path(telegram["process"]["executable"]) == executable
                      and telegram["process"]["pid"] != telegram["wrapper"]["pid"],
                      "Telegram supervisor owns the embedded Rust core and loopback listener")
                with socket.create_connection(("127.0.0.1", telegram_port), timeout=3) as client:
                    client.sendall(bytes(64))
                    check(client.recv(1) == b"", "packaged Telegram core rejects unauthenticated input")
                installation_id = uuid.uuid4().hex
                staged = root / f"bin/.native-build-{installation_id}.tmp"
                previous = root / f"dist/native/previous-controllers/zapret-rust.exe.{installation_id}.old"
                previous.parent.mkdir(parents=True, exist_ok=True)
                staged.write_bytes(executable.read_bytes())
                replace = ctypes.WinDLL("kernel32", use_last_error=True).ReplaceFileW
                replace.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_wchar_p,
                                    ctypes.c_uint32, ctypes.c_void_p, ctypes.c_void_p]
                replace.restype = ctypes.c_int
                if not replace(str(executable), str(staged), str(previous), 0, None, None):
                    raise ctypes.WinError(ctypes.get_last_error())
                updated = run("telegram", "status")
                check(updated.get("running") and updated.get("current") and updated.get("requires_restart")
                      and updated["process"]["pid"] == telegram["process"]["pid"]
                      and updated["active_port"] == telegram_port,
                      "mapped controller update preserves the recorded Telegram core and listener")
                with socket.create_connection(("127.0.0.1", telegram_port), timeout=3) as client:
                    client.sendall(bytes(64))
                    check(client.recv(1) == b"", "Telegram listener remains functional after controller replacement")
                configured = run("telegram", "config", "--port", str(telegram_port + 1 if telegram_port < 65535 else telegram_port - 1))
                check(configured.get("requires_restart") and configured.get("active_port") == telegram_port,
                      "saving Telegram config preserves the active listener until restart")
            finally:
                if supervisor.poll() is None:
                    supervisor.terminate()
                supervisor.wait(timeout=10)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not run("telegram", "status", timeout=5).get("running"):
                break
            time.sleep(0.1)
        check(not run("telegram", "status")["running"], "closing the background host reaps its Telegram core")
        (root / "runtime/settings.ini").unlink()
        state = run("status")
        check(isinstance(state.get("known"), bool) and isinstance(state.get("ownership_known"), bool), "status preserves unknown ownership instead of inventing a stopped engine")
        observations["status"] = state
        ipv4 = run("platform-worker", "prefer-ipv4", "--arguments-json", "{}")
        check(ipv4.get("backend") == "WindowsCim" and isinstance(ipv4.get("known"), bool)
              and isinstance(ipv4.get("enabled"), bool),
              "normal CLI reads typed active IPv4 prefix policies through the Windows provider")
        timestamps = run("platform-worker", "tcp-timestamps-status", "--arguments-json", "{}")
        check(timestamps.get("backend") == "WindowsCim" and isinstance(timestamps.get("enabled"), bool)
              and timestamps.get("changed") is False,
              "normal CLI observes TCP timestamp templates without changing settings")
        observations["ipv4_preference"] = ipv4
        observations["tcp_timestamps"] = timestamps
        settings = run("settings")
        check(settings["alt"] == "31" and settings["auto"] == "on", "fresh package defaults to SOFT-STUN2 with automatic rotation")
        run("settings", "FutureSetting", "preserved")
        check(run("settings", "futuresetting")["value"] == "preserved", "non-engine INI edits work in a fresh package and retain spelling")
        check("FutureSetting=preserved" in (root / "runtime/settings.ini").read_text(encoding="utf-8"), "unknown INI spelling survives native publication")

        plan = run("test", "--plan-only")
        check(plan["targets"] and plan["strategies"] and plan["settings"]["values"]["FutureSetting"] == "preserved", "autopick plan reads the native package without stopping the live bypass")
        saved = {"schema": 1, "best": {"id": "50", "score": 48, "total": 54},
                 "rows": [{"id": "50", "score": 48, "total": 54}],
                 "availability": {"50": {"ok": 49, "total": 54}},
                 "strategy_names": {"50": "ALT11 белый 1"}, "primary": "50",
                 "primary_changed": False, "accepted": False, "quality_eligible": True}
        saved_path = root / "runtime/test-native-last.json"
        saved_path.write_text(json.dumps(saved, ensure_ascii=False), encoding="utf-8")
        settings_before = (root / "runtime/settings.ini").read_bytes()
        check(run("test", "--last") == saved, "cached selection JSON preserves the original structured result")
        human = subprocess.run([str(executable), "--root", str(root), "test", "--last"],
                               cwd=root, capture_output=True, timeout=10)
        human_text = human.stdout.decode("utf-8")
        check(human.returncode == 0 and human_text.startswith("╭") and "ALT11 белый 1" in human_text
              and "49/54" in human_text and "Основная после проверки" in human_text
              and "strategy_names" not in human_text and "quality_eligible" not in human_text,
              "cached selection uses a readable table through the actual CLI")
        check((root / "runtime/settings.ini").read_bytes() == settings_before
              and json.loads(saved_path.read_text(encoding="utf-8")) == saved,
              "viewing a previous selection does not rewrite settings or measured evidence")
        provider_plan = run("provider-check", "--args", json.dumps({"plan_only": True}))
        check(provider_plan["plan_only"] is True and provider_plan["full"] is True and provider_plan["report_only"] is True and provider_plan["keep_primary"] is True,
              "provider-check preserves the complete report-only strategy workflow without running it in plan mode")
        all_strategies = run("strategies")
        check(len(all_strategies) == 36, "all 36 bundled strategy records are available")
        (root / "lists/autohostlist.txt").write_text("# private native smoke fixture\n", encoding="utf-8")
        (root / "runtime/ipset-any.txt").write_text("0.0.0.0/0\n::/0\n", encoding="utf-8")
        for strategy in all_strategies:
            composed = run("compose", "--alt", strategy["id"], "--no-auto", "--dry-run", "--validate", timeout=60)
            check(composed["validation"]["ok"] is True, f"native preflight validates {strategy['name']}")
        for mode in ["loaded", "any", "none"]:
            composed = run("compose", "--ipset", mode, "--dry-run", "--validate", timeout=60)
            check(composed["validation"]["ok"] is True, f"native automatic rotation filter preflight passes IPSet {mode}")

        rules = run("direct-rules")
        check(rules.get("text") or rules.get("output"), "direct rules are generated through the native command")
        report = run("report")
        check(report.get("output") or report.get("file") or report.get("text"), "native report is generated without machine mutations")
        preview = run("update", "--from", str(archive), timeout=90)
        check(preview.get("installable") is True, "native updater validates a complete local archive without installing")
        before = digest((root / "runtime/settings.ini").read_bytes())
        result = subprocess.run([str(executable), "--root", str(root), "update", "--from", str(archive), "--sha256", "0" * 64],
                                capture_output=True, timeout=30)
        check(result.returncode != 0 and digest((root / "runtime/settings.ini").read_bytes()) == before, "wrong archive digest is rejected without changing settings")

        with fixture() as (url, port):
            job = {"version": 1, "id": "smoke", "url": url, "body_limit": 65536, "timeout_ms": 2000}
            result = subprocess.run([str(executable), "probe"], input=(json.dumps(job) + "\n").encode(), capture_output=True, timeout=10)
            row = json.loads(result.stdout)
            check(result.returncode == 0 and row["termination"] == "Complete" and row["body_bytes"] == 7, "integrated native probe completes a real loopback HTTP request")
            check(row["finished_monotonic_ms"] >= row["started_monotonic_ms"] > 0, "worker emits shared monotonic target clocks")
            connection = run("connection-check", url, "--timeout-ms", "2000")
            check(connection["targets"][0]["assessment"]["reachable_http"] is True, "normal connection-check entry reaches real loopback HTTP")
            check(Path(connection["TextFile"]).is_file() and digest(Path(connection["TextFile"]).read_bytes()) == connection["text_sha256"], "connection result references its immutable matching text report")
            web = run("webcheck", url, "--args", json.dumps({"modes": ["Http1"], "visits": 1}), "--timeout-ms", "2000")
            check(any(row["state"] == "OK" for row in web["rows"]), "normal webcheck entry completes native HTTP/1.1")
            latency = run("latency", "127.0.0.1", "--args", json.dumps({"protocol": "tcp", "port": port, "count": 2, "interval_ms": 10}))
            check(latency["game_latency_measured"] is False and latency["summaries"][0]["summary"]["success_count"] == 2, "latency reports actual TCP handshakes separately from game RTT")

        capabilities = run("webcheck", "--args", json.dumps({"capabilities_only": True, "browser_path": ""}))
        check(capabilities["native_http3"] != capabilities["rust_http3"] and capabilities["curl_path"] is None,
              "default HTTP/3 uses a built-in transport")
        client, tls = (("Windows WinHTTP HTTP/3 HEAD", "Schannel") if capabilities["native_http3"]
                       else ("Rust direct Quinn HTTP/3 HEAD", "rustls"))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as blackhole:
            blackhole.bind(("127.0.0.1", 0))
            url = f"https://127.0.0.1:{blackhole.getsockname()[1]}/"
            started = time.monotonic()
            web = run("webcheck", url, "--args", json.dumps({"modes": ["Http3"], "browser_path": ""}),
                      "--timeout-ms", "100")
            elapsed = time.monotonic() - started
        row = web["rows"][0]
        check(row["client"] == client and row["tls_backend"] == tls
              and row["trust_source"] == "System" and web["capabilities"]["curl_path"] is None,
              "normal webcheck entry uses the selected built-in HTTP/3 client")
        check(row["reason"] == "Timeout" and not row["complete"] and not row["quic_confirmed"]
              and not row["protocol_confirmed"] and elapsed < 5,
              "silent local QUIC endpoint obeys the deadline without confirming a protocol")
        observations["native_http3_timeout"] = row

        launcher = root / "zapret-rust.bat"
        expected_engine = str(root / "bin" / "winws2.exe")
        for folder in ["System32", "SysWOW64"]:
            command = [str(Path(os.environ["SystemRoot"]) / folder / "cmd.exe"), "/d", "/c", str(launcher), "--version"]
            result = subprocess.run(command, cwd=root, capture_output=True, timeout=10)
            check(result.returncode == 0 and result.stdout.decode().strip() == expected_version, f"{folder} invokes the x64 native application through zapret-rust.bat")
            result = subprocess.run(command[:-1] + ["--json", "compose", "--no-auto", "--dry-run"],
                                    cwd=root, capture_output=True, timeout=10)
            composed = json.loads(result.stdout) if result.returncode == 0 else {}
            check(result.returncode == 0 and composed.get("executable", "").replace("/", "\\") == expected_engine,
                  f"{folder} BAT root resolves to the actual engine path without dot components")
        executable.rename(root / "bin/mapped-old-native.exe")
        result = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/cmd.exe"), "/d", "/c", str(launcher), "--version"],
                                cwd=root, capture_output=True, timeout=10)
        check(result.returncode == 0 and result.stdout.decode().strip() == expected_version, "launcher still executes native recovery while the main image is absent")
        result = subprocess.run([str(Path(os.environ["SystemRoot"]) / "System32/cmd.exe"), "/d", "/c", str(launcher),
                                 "--json", "compose", "--no-auto", "--dry-run"],
                                cwd=root, capture_output=True, timeout=10)
        composed = json.loads(result.stdout) if result.returncode == 0 else {}
        check(result.returncode == 0 and composed.get("executable", "").replace("/", "\\") == expected_engine,
              "recovery BAT root keeps the exact engine ownership path")

    report = {"passed": passed, "count": len(passed), "archive_sha256": digest(archive.read_bytes()), "observations": observations,
              "live_changes": False, "privileged_install_or_restart": "NotExecuted"}
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"PASS {len(passed)} integrated native checks", flush=True)


if __name__ == "__main__":
    main()
