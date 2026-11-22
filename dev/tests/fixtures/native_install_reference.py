"""Publish the native controller while a safe preview holds its previous image.

Build/install changes package executables only. No live bypass or Windows service
is started, stopped, installed or removed by this check.
"""
import hashlib
import json
import os
from pathlib import Path
import subprocess

root = Path(__file__).resolve().parents[2]
output = root / "dist/native"
binary = root / "bin/zapret-rust.exe"
worker = root / "bin/zapret-rust-worker.exe"
previous = output / "previous-controllers"
before_sidecars = {path.name for path in (root / "bin").glob(".native-build-*")}
before_backups = set(previous.glob("*.old")) if previous.exists() else set()
preview = subprocess.Popen(
    [str(binary), "menu-preview", "--width", "55", "--height", "16", "--wait"],
    cwd=root, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    creationflags=subprocess.CREATE_NO_WINDOW,
)
background_preview = None
try:
    first_line = preview.stdout.readline().decode("utf-8")
    assert first_line.startswith("╭") and "zapret-rust v" in first_line and preview.poll() is None
    if worker.is_file():
        background_preview = subprocess.Popen(
            [str(worker), "--self-check", "--wait"], cwd=root,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
        report = json.loads(background_preview.stdout.readline())
        assert report["console_window"] is False and background_preview.poll() is None
    powershell = Path(os.environ["SystemRoot"]) / "System32/WindowsPowerShell/v1.0/powershell.exe"
    with (output / "native-install-build.log").open("wb") as log:
        result = subprocess.run(
            [str(powershell), "-NoProfile", "-ExecutionPolicy", "Bypass", "-File",
             str(root / "dev/native-build.ps1"), "-Action", "build", "-Package", "zapret", "-Install"],
            cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=180,
        )
    assert result.returncode == 0, "Build/install failed; inspect native-install-build.log"
    assert preview.poll() is None, "Publishing an update must not close an existing menu"
    compiled = (output / "release/zapret.exe").read_bytes()
    assert binary.read_bytes() == compiled == (root / "bin/zapret-rust-recovery.exe").read_bytes()
    compiled_worker = (output / "release/zapret-worker.exe").read_bytes()
    assert worker.read_bytes() == compiled_worker
    if background_preview is not None:
        assert background_preview.poll() is None, "Publishing an update must not close a mapped background host"
    after_sidecars = {path.name for path in (root / "bin").glob(".native-build-*")}
    assert after_sidecars <= before_sidecars, "Installer left a new sidecar inside bin"
    retained = sorted(str(path.relative_to(root)) for path in set(previous.glob("*.old")) - before_backups)
    report = {
        "build_exit": result.returncode, "mapped_preview_survived": True,
        "new_sidecars_in_bin": [], "retained_outside_bin": retained,
        "binary_sha256": hashlib.sha256(compiled).hexdigest(),
        "worker_sha256": hashlib.sha256(compiled_worker).hexdigest(),
        "mapped_background_survived": background_preview is not None,
        "live_bypass_or_service_control": False,
    }
    (output / "native-install.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2), flush=True)
finally:
    preview.communicate(input=b"\n", timeout=10)
    if background_preview is not None:
        background_preview.communicate(input=b"\n", timeout=10)
