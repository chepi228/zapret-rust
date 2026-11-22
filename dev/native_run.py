"""Launch the native developer CLI from compatibility entry points."""
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]

def run(arguments):
    environment = os.environ.copy()
    cargo = shutil.which("cargo")
    if cargo is None:
        tools = ROOT / "dist/rust-tools"
        cargo = tools / "cargo/bin/cargo.exe"
        if not cargo.is_file():
            raise RuntimeError("Install Rust, then run cargo zapret")
        environment["CARGO_HOME"] = str(tools / "cargo")
        environment["RUSTUP_HOME"] = str(tools / "rustup")
        paths = [str(cargo.parent)]
        llvm = sorted(tools.glob("llvm-mingw-*-ucrt-x86_64"), reverse=True)
        if llvm:
            paths.append(str(llvm[0] / "bin"))
        environment["PATH"] = os.pathsep.join(paths + [environment.get("PATH", "")])
    return subprocess.run([str(cargo), "zapret", *arguments], cwd=ROOT, env=environment, check=False).returncode
