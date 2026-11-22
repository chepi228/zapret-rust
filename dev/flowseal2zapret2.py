"""Compatibility entry point for cargo zapret import-flowseal."""
import os
import argparse
from pathlib import Path
import shutil
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--allow-known-differences", action="store_true")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    environment = os.environ.copy()
    cargo = shutil.which("cargo")
    if cargo is None:
        tools = root / "dist/rust-tools"
        cargo = tools / "cargo/bin/cargo.exe"
        if not cargo.is_file():
            raise RuntimeError("Install Rust, then run cargo zapret import-flowseal")
        environment["CARGO_HOME"] = str(tools / "cargo")
        environment["RUSTUP_HOME"] = str(tools / "rustup")
        environment["PATH"] = str(cargo.parent) + os.pathsep + environment["PATH"]
    command = [
        str(cargo), "zapret", "import-flowseal",
        str(args.source.absolute()), str(args.output.absolute()),
    ]
    if args.check:
        command.append("--check")
    if args.allow_known_differences:
        command.append("--allow-known-differences")
    return subprocess.run(
        command,
        cwd=root,
        env=environment,
        check=False,
    ).returncode


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, RuntimeError) as error:
        print(str(error), file=sys.stderr)
        sys.exit(1)
