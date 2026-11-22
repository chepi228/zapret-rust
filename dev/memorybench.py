"""Compatibility entry for the Rust Lua memory benchmark. --runtime is retained for old invocations."""
import argparse
from pathlib import Path
import sys
from native_run import run

parser = argparse.ArgumentParser(description=__doc__)
for name in ("pkg", "baseline", "out"):
    parser.add_argument("--" + name, required=True, type=lambda value: str(Path(value).absolute()))
parser.add_argument("--baseline-ref")
parser.add_argument("--runtime")
parser.add_argument("--hosts", type=int, default=1000)
parser.add_argument("--rounds", type=int, default=7)
parser.add_argument("--warm", type=int, default=10000)
args = parser.parse_args()
arguments = ["memory-bench", "--pkg", args.pkg, "--baseline", args.baseline, "--out", args.out, "--hosts", str(args.hosts), "--rounds", str(args.rounds), "--warm", str(args.warm)]
if args.baseline_ref:
    arguments += ["--baseline-ref", args.baseline_ref]
sys.exit(run(arguments))
