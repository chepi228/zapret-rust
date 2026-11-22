"""Compatibility entry for native loopback acceptance with the historical comparison arm."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "dev"))
from native_run import run

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("binary", type=lambda value: str(Path(value).absolute()))
parser.add_argument("--output", required=True, type=lambda value: str(Path(value).absolute()))
parser.add_argument("--benchmark-rounds", type=int, default=3)
parser.add_argument("--subcommand", choices=["probe"])
args = parser.parse_args()
arguments = ["check-probe", args.binary, "--output", args.output, "--benchmark-rounds", str(args.benchmark_rounds), "--compare-legacy"]
if args.subcommand:
    arguments += ["--subcommand", args.subcommand]
sys.exit(run(arguments))
