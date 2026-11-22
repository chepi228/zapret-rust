"""Compatibility entry for cargo zapret check-package."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_run import run

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("archive", type=lambda value: str(Path(value).absolute()))
parser.add_argument("--output", required=True, type=lambda value: str(Path(value).absolute()))
args = parser.parse_args()
sys.exit(run(["check-package", args.archive, "--output", args.output]))
