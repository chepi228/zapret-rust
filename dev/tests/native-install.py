"""Compatibility entry for cargo zapret check-install."""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from native_run import run
sys.exit(run(["check-install", *sys.argv[1:]]))
