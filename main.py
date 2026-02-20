from pathlib import Path
import sys

# Compat wrapper for running from repository root: `python main.py ...`
ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from miskzi_ciphers.cli import main as cli_main


if __name__ == "__main__":
    raise SystemExit(cli_main())
