from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from handlers.git_rule_ci import main
from handlers.cli_result import run_cli

if __name__ == "__main__":
    raise SystemExit(run_cli(main))
