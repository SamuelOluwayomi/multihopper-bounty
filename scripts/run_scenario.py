import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.oracle_scenarios import SCENARIOS, run_scenario
from src.redaction import safe_json


def main():
    if len(sys.argv) < 2 or sys.argv[1] in {"-h", "--help"}:
        print("Usage: python scripts/run_scenario.py <scenario_name> [waitSeconds]")
        print("")
        print("Available scenarios:")
        for name in sorted(SCENARIOS):
            print(f"  - {name}")
        return

    name = sys.argv[1]
    args = {}
    if name == "prepare_after_expiry" and len(sys.argv) >= 3:
        args["waitSeconds"] = int(sys.argv[2])

    status, result = run_scenario(name, args)
    print(f"HTTP {status}")
    print(safe_json(result, indent=2))


if __name__ == "__main__":
    main()
