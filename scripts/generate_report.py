import argparse
import os
import sys

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from src.findings import generate_report, all_findings


def main():
    parser = argparse.ArgumentParser(
        description="Generate a Markdown bug report from recorded findings.",
    )
    parser.add_argument(
        "--out", "-o",
        default="reports/mh_bug_report.md",
        metavar="PATH",
        help="Output file path (default: reports/mh_bug_report.md)",
    )
    parser.add_argument(
        "--stdout",
        action="store_true",
        help="Print report to stdout instead of writing a file",
    )
    args = parser.parse_args()

    findings = all_findings()
    print(f"Findings loaded: {len(findings)}")

    if args.stdout:
        import io
        tmp = "_tmp_report.md"
        generate_report(tmp)
        with open(tmp) as f:
            print(f.read())
        os.remove(tmp)
    else:
        os.makedirs(os.path.dirname(args.out), exist_ok=True)
        generate_report(args.out)
        print(f"Report written → {args.out}")


if __name__ == "__main__":
    main()

