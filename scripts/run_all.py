import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.evidence_index import DEFAULT_DUPLICATE_TOPICS, PRIORITY_GAPS, load_evidence_findings
from src.redaction import redact_text


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"
INTERMEDIATE_REPORTS = [
    "ai_oracle_trace.jsonl",
    "ai_red_team_findings.md",
    "evidence_index.md",
    "final_bounty_report.md",
    "mh_bug_report.md",
    "mh_bug_report_enriched.md",
    "poc_evidence.md",
]


def run_step(name: str, command: list[str], env: dict[str, str]) -> tuple[int, str]:
    print(f"\n{'=' * 72}")
    print(f"STEP: {name}")
    print(f"CMD: {' '.join(command)}")
    print(f"{'=' * 72}")
    proc = subprocess.run(
        command,
        cwd=ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    output = redact_text(proc.stdout or "")
    print(output)
    return proc.returncode, output


def read_report(name: str) -> str:
    path = REPORTS / name
    if not path.exists():
        return f"_Missing report: `{name}`_\n"
    return redact_text(path.read_text(encoding="utf-8", errors="replace"))


def latest_trace(limit: int = 20) -> str:
    path = REPORTS / "ai_oracle_trace.jsonl"
    if not path.exists():
        return "_No oracle trace generated._\n"
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    tail = lines[-limit:]
    if not tail:
        return "_Oracle trace is empty._\n"
    return "\n".join(tail)


def build_final_report(step_results: list[tuple[str, int]], args):
    REPORTS.mkdir(exist_ok=True)
    findings = load_evidence_findings()
    generated = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())

    lines = [
        "# MultiHopper Bounty Report - Combined Evidence",
        "",
        f"**Generated:** {generated}",
        f"**Target:** `{os.environ.get('MH_API_BASE', 'https://devnet.multihopper.com')}`",
        "",
        "## Run Summary",
        "",
        "| Phase | Exit Code |",
        "|---|---:|",
    ]
    for name, code in step_results:
        lines.append(f"| {name} | `{code}` |")

    lines += [
        "",
        "## Severity Discipline",
        "",
        "Severity is intentionally capped to the proof level. Critical should only be used for confirmed live credential-value disclosure, unauthorized access, unauthorized fund movement, cross-tenant access, RCE, or equivalent. Schema leakage, contradictory quote state, rejected bypasses, and documentation failures are capped below Critical unless stronger evidence is produced.",
        "",
        "## Already Covered / Avoid Repeating",
        "",
    ]
    for topic in DEFAULT_DUPLICATE_TOPICS:
        lines.append(f"- {topic}")

    lines += [
        "",
        "## Best Remaining Targets",
        "",
    ]
    for gap in PRIORITY_GAPS:
        lines.append(f"- {gap}")

    lines += [
        "",
        "## Findings Index",
        "",
    ]
    if findings:
        lines += ["| Severity | Title | Source |", "|---|---|---|"]
        for f in findings:
            if f.source in {"mh_bug_report_enriched.md"}:
                continue
            lines.append(f"| {f.severity} | {f.title} | `{f.source}` |")
    else:
        lines.append("_No finding headings parsed._")

    lines += [
        "",
        "---",
        "",
        "## Agentic Harness + Deep Probes",
        "",
        read_report("mh_bug_report.md"),
        "",
        "---",
        "",
        "## Proof-of-Concept Evidence",
        "",
        read_report("poc_evidence.md"),
        "",
        "---",
        "",
        "## AI Oracle Findings",
        "",
        read_report("ai_red_team_findings.md"),
        "",
        "---",
        "",
        "## AI Oracle Trace Tail",
        "",
        "```jsonl",
        latest_trace(args.trace_lines),
        "```",
        "",
        "---",
        "",
        "## Evidence Index",
        "",
        read_report("evidence_index.md"),
    ]

    out = REPORTS / "submission_report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nFinal combined report written to {out}")

    if not args.keep_intermediate:
        for name in INTERMEDIATE_REPORTS:
            path = REPORTS / name
            if path.exists():
                path.unlink()
        print("Removed intermediate report files. Use --keep-intermediate to retain them.")


def main():
    parser = argparse.ArgumentParser(description="Run all MultiHopper bounty probes and build one combined report.")
    parser.add_argument("--oracle-turns", default="12", help="Number of AI oracle turns.")
    parser.add_argument("--skip-oracle", action="store_true", help="Skip AI oracle phase.")
    parser.add_argument("--skip-poc", action="store_true", help="Skip PoC evidence phase.")
    parser.add_argument("--slow-expiry", action="store_true", help="Also run prepare_after_expiry scenario with 75s wait.")
    parser.add_argument("--trace-lines", type=int, default=20, help="Number of oracle trace lines to include.")
    parser.add_argument("--keep-intermediate", action="store_true", help="Keep phase reports after building submission_report.md.")
    args = parser.parse_args()

    REPORTS.mkdir(exist_ok=True)
    env = os.environ.copy()
    env["MH_SKIP_AI"] = "1"

    results: list[tuple[str, int]] = []
    code, _ = run_step("harness + deep probes", [sys.executable, "src/harness.py"], env)
    results.append(("harness + deep probes", code))

    if args.slow_expiry:
        code, _ = run_step(
            "slow expiry scenario",
            [sys.executable, "scripts/run_scenario.py", "prepare_after_expiry", "75"],
            env,
        )
        results.append(("slow expiry scenario", code))

    if not args.skip_poc:
        code, _ = run_step("poc evidence", [sys.executable, "src/poc_probe.py"], env)
        results.append(("poc evidence", code))

    if not args.skip_oracle:
        oracle_env = env.copy()
        oracle_env["MH_ORACLE_TURNS"] = str(args.oracle_turns)
        code, _ = run_step("ai oracle", [sys.executable, "src/ai_red_team.py"], oracle_env)
        results.append(("ai oracle", code))

    code, _ = run_step("evidence index", [sys.executable, "scripts/summarize_evidence.py"], env)
    results.append(("evidence index", code))

    build_final_report(results, args)


if __name__ == "__main__":
    main()
