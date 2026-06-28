import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.evidence_index import DEFAULT_DUPLICATE_TOPICS, PRIORITY_GAPS, load_evidence_findings


def main():
    findings = load_evidence_findings()
    os.makedirs("reports", exist_ok=True)
    lines = [
        "# MultiHopper Evidence Index",
        "",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
        "",
        "## Already Covered",
        "",
    ]
    for topic in DEFAULT_DUPLICATE_TOPICS:
        lines.append(f"- {topic}")

    lines += [
        "",
        "## Report Headings Found",
        "",
    ]
    if findings:
        for finding in findings:
            lines.append(f"- **{finding.severity}** - {finding.title} (`{finding.source}`)")
    else:
        lines.append("- No markdown report headings found.")

    lines += [
        "",
        "## Best Next Targets",
        "",
    ]
    for gap in PRIORITY_GAPS:
        lines.append(f"- {gap}")

    lines += [
        "",
        "## Evidence Handling Rule",
        "",
        "Keep raw exploit-relevant technical evidence such as SQL queries, table names, column names, request IDs, transaction signatures, transfer IDs, HTTP status codes, and exact error messages.",
        "",
        "Do not publish live API keys, private keys, seed phrases, bearer tokens, or passwords. Store a SHA-256 fingerprint and length instead so engineers can match the secret internally.",
        "",
    ]

    path = "reports/evidence_index.md"
    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"Wrote {path}")


if __name__ == "__main__":
    main()
