import os
import re
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from src.redaction import redact_text


ROOT = Path(__file__).resolve().parents[1]
REPORTS = ROOT / "reports"


SEVERITY_ORDER = {
    "Critical": 0,
    "High": 1,
    "Medium": 2,
    "Low": 3,
    "Documentation blocker": 4,
    "Documentation": 5,
    "Info": 6,
    "Unknown": 9,
}


CALIBRATION_NOTE = (
    "Severity is capped to the proof level. Critical is reserved for confirmed live "
    "credential-value disclosure, unauthorized access, unauthorized fund movement, "
    "cross-tenant access, RCE, or equivalent. Schema leakage, contradictory quote "
    "state, rejected bypasses, and documentation failures are kept below Critical "
    "unless stronger evidence is produced."
)


def read(name: str) -> str:
    path = REPORTS / name
    if not path.exists():
        return ""
    return redact_text(path.read_text(encoding="utf-8", errors="replace"))


def clean_text(text: str) -> str:
    replacements = {
        "â€”": "-",
        "â†’": "->",
        "âœ…": "Yes",
        "âš ï¸": "Warning",
        "Ã—": "x",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def clean_body(body: str) -> str:
    lines = []
    for line in body.splitlines():
        if re.match(r"^###\s+\d+\.\s+", line):
            continue
        if re.match(r"^##\s+\[(CRITICAL|HIGH|MEDIUM|LOW|INFO|Documentation blocker|Documentation)\]", line, re.I):
            continue
        if line.strip() == "---":
            continue
        lines.append(line)
    return "\n".join(lines).strip()


def extract_sections(text: str) -> list[dict]:
    text = clean_text(text)
    sections: list[dict] = []
    current_sev = "Unknown"
    current_title = None
    current_lines: list[str] = []

    def flush():
        nonlocal current_title, current_lines
        if current_title and current_lines:
            sections.append({
                "title": current_title,
                "severity": current_sev,
                "body": "\n".join(current_lines).strip(),
            })
        current_title = None
        current_lines = []

    for line in text.splitlines():
        sev_match = re.match(r"^##\s+(Critical|High|Medium|Low|Documentation blocker|Documentation|Info)\b", line, re.I)
        if sev_match:
            flush()
            current_sev = sev_match.group(1)
            current_sev = current_sev[0].upper() + current_sev[1:]
            continue

        poc_match = re.match(r"^##\s+\[(CRITICAL|HIGH|MEDIUM|LOW|INFO|Documentation blocker|Documentation)\]\s+(.+)", line, re.I)
        if poc_match:
            flush()
            current_sev = poc_match.group(1).title()
            current_title = poc_match.group(2).strip()
            current_lines = [line]
            continue

        finding_match = re.match(r"^###\s+\d+\.\s+(.+)", line)
        if finding_match:
            flush()
            current_title = finding_match.group(1).strip()
            current_lines = [line]
            continue

        if current_title:
            current_lines.append(line)

    flush()
    return sections


def canonical(title: str) -> str:
    title = title.lower()
    title = re.sub(r"[^a-z0-9]+", " ", title)
    synonyms = {
        "typescript signing example destroys server partial signatures": "typescript partial signature docs bug",
        "server partial signature overwritten during client signing": "typescript partial signature docs bug",
        "sql orm schema leaked in http 500 error response via overrides injection": "sql schema leak",
        "critical information disclosure sql schema leakage": "sql schema leak",
        "overrides merging allows arbitrary field overwrite 100 000 000x amount discrepancy accepted": "overrides amount overwrite",
        "amountraw amounttokens decimal consistency not validated at creation": "amount mismatch",
        "logical validation bypass amount self transfer mismatch": "amount mismatch self transfer",
        "self transfer sourceowner recipientwallet accepted without error": "self transfer",
        "claude md context block hardcodes mainnet api base agents will hit production": "mainnet context docs bug",
        "agentic python signing example contains invalid syntax bytes 0x 80": "python docs syntax bug",
        "webhook verification docs omit timestamp replay protection and conflict with post idempotency rule": "webhook replay docs gap",
        "confirm broadcast called before prepare state machine boundary test": "confirm before prepare rejected boundary",
    }
    key = title.strip()
    return synonyms.get(key, key)


def calibrated(section: dict) -> dict:
    title = section["title"]
    body = section["body"]
    sev = section["severity"]
    lower = f"{title}\n{body}".lower()

    if sev == "Critical":
        critical_proof = any(token in lower for token in [
            "private key value",
            "seed phrase",
            "bearer token value",
            "unauthorized access",
            "unauthorized transfer",
            "funds moved",
            "funds drained",
            "cross-tenant access",
            "remote code execution",
        ])
        if not critical_proof:
            sev = "High"
            body += "\n\n**Severity calibration:** Downgraded from Critical because the available evidence does not prove live credential-value disclosure, unauthorized access, unauthorized fund movement, cross-tenant access, or RCE."

    if "server responded http 400" in lower or "attempted bypass was not accepted" in lower:
        if "accepted without prepare" not in lower:
            sev = "Info"
            body += "\n\n**Severity calibration:** Recorded as boundary-test evidence; the bypass was rejected."

            section["severity"] = sev
    section["body"] = clean_body(body)
    return section


def choose_best(existing: dict, candidate: dict) -> dict:
    if SEVERITY_ORDER.get(candidate["severity"], 9) < SEVERITY_ORDER.get(existing["severity"], 9):
        return candidate
    if len(candidate["body"]) > len(existing["body"]) and candidate["severity"] == existing["severity"]:
        return candidate
    return existing


def main():
    REPORTS.mkdir(exist_ok=True)
    sources = [
        "poc_evidence.md",
        "mh_bug_report.md",
        "ai_red_team_findings.md",
    ]

    deduped: dict[str, dict] = {}
    for source in sources:
        for section in extract_sections(read(source)):
            section["source"] = source
            section = calibrated(section)
            key = canonical(section["title"])
            if key in deduped:
                deduped[key] = choose_best(deduped[key], section)
            else:
                deduped[key] = section

    findings = sorted(
        deduped.values(),
        key=lambda item: (SEVERITY_ORDER.get(item["severity"], 9), item["title"]),
    )

    generated = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    lines = [
        "# MultiHopper Bounty Submission Report",
        "",
        f"**Generated:** {generated}",
        "**Scope:** Existing generated reports only; no tests were rerun.",
        "",
        "## Severity Discipline",
        "",
        CALIBRATION_NOTE,
        "",
        "## Executive Summary",
        "",
        f"This report consolidates `{len(sources)}` existing report files into `{len(findings)}` deduplicated finding entries.",
        "",
        "| Severity | Count |",
        "|---|---:|",
    ]

    for sev in ["Critical", "High", "Medium", "Low", "Documentation blocker", "Documentation", "Info", "Unknown"]:
        count = sum(1 for item in findings if item["severity"] == sev)
        if count:
            lines.append(f"| {sev} | {count} |")

    lines += [
        "",
        "## Findings",
        "",
    ]

    for idx, item in enumerate(findings, 1):
        lines += [
            f"### {idx}. [{item['severity']}] {item['title']}",
            "",
            f"**Source:** `{item['source']}`",
            "",
            item["body"],
            "",
            "---",
            "",
        ]

    lines += [
        "## Appendix: Source Files",
        "",
    ]
    for source in sources:
        path = REPORTS / source
        if path.exists():
            lines.append(f"- `{source}` ({path.stat().st_size} bytes)")

    out = REPORTS / "submission_report.md"
    out.write_text("\n".join(lines), encoding="utf-8")
    print(f"Wrote {out}")


if __name__ == "__main__":
    main()
