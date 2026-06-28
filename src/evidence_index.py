import os
import re
from dataclasses import dataclass


REPORT_DIR = "reports"


@dataclass(frozen=True)
class EvidenceFinding:
    source: str
    title: str
    severity: str = "Unknown"


DEFAULT_DUPLICATE_TOPICS = [
    "SQL/ORM schema leak via overrides/status injection",
    "overrides can overwrite amountRaw/amountTokens/tokenDecimals/sourceOwner/recipientWallet",
    "amountRaw and amountTokens decimal mismatch accepted at creation",
    "self-transfer sourceOwner == recipientWallet accepted",
    "confirm-broadcast before prepare with invalid fake signatures",
    "TypeScript VersionedTransaction.sign destroys server partial signatures",
    "CLAUDE.md / agent context hardcodes mainnet API_BASE",
    "Python docs typo bytes([0x 80])",
    "webhook docs omit timestamp/replay protection",
    "simple hops and arrivalSeconds schema boundary checks",
    "missing/invalid Idempotency-Key basic validation",
    "duplicate externalId basic uniqueness check",
    "invalid wallet format basic validation",
]


PRIORITY_GAPS = [
    "signature-to-prepared-bundle binding in confirm-broadcast",
    "wrong signature cardinality and ordering",
    "valid-looking but wrong-state confirm-broadcast errors",
    "state mutation after rejected confirm-broadcast",
    "concurrent same-key idempotency races and MH_072 behavior",
    "same Idempotency-Key with different body and documented MH_071 behavior",
    "prepare cache consistency for same transfer under retries",
    "blockhash expiry and safe resume after partial broadcast",
    "GET /transfers status consistency after prepare and failed confirm",
    "cross-transfer signature replay after real devnet broadcast",
    "prepared transaction invariants: required signer slots, duplicate tx messages, null fields after resume",
]


def _read_report(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return fh.read()
    except OSError:
        return ""


def load_evidence_findings(report_dir: str = REPORT_DIR) -> list[EvidenceFinding]:
    if not os.path.isdir(report_dir):
        return []

    findings: list[EvidenceFinding] = []
    skip_titles = {
        "Description",
        "Request (curl equivalent)",
        "Actual Server Response",
        "Risk & Impact",
        "Suggested Fix",
        "Step-by-Step Reproduction",
        "Proof-of-Concept Payload",
        "Vulnerability Description",
        "Impact on Automated Agent Workflows",
        "Submission framing",
        "Highest-value bug classes",
        "Agentic & On-Chain Security Impact Analysis",
        "Mitigation Strategies",
    }
    for name in os.listdir(report_dir):
        if not name.endswith(".md"):
            continue
        if name in {"evidence_index.md", "testing-playbook.md"}:
            continue
        path = os.path.join(report_dir, name)
        text = _read_report(path)
        current_severity = "Unknown"
        for line in text.splitlines():
            line = line.strip()
            if not line.startswith(("## ", "### ")):
                continue
            section_match = re.match(r"^##\s+(Critical|High|Medium|Low|Documentation)\b", line, re.I)
            if section_match:
                current_severity = section_match.group(1).title()
                continue
            if "Suggested" in line or "Summary" in line or "Step-by-Step" in line:
                continue
            title = re.sub(r"^#+\s*", "", line).strip()
            title = title.replace("â€”", "-").replace("â†’", "->")
            if title in skip_titles or title.startswith(("Critical (", "High (", "Medium (", "Low (", "Documentation (")):
                continue
            if re.match(r"^\d+\.\s+(Deep Smart Contract|Autonomous Agent|Mitigation)", title):
                continue
            severity = current_severity
            match = re.match(r"\[(CRITICAL|HIGH|MEDIUM|LOW|Critical|High|Medium|Low|Documentation)\]\s*(.*)", title)
            if match:
                severity = match.group(1).title()
                title = match.group(2).strip()
            inline = re.match(r"^\d+\.\s+(Critical|High|Medium|Low|Documentation)\s+(.+)", title, re.I)
            if inline:
                severity = inline.group(1).title()
                title = inline.group(2).strip()
            title = re.sub(r"^\d+\.\s*", "", title)
            findings.append(EvidenceFinding(source=name, title=title, severity=severity))
    return findings


def build_oracle_context() -> str:
    findings = load_evidence_findings()
    lines = [
        "Known prior evidence. Avoid spending oracle turns reproducing these unless you are testing a stronger variant:",
    ]
    for topic in DEFAULT_DUPLICATE_TOPICS:
        lines.append(f"- {topic}")

    if findings:
        lines.append("")
        lines.append("Report headings already present:")
        for finding in findings[:40]:
            lines.append(f"- [{finding.severity}] {finding.title} ({finding.source})")

    lines.append("")
    lines.append("Preferred unexplored targets:")
    for gap in PRIORITY_GAPS:
        lines.append(f"- {gap}")

    return "\n".join(lines)
