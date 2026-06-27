import time
from dataclasses import dataclass, field


@dataclass
class Finding:
    title: str
    severity: str
    flow_step: str
    description: str
    request_payload: dict   = field(default_factory=dict)
    response_body: str      = ""
    expected: str           = ""
    actual: str             = ""
    proposed_fix: str       = ""


_findings: list[Finding] = []


def record(f: Finding):
    _findings.append(f)
    def clean(s: str) -> str:
        return s.encode("ascii", "replace").decode("ascii").replace("?", "-")
    print(f"\n{'='*60}")
    print(f"[FINDING] [{f.severity}] {clean(f.title)}")
    print(f"  Step:     {clean(f.flow_step)}")
    print(f"  Expected: {clean(f.expected)}")
    print(f"  Actual:   {clean(f.actual)}")
    print(f"  Fix:      {clean(f.proposed_fix)}")
    print("="*60)


def all_findings() -> list[Finding]:
    return list(_findings)


def generate_report(path: str = "reports/mh_bug_report.md"):
    import os
    os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)

    api_base = os.environ.get("MH_API_BASE", "https://devnet.multihopper.com")
    lines = [
        "# MultiHopper Agentic Flow — Bug Report",
        f"**Generated:** {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())}",
        f"**Environment:** {api_base}",
        f"**Total findings:** {len(_findings)}",
        "",
        "---",
        "",
    ]

    if not _findings:
        lines.append("No issues found — all tested behaviors matched documentation.")
    else:
        for sev in ["Critical", "High", "Medium", "Low", "Documentation"]:
            bucket = [f for f in _findings if f.severity == sev]
            if not bucket:
                continue
            lines.append(f"## {sev} ({len(bucket)})")
            lines.append("")
            for i, f in enumerate(bucket, 1):
                lines += [
                    f"### {i}. {f.title}",
                    f"**Severity:** {f.severity}  |  **Flow step:** `{f.flow_step}`",
                    "",
                    f.description,
                    "",
                    f"**Expected:** {f.expected}",
                    "",
                    f"**Actual:** {f.actual}",
                    "",
                ]
                if f.request_payload:
                    import json
                    lines += [
                        "**Request payload (sanitized):**",
                        "```json",
                        json.dumps(f.request_payload, indent=2),
                        "```",
                        "",
                    ]
                if f.response_body:
                    lines += [
                        "**Response body (sanitized):**",
                        "```",
                        f.response_body[:1000],
                        "```",
                        "",
                    ]
                lines += [
                    f"**Proposed fix:** {f.proposed_fix}",
                    "",
                    "---",
                    "",
                ]

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    print(f"\nReport written to {path}")


