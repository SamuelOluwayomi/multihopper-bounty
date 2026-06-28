import time
from dataclasses import dataclass, field

from src.redaction import redact_text, safe_json, sanitize


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
    confidence: str         = "Medium"
    evidence_level: str     = "Behavior observed in test environment"
    severity_rationale: str = ""


_findings: list[Finding] = []


def _is_transport_failure(f: Finding) -> bool:
    text = " ".join([
        f.actual or "",
        f.response_body or "",
        f.description or "",
    ])
    markers = [
        "HTTP 0",
        "HTTPSConnectionPool",
        "NewConnectionError",
        "Failed to establish a new connection",
        "NameResolutionError",
        "Max retries exceeded",
        "WinError 10013",
        "HTTP 429",
        "MH_004",
        "Rate limit exceeded",
    ]
    return any(marker in text for marker in markers)


def _calibrate_severity(f: Finding) -> Finding:
    sev = f.severity.strip()
    text = " ".join([
        f.title,
        f.description,
        f.expected,
        f.actual,
        f.response_body,
    ]).lower()

    if sev.lower() in {"critical", "crit"}:
        critical_proof = any(marker in text for marker in [
            "private key",
            "seed phrase",
            "bearer token",
            "api key value",
            "unauthorized transfer",
            "unauthorized withdrawal",
            "funds moved",
            "funds drained",
            "cross-tenant access",
            "remote code execution",
            "accepted without signature",
        ])
        if not critical_proof:
            f.severity = "High"
            f.severity_rationale = (
                f.severity_rationale
                or "Downgraded from Critical: current evidence shows a serious bug, "
                   "but not confirmed fund movement, credential disclosure, cross-tenant access, or RCE."
            )

    if "server responded http 400" in text or "rejected with" in text:
        if sev.lower() in {"critical", "high", "medium"} and "accepted" not in text:
            f.severity = "Info"
            f.severity_rationale = (
                f.severity_rationale
                or "Recorded as test evidence only: the tested bypass was rejected, so no vulnerability is proven."
            )

    if "documentation" in f.flow_step.lower() and f.severity.lower() == "critical":
        f.severity = "Documentation blocker"
        f.severity_rationale = (
            f.severity_rationale
            or "Documentation issue: severe integration impact, but not direct exploit proof."
        )

    return f


def record(f: Finding):
    if _is_transport_failure(f):
        print("\n[SKIP] Transport/network failure was not recorded as a bounty finding.")
        print(f"  Title: {f.title}")
        print(f"  Actual: {redact_text(f.actual or f.response_body)[:180]}")
        return

    f.request_payload = sanitize(f.request_payload)
    f.response_body = redact_text(f.response_body)
    f.actual = redact_text(f.actual)
    f.expected = redact_text(f.expected)
    f.description = redact_text(f.description)
    f.proposed_fix = redact_text(f.proposed_fix)
    f.severity_rationale = redact_text(f.severity_rationale)
    f = _calibrate_severity(f)

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
        for sev in ["Critical", "High", "Medium", "Low", "Documentation blocker", "Documentation", "Info"]:
            bucket = [f for f in _findings if f.severity == sev]
            if not bucket:
                continue
            lines.append(f"## {sev} ({len(bucket)})")
            lines.append("")
            for i, f in enumerate(bucket, 1):
                lines += [
                    f"### {i}. {f.title}",
                    f"**Severity:** {f.severity}  |  **Flow step:** `{f.flow_step}`",
                    f"**Confidence:** {f.confidence}  |  **Evidence level:** {f.evidence_level}",
                    "",
                    f.description,
                    "",
                    f"**Severity rationale:** {f.severity_rationale or 'Severity is limited to what the reproduced evidence proves.'}",
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
                        safe_json(f.request_payload, indent=2),
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
