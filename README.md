# MultiHopper Agentic Flow — Bug Bounty Harness

Testing suite for the [MultiHopper Superteam Earn Bounty](https://earn.superteam.fun).
Covers the full agentic flow: **create → prepare → sign → confirm-broadcast → monitor**.

---

## Getting Test Credentials

Before running any tests, you need three things:

1. **Devnet API key** — create one at: https://devnet.multihopper.com/developer/dashboard
2. **A funded devnet wallet** — get free devnet SOL: https://faucet.solana.com
3. **Join the MultiHopper Builder Telegram** for support: https://t.me/multihopperbuilde

---

## Quick Start

```powershell
# 1. Clone and enter the repo
git clone <your-repo-url>
cd multihopper-bounty

# 2. Create and activate a virtual environment (recommended)
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Copy and fill in your credentials
copy .env.example .env
# Edit .env with your test API key, source wallet, recipient wallet, and private key

# 5a. Run the full pytest suite
python -m pytest tests/ -v

# 5b. Or run the full calibrated bounty workflow
python scripts/run_all.py
# writes reports/submission_report.md
```

---

## Project Structure

```
multihopper-bounty/
├── src/
│   ├── harness.py           # Standalone test harness (run directly)
│   ├── client.py            # Thin API client wrapper
│   ├── signer.py            # Transaction signing helpers
│   └── findings.py          # Finding dataclass + Markdown report generator
├── tests/
│   ├── conftest.py          # Shared pytest fixtures
│   ├── test_idempotency.py  # Idempotency-Key behavior tests
│   ├── test_validation.py   # Input validation edge cases
│   ├── test_broadcast_flow.py  # confirm-broadcast state machine tests
│   ├── test_signing.py      # Signing helper unit + integration tests
│   └── test_status_polling.py  # GET /transfers/:id monitoring tests
├── reports/                 # Auto-generated bug reports (git-ignored)
├── scripts/
│   ├── run_all.py           # Full calibrated workflow + consolidated report
│   └── generate_report.py   # Standalone report generator CLI
├── CLAUDE.md                # Agent context file (MultiHopper API summary)
├── pyproject.toml           # pytest configuration
├── .env.example             # Environment variable template
├── requirements.txt
└── README.md
```

---

## Submission Format

Each finding in `reports/submission_report.md` follows the bounty format:
- **Title** + severity (Critical / High / Medium / Low / Documentation)
- **Environment** + flow step
- **Steps to reproduce** (the test that triggered it)
- **Evidence** — sanitized request/response, expected vs actual
- **Impact** on agentic usage
- **Proposed fix**

---

## Test Coverage

| Area | Test file |
|---|---|
| Idempotency-Key (create + prepare) | `test_idempotency.py` |
| Input validation (hops, arrivalSeconds, wallets, externalId) | `test_validation.py` |
| confirm-broadcast state machine | `test_broadcast_flow.py` |
| Client-side signing (VersionedTransaction / Legacy) | `test_signing.py` |
| Status polling / GET /transfers/:id | `test_status_polling.py` |
| Full agentic flow + estimate + signing | `src/harness.py` |

---

## Resources

- [MultiHopper Dev Docs](https://dev-docs.multihopper.com)
- [Quickstart](https://dev-docs.multihopper.com/quickstart)
- [Agentic Integration Guide](https://dev-docs.multihopper.com/guides/agentic-integration)
- [API Reference](https://dev-docs.multihopper.com/api-reference/introduction)
