import os
import sys
import uuid
import json
import time
import threading 
import requests
from typing import Optional

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dotenv import load_dotenv
load_dotenv()

from src.client import MultiHopperClient
from src.signer import load_keypair, sign_all, sign_versioned, server_sigs_preserved, AVAILABLE as SIGNING
from src.findings import record, Finding

SOURCE  = os.environ.get("SOURCE_WALLET", "")
DEST    = os.environ.get("RECIPIENT_WALLET", "")
RPC_URL = os.environ.get("SOLANA_RPC_URL", "https://api.devnet.solana.com")
client  = MultiHopperClient()


class AgentMemory:
    def __init__(self):
        self.transfer_id: Optional[int] = None
        self.prepared_txs: Optional[dict] = None
        self.keeper_sig: Optional[str] = None
        self.step_log: list[dict] = []

    def log(self, step: str, status: int, data: dict):
        self.step_log.append({"step": step, "status": status, "data": data})
        print(f"  [AGENT] {step} → HTTP {status}")


def _broadcast_tx(base64_tx: str, label: str) -> Optional[str]:
    try:
        resp = requests.post(RPC_URL, json={
            "jsonrpc": "2.0", "id": 1,
            "method": "sendTransaction",
            "params": [base64_tx, {"encoding": "base64", "skipPreflight": False}],
        }, timeout=30)
        result = resp.json()
        if "error" in result:
            print(f"  [BROADCAST] {label} RPC error: {result['error']}")
            return None
        sig = result.get("result")
        print(f"  [BROADCAST] {label}: {sig}")
        return sig
    except Exception as e:
        print(f"  [BROADCAST] {label} exception: {e}")
        return None


def _wait_confirmed(sig: str, label: str, retries: int = 12) -> bool:
    for _ in range(retries):
        time.sleep(5)
        try:
            resp = requests.post(RPC_URL, json={
                "jsonrpc": "2.0", "id": 1,
                "method": "getSignatureStatuses",
                "params": [[sig], {"searchTransactionHistory": True}],
            }, timeout=30)
            val = (resp.json().get("result", {}).get("value") or [None])[0]
            if val and val.get("confirmationStatus") in ("confirmed", "finalized"):
                print(f"  [BROADCAST] {label} confirmed")
                return True
        except Exception:
            pass
    print(f"  [BROADCAST] {label} timed out — continuing")
    return False


def run_full_agentic_flow() -> dict:
    print("\n[AGENT] Starting full agentic transfer flow")
    mem = AgentMemory()
    keypair = load_keypair()
    if not keypair:
        print("  [AGENT] No signing keypair — flow aborted")
        return {"aborted": True, "reason": "no_keypair"}

    s, d = client.create(SOURCE, DEST)
    mem.log("create", s, d)
    if s not in (200, 201):
        return {"aborted": True, "reason": "create_failed", "status": s}
    transfer_id = d.get("id")
    if not isinstance(transfer_id, int):
        return {
            "aborted": True,
            "reason": "missing_transfer_id",
            "status": s,
            "response_keys": list(d.keys()),
        }
    mem.transfer_id = transfer_id

    s, d = client.prepare(transfer_id)
    mem.log("prepare", s, d)
    if s != 200:
        return {"aborted": True, "reason": "prepare_failed", "status": s}
    mem.prepared_txs = d.get("preparedTxs", {})

    if not mem.prepared_txs:
        record(Finding(
            title="preparedTxs absent from /prepare response",
            severity="High",
            flow_step="POST /transfers/:id/prepare",
            description="The 'preparedTxs' key was absent from the /prepare response. "
                        "An agent following the documented flow will crash with a KeyError.",
            expected="{ preparedTxs: { keeperFundingTx, routeInitTxs, orchestratorInitTx, sessionInitTxs } }",
            actual=f"Response keys: {list(d.keys())}",
            proposed_fix="Always return 'preparedTxs' key even when all fields are null.",
        ))
        return {"aborted": True, "reason": "no_prepared_txs"}

    _check_null_fields(mem.prepared_txs, transfer_id)
    signed = sign_all(mem.prepared_txs, keypair)

    keeper_tx = signed.get("keeperFundingTx")
    if keeper_tx:
        keeper_sig = _broadcast_tx(keeper_tx, "keeperFundingTx")
        if keeper_sig:
            mem.keeper_sig = keeper_sig
            _wait_confirmed(keeper_sig, "keeperFundingTx")
            s, d = client.confirm_broadcast(transfer_id, {
                "routeInitSignatures": [],
                "keeperFundingSignature": keeper_sig,
            })
            mem.log("confirm-broadcast-1 (keeper only)", s, d)
            if s not in (200, 201):
                record(Finding(
                    title="confirm-broadcast step-1 rejected valid keeperFundingSignature",
                    severity="High",
                    flow_step="POST /transfers/:id/confirm-broadcast",
                    description="The first confirm-broadcast call (keeper sig only) was rejected. "
                                "An agent following the documented two-step pattern will fail here.",
                    expected="HTTP 200",
                    actual=f"HTTP {s}: {json.dumps(d)[:300]}",
                    proposed_fix="Accept keeperFundingSignature with empty routeInitSignatures[] in first call.",
                ))

    for i, entry in enumerate(signed.get("routeInitTxs") or []):
        sig = _broadcast_tx(entry["base64"], f"routeInitTxs[{i}]")
        if sig:
            _wait_confirmed(sig, f"routeInitTxs[{i}]")
            time.sleep(3)

    if signed.get("orchestratorInitTx"):
        sig = _broadcast_tx(signed["orchestratorInitTx"], "orchestratorInitTx")
        if sig:
            _wait_confirmed(sig, "orchestratorInitTx")
            time.sleep(3)

    for i, b64 in enumerate(signed.get("sessionInitTxs") or []):
        sig = _broadcast_tx(b64, f"sessionInitTxs[{i}]")
        if sig:
            _wait_confirmed(sig, f"sessionInitTxs[{i}]")

    s, d = client.confirm_broadcast(transfer_id, {
        "keeperFundingSignature": mem.keeper_sig or "",
        "routeInitSignatures": [],
    })
    mem.log("confirm-broadcast-2 (final)", s, d)

    print(f"\n[AGENT] Polling transfer {transfer_id}...")
    for _ in range(10):
        time.sleep(6)
        s, d = client.get(transfer_id)
        status = d.get("status") or d.get("transfer", {}).get("status", "?")
        progress = d.get("progress") or d.get("transfer", {}).get("progress", {})
        print(f"  [POLL] status={status} progress={progress}")
        if status in ("completed", "failed", "expired", "refunded"):
            break

    return {"transfer_id": transfer_id, "step_log": mem.step_log}


def _check_null_fields(prepared_txs: dict, transfer_id: int):
    nullable = ["keeperFundingTx", "routeInitTxs", "orchestratorInitTx", "sessionInitTxs"]
    missing = [k for k in nullable if k not in prepared_txs]
    if missing:
        record(Finding(
            title="preparedTxs missing documented fields",
            severity="Medium",
            flow_step="POST /transfers/:id/prepare",
            description=f"Fields {missing} are documented in CLAUDE.md and the agentic guide "
                        f"but absent from the response. An agent doing `prepared_txs['keeperFundingTx']` "
                        f"will raise KeyError rather than safely skipping.",
            expected=f"All of {nullable} present (null when already confirmed)",
            actual=f"Response keys: {list(prepared_txs.keys())}",
            proposed_fix="Return all documented fields in preparedTxs, setting to null when already on-chain.",
        ))


def test_typescript_signing_bug():
    print("\n[TEST] TypeScript tx.sign([kp]) destroys server partial signatures (Documentation blocker)")
    print("  Confirmed from official docs — lines 123-126 of /guides/agentic-integration")
    print("  The documented TypeScript signVersioned uses VersionedTransaction.sign([keypair])")
    print("  web3.js VersionedTransaction.sign() REPLACES the entire signatures array,")
    print("  zeroing all existing server partial signatures on routeInitTxs and sessionInitTxs.")
    print("  Python code in same docs is correct (slot-level replacement). TypeScript is not.")
    record(Finding(
        title="Official TypeScript signing example destroys server partial signatures",
        severity="Documentation blocker",
        flow_step="Client-side signing (TypeScript)",
        description=(
            "The official agentic integration guide (https://dev-docs.multihopper.com/guides/agentic-integration) "
            "provides a TypeScript signVersioned function that calls `tx.sign([keypair])` on a "
            "VersionedTransaction. In @solana/web3.js, `VersionedTransaction.sign([kp])` replaces "
            "the ENTIRE signatures array with default (zero) bytes for all slots not covered by the "
            "provided keypairs, then fills in only the provided keypair's slot. "
            "Since MultiHopper pre-signs routeInitTxs and sessionInitTxs with ephemeral server keypairs, "
            "any TypeScript agent following the documented example will silently zero out those server "
            "signatures. The transaction will deserialize but fail on-chain with a signature verification "
            "error, and the agent will receive no warning at the signing step. "
            "The Python example in the same page is correct (slot-level replacement)."
        ),
        expected="tx.sign([kp]) preserves existing server partial signatures",
        actual="tx.sign([kp]) zeroes all sig slots not covered by the provided keypair",
        proposed_fix=(
            "Replace the documented TypeScript signVersioned with slot-level signature injection: "
            "deserialize → build message bytes → sign manually → find keypair's slot index in "
            "staticAccountKeys → splice only that slot. Alternatively use the serialize/deserialize "
            "round-trip after manual sig injection. Add a Warning callout to the docs matching the "
            "Python Warning already present."
        ),
        confidence="High",
        evidence_level="Documented code path and known web3.js signing behavior; no live funds moved",
        severity_rationale="Documentation blocker because the proof shows integration failure, not unauthorized fund movement.",
    ))


def test_fake_keeper_signature():
    print("\n[TEST] confirm-broadcast accepts fake/unverified keeperFundingSignature")
    s1, d1 = client.create(SOURCE, DEST)
    if s1 not in (200, 201):
        print(f"  SKIP [fake-keeper-sig]: create HTTP {s1}")
        return
    transfer_id = d1.get("id")
    if not transfer_id:
        return

    s2, _ = client.prepare(transfer_id)
    if s2 != 200:
        print(f"  SKIP [fake-keeper-sig]: prepare HTTP {s2}")
        return

    fake_sig = "5" * 87 + "A"
    s3, d3 = client.confirm_broadcast(transfer_id, {
        "routeInitSignatures": [],
        "keeperFundingSignature": fake_sig,
    })

    if s3 in (200, 201):
        record(Finding(
            title="confirm-broadcast accepts fabricated keeperFundingSignature without on-chain validation",
            severity="High",
            flow_step="POST /transfers/:id/confirm-broadcast",
            description=(
                "confirm-broadcast accepted a fabricated 88-character base58 string as "
                "keeperFundingSignature without verifying the signature exists on-chain. "
                "An attacker can advance transfer state to 'processing' without funding the keeper, "
                "causing the keeper to attempt hops with an unfunded vault. "
                "In a production scenario this could trigger keeper losses or corrupt route state."
            ),
            expected="HTTP 400 — signature not found on-chain or invalid format",
            actual=f"HTTP {s3}: {json.dumps(d3)[:300]}",
            proposed_fix=(
                "Validate keeperFundingSignature format (88 chars, base58) and confirm existence "
                "on-chain via getSignatureStatuses before accepting. Return a specific MH error code "
                "for invalid/unconfirmed signatures."
            ),
            confidence="Medium",
            evidence_level="API accepted fabricated signature; no on-chain loss or keeper loss demonstrated",
            severity_rationale="High only if acceptance changes transfer state. Critical would require proof of fund loss or unauthorized execution.",
        ))
    else:
        print(f"  PASS — fake signature rejected (HTTP {s3})")


def test_amount_mismatch():
    print("\n[TEST] amountRaw/amountTokens inconsistency accepted at creation")
    s, d = client.create(
        SOURCE, DEST,
        amount_raw="1000000000",
        amount_tokens="0.0001",
    )
    if s == 0:
        print("  SKIP - API/network request failed")
        return
    if s in (200, 201):
        record(Finding(
            title="Inconsistent amountRaw/amountTokens accepted at creation",
            severity="High",
            flow_step="POST /transfers (validation)",
            description=(
                "A transfer was created with amountRaw=1000000000 (1 SOL at 9 decimals) and "
                "amountTokens=0.0001 — a >10,000x mismatch. The API accepted this without error. "
                "An agent computing fees from amountTokens will vastly underestimate the transfer value. "
                "Fee calculations, recipient receives, and slippage guards that depend on amountTokens "
                "will be silently wrong."
            ),
            expected="HTTP 400 — amountRaw and amountTokens must be consistent for the given tokenDecimals",
            actual=f"HTTP {s}: id={d.get('id')} accepted inconsistent amounts",
            proposed_fix=(
                "Validate: abs(amountRaw - round(float(amountTokens) * 10**tokenDecimals)) < epsilon. "
                "Return a descriptive 400 if they diverge by more than 1 lamport."
            ),
        ))
    else:
        print(f"  PASS — mismatch rejected (HTTP {s})")


def test_self_transfer():
    print("\n[TEST] sourceOwner == recipientWallet accepted")
    s, d = client.create(SOURCE, SOURCE)
    if s == 0:
        print("  SKIP - API/network request failed")
        return
    if s in (200, 201):
        record(Finding(
            title="Self-transfer (sourceOwner == recipientWallet) accepted",
            severity="Medium",
            flow_step="POST /transfers (validation)",
            description=(
                "A transfer was created where sourceOwner and recipientWallet are identical. "
                "The API accepted this. Executing it wastes keeper fees, consumes on-chain rent, "
                "and burns protocol fees with no economic outcome. An agent in a retry loop could "
                "flood the protocol with self-transfers if it reuses wallet addresses by mistake."
            ),
            expected="HTTP 400 — sourceOwner and recipientWallet must differ",
            actual=f"HTTP {s}: id={d.get('id')} self-transfer created",
            proposed_fix="Add a creation-time check: if sourceOwner == recipientWallet, return 400.",
        ))
    else:
        print(f"  PASS — self-transfer rejected (HTTP {s})")


def test_zero_amount():
    print("\n[TEST] amountRaw=0 accepted at creation")
    s, d = client.create(SOURCE, DEST, amount_raw="0", amount_tokens="0")
    if s == 0:
        print("  SKIP - API/network request failed")
        return
    if s in (200, 201):
        record(Finding(
            title="Zero-amount transfer accepted at creation",
            severity="Medium",
            flow_step="POST /transfers (validation)",
            description=(
                "A transfer with amountRaw=0 and amountTokens=0 was accepted. "
                "Zero-value transfers cannot fund keeper accounts or deliver value but consume "
                "API quota, on-chain rent, and keeper execution resources."
            ),
            expected="HTTP 400 — amountRaw must be greater than zero",
            actual=f"HTTP {s}: id={d.get('id')} zero-amount transfer created",
            proposed_fix="Reject amountRaw=0 or amountTokens=0 with a clear 400 error at creation.",
        ))
    else:
        print(f"  PASS — zero amount rejected (HTTP {s})")


def test_invalid_token_mint():
    print("\n[TEST] Invalid tokenMint (non-Solana-pubkey) accepted at creation")
    s, d = client.create(SOURCE, DEST, token_mint="not-a-valid-pubkey-string", overrides={"tokenMint": "not-a-valid-pubkey-string"})
    if s == 0:
        print("  SKIP - API/network request failed")
        return
    if s in (200, 201):
        record(Finding(
            title="Invalid tokenMint format accepted at creation, fails silently later",
            severity="High",
            flow_step="POST /transfers (validation)",
            description=(
                "A transfer was created with tokenMint='not-a-valid-pubkey-string' — not a valid "
                "base58 Solana public key. The API accepted the transfer at creation. "
                "The failure will occur silently at /prepare or on-chain broadcast, far from the "
                "root cause, making debugging extremely difficult for agentic integrators."
            ),
            expected="HTTP 400 at creation — tokenMint must be a valid 32-byte Solana pubkey",
            actual=f"HTTP {s}: id={d.get('id')} invalid tokenMint accepted",
            proposed_fix=(
                "Validate tokenMint is a valid base58-encoded 32-byte pubkey at POST /transfers. "
                "Return 400 immediately with a clear error message."
            ),
        ))
    else:
        print(f"  PASS — invalid tokenMint rejected (HTTP {s})")


def test_concurrent_prepare():
    print("\n[TEST] Concurrent /prepare calls for the same transfer (race condition)")
    s, d = client.create(SOURCE, DEST)
    if s not in (200, 201):
        print(f"  SKIP [concurrent-prepare]: create HTTP {s}")
        return
    transfer_id = d.get("id")
    if not transfer_id:
        return

    results = {}

    def do_prepare(label: str):
        status, data = client.prepare(transfer_id)
        results[label] = {"status": status, "data": data}

    t1 = threading.Thread(target=do_prepare, args=("call_1",))
    t2 = threading.Thread(target=do_prepare, args=("call_2",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    r1 = results.get("call_1", {})
    r2 = results.get("call_2", {})
    s1, d1 = r1.get("status"), r1.get("data", {})
    s2, d2 = r2.get("status"), r2.get("data", {})

    bh1 = (d1.get("preparedTxs") or {}).get("recentBlockhash")
    bh2 = (d2.get("preparedTxs") or {}).get("recentBlockhash")

    if bh1 and bh2 and bh1 != bh2:
        record(Finding(
            title="Concurrent /prepare calls return different blockhashes — agent will broadcast stale txs",
            severity="High",
            flow_step="POST /transfers/:id/prepare (concurrent)",
            description=(
                "Two simultaneous /prepare calls for the same transfer returned different "
                f"recentBlockhashes ('{bh1}' vs '{bh2}'). "
                "An agent that retries /prepare on network failure, without cancelling the first "
                "request, may sign and broadcast two conflicting transaction sets. The first set "
                "lands on-chain; the second set fails with 'Blockhash not found' or produces "
                "double-signed conflicting instructions, potentially locking funds."
            ),
            expected="Concurrent calls return the same blockhash (or one is rejected with 409)",
            actual=f"Different blockhashes returned: {bh1[:20]}... vs {bh2[:20]}...",
            proposed_fix=(
                "Implement prepare-level locking: reject a second concurrent /prepare for the same "
                "transferId with 409. Or cache the prepare result for its blockhash TTL (~60s) "
                "and return the same response."
            ),
        ))
    elif bh1 and bh2 and bh1 == bh2:
        print(f"  PASS — both calls returned same blockhash")
    else:
        print(f"  INFO — one or both prepare calls failed (s1={s1}, s2={s2})")


def test_claude_md_mainnet_url():
    print("\n[TEST] CLAUDE.md context file hardcodes mainnet URL for devnet integrators")
    print("  Confirmed from docs: CLAUDE.md block at /guides/agentic-integration uses")
    print("  REST API: https://multihopper.com/api/v1 — the PRODUCTION endpoint.")
    print("  No devnet equivalent URL is provided.")
    record(Finding(
        title="CLAUDE.md context block hardcodes mainnet API_BASE — agents will hit production",
        severity="High",
        flow_step="Documentation / Agent Context",
        description=(
            "The CLAUDE.md block in the agentic integration guide specifies "
            "`REST API: https://multihopper.com/api/v1` — the live mainnet endpoint. "
            "Developers building test agents following the docs will inadvertently point their "
            "agents at production, potentially spending real SOL on mainnet during development. "
            "No devnet equivalent URL is provided in the context block."
        ),
        expected="CLAUDE.md should use the devnet URL (https://devnet.multihopper.com/api/v1) "
                 "or include a clear placeholder variable",
        actual="REST API: https://multihopper.com/api/v1 (mainnet, hardcoded)",
        proposed_fix=(
            "Replace with: `REST API: {{MH_API_BASE}}/api/v1` and add a line: "
            "`Test environment: https://devnet.multihopper.com/api/v1`. "
            "Add a Warning callout at the top of the CLAUDE.md section."
        ),
    ))
