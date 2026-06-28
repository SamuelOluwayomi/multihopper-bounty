import os
import uuid
import json
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from dotenv import load_dotenv
load_dotenv()

from src.client import MultiHopperClient
from src.signer import load_keypair, sign_all, server_sigs_preserved, AVAILABLE as SIGNING
from src.findings import record, generate_report, Finding
from src.agent import (
    test_typescript_signing_bug,
    test_fake_keeper_signature,
    test_amount_mismatch,
    test_self_transfer,
    test_zero_amount,
    test_invalid_token_mint,
    test_concurrent_prepare,
    test_claude_md_mainnet_url,
)
from src.deep_probes import run_deep_probes

SOURCE  = os.environ.get("SOURCE_WALLET", "")
DEST    = os.environ.get("RECIPIENT_WALLET", "")
client  = MultiHopperClient()


def skip_if_no_transfer(label: str, s: int, d: dict):
    if s not in (200, 201):
        print(f"  SKIP [{label}]: create failed HTTP {s}")
        return True
    return False


def test_missing_idempotency_key():
    print("\n[TEST] Missing Idempotency-Key on POST /transfers")
    s, d = client.raw("POST", "/transfers", body={
        "tokenMint": "So11111111111111111111111111111111111111112",
        "amountRaw": "100000000", "amountTokens": "0.1",
        "tokenDecimals": 9, "sourceOwner": SOURCE,
        "recipientWallet": DEST, "hops": 3, "arrivalSeconds": 300,
        "externalId": f"mh-test-{uuid.uuid4()}",
    })
    if s == 400 and "MH_070" in json.dumps(d):
        print("  PASS")
    else:
        record(Finding(
            title="Missing Idempotency-Key not rejected with MH_070",
            severity="Medium", flow_step="POST /transfers",
            description="POST /transfers accepted a request with no Idempotency-Key header.",
            expected="HTTP 400 + MH_070", actual=f"HTTP {s}: {json.dumps(d)[:200]}",
            proposed_fix="Enforce Idempotency-Key header on all POST mutations; return MH_070 immediately if absent.",
        ))


def test_duplicate_idempotency_key():
    print("\n[TEST] Duplicate Idempotency-Key (same request twice)")
    idem = str(uuid.uuid4())
    s1, d1 = client.create(SOURCE, DEST, idem_key=idem)
    s2, d2 = client.create(SOURCE, DEST, idem_key=idem)
    if s1 == 0 or s2 == 0:
        print(f"  SKIP: API/network request failed (HTTP {s1}, HTTP {s2})")
        return
    if s1 == s2 and d1.get("id") == d2.get("id"):
        print("  PASS — same id returned")
    else:
        record(Finding(
            title="Duplicate Idempotency-Key returns different transfer",
            severity="High", flow_step="POST /transfers (idempotency)",
            description="Two calls with the same Idempotency-Key produced different transfer IDs.",
            expected=f"Same id both times (id={d1.get('id')})",
            actual=f"id1={d1.get('id')} id2={d2.get('id')}",
            proposed_fix="Cache response per Idempotency-Key within its TTL; replay on repeat calls.",
        ))


def test_conflicting_idempotency_key():
    print("\n[TEST] Conflicting Idempotency-Key (same key, different body)")
    idem = str(uuid.uuid4())
    s1, d1 = client.create(SOURCE, DEST, idem_key=idem, hops=3)
    s2, d2 = client.create(SOURCE, DEST, idem_key=idem, overrides={"hops": 5})
    if s1 == 0 or s2 == 0:
        print(f"  SKIP: API/network request failed (HTTP {s1}, HTTP {s2})")
        return
    if s2 == 409 or d1.get("id") == d2.get("id"):
        print("  PASS")
    else:
        record(Finding(
            title="Conflicting Idempotency-Key accepted silently",
            severity="Medium", flow_step="POST /transfers (idempotency conflict)",
            description="Same key + different body was accepted and may have created a second transfer.",
            expected="HTTP 409 or original cached response",
            actual=f"HTTP {s2}: id={d2.get('id')} (original={d1.get('id')})",
            proposed_fix="Return 409 on conflict, or replay original. Document this behavior for agent implementors.",
        ))


def test_hops_out_of_range():
    print("\n[TEST] Out-of-range hops (2, 11, 0)")
    for hops, label in [(2, "below min"), (11, "above max"), (0, "zero")]:
        s, d = client.create(SOURCE, DEST, overrides={"hops": hops})
        if s == 400 and "MH_013" in json.dumps(d):
            print(f"  PASS hops={hops} ({label})")
        else:
            record(Finding(
                title=f"hops={hops} ({label}) not rejected with MH_013",
                severity="Low", flow_step="POST /transfers (validation)",
                description=f"hops={hops} outside valid range 3–10 was not rejected.",
                expected="HTTP 400 + MH_013", actual=f"HTTP {s}: {json.dumps(d)[:150]}",
                proposed_fix="Validate hops in [3,10] at creation time; return MH_013 with clear message.",
            ))


def test_duplicate_external_id():
    print("\n[TEST] Duplicate externalId")
    ext = f"mh-test-extid-{uuid.uuid4()}"
    s1, d1 = client.create(SOURCE, DEST, overrides={"externalId": ext})
    s2, d2 = client.create(SOURCE, DEST, overrides={"externalId": ext})
    if s2 == 409 and "MH_033" in json.dumps(d2):
        print("  PASS")
    else:
        record(Finding(
            title="Duplicate externalId not rejected with MH_033",
            severity="Medium", flow_step="POST /transfers",
            description="Two transfers with the same externalId were both accepted.",
            expected="HTTP 409 + MH_033 on second call",
            actual=f"HTTP {s2}: {json.dumps(d2)[:150]}",
            proposed_fix="Enforce per-key externalId uniqueness; return MH_033 on duplicate.",
        ))


def test_prepare_unknown_id():
    print("\n[TEST] Prepare on non-existent transfer ID")
    s, d = client.prepare(999999999)
    if s == 404:
        print("  PASS")
    else:
        record(Finding(
            title="Prepare on unknown ID does not return 404",
            severity="Low", flow_step="POST /transfers/:id/prepare",
            description="Calling /prepare on a fake transfer ID returned an unexpected status.",
            expected="HTTP 404", actual=f"HTTP {s}: {json.dumps(d)[:150]}",
            proposed_fix="Return 404 with a descriptive error for unknown transfer IDs.",
        ))


def test_confirm_broadcast_missing_keeper_sig():
    print("\n[TEST] confirm-broadcast missing keeperFundingSignature")
    s1, d1 = client.create(SOURCE, DEST)
    if skip_if_no_transfer("confirm-missing-keeper", s1, d1): return
    transfer_id = d1["id"]

    s2, d2 = client.prepare(transfer_id)
    if s2 != 200:
        print(f"  SKIP: prepare failed HTTP {s2}")
        return

    has_keeper = d2.get("preparedTxs", {}).get("keeperFundingTx") is not None
    s3, d3 = client.confirm_broadcast(transfer_id, {"routeInitSignatures": []})
    if has_keeper:
        if s3 == 400 and "MH_039" in json.dumps(d3):
            print("  PASS — MH_039 returned")
        else:
            record(Finding(
                title="Missing keeperFundingSignature not rejected (MH_039)",
                severity="High", flow_step="POST /transfers/:id/confirm-broadcast",
                description="confirm-broadcast without keeperFundingSignature was accepted despite keeperFundingTx being issued.",
                expected="HTTP 400 + MH_039", actual=f"HTTP {s3}: {json.dumps(d3)[:200]}",
                proposed_fix="Guard confirm-broadcast: if keeperFundingTx was issued and not recorded, require keeperFundingSignature.",
            ))
    else:
        print("  INFO: no keeperFundingTx in preparedTxs (pre-funded route), test N/A")


def test_confirm_before_prepare():
    print("\n[TEST] confirm-broadcast before prepare")
    s1, d1 = client.create(SOURCE, DEST)
    if skip_if_no_transfer("confirm-before-prepare", s1, d1): return
    s2, d2 = client.confirm_broadcast(d1["id"], {"routeInitSignatures": ["fakeSig"], "keeperFundingSignature": "fakeSig"})
    if s2 in (400, 409, 422):
        print(f"  PASS — HTTP {s2}")
    else:
        record(Finding(
            title="confirm-broadcast accepted before /prepare was called",
            severity="Medium", flow_step="POST /transfers/:id/confirm-broadcast",
            description="Submitting fake signatures before /prepare was called was not rejected.",
            expected="HTTP 400/409/422", actual=f"HTTP {s2}: {json.dumps(d2)[:200]}",
            proposed_fix="Require transfer to be in a prepared state before accepting confirm-broadcast.",
        ))


def test_double_prepare_same_key():
    print("\n[TEST] Double /prepare with same Idempotency-Key")
    s1, d1 = client.create(SOURCE, DEST)
    if skip_if_no_transfer("double-prepare", s1, d1): return
    idem = str(uuid.uuid4())
    sp1, dp1 = client.prepare(d1["id"], idem_key=idem)
    sp2, dp2 = client.prepare(d1["id"], idem_key=idem)
    if sp1 == sp2 == 200 and dp1.get("preparedTxs") == dp2.get("preparedTxs"):
        print("  PASS — identical preparedTxs")
    else:
        record(Finding(
            title="Double /prepare same key returns different preparedTxs",
            severity="High", flow_step="POST /transfers/:id/prepare (idempotency)",
            description="Two /prepare calls with the same Idempotency-Key returned different transaction bundles.",
            expected="Identical cached preparedTxs", actual=f"HTTP {sp1} vs {sp2}",
            proposed_fix="Cache /prepare response per Idempotency-Key; return cached payload on repeat within blockhash TTL.",
        ))


def test_arrival_seconds_too_low():
    print("\n[TEST] arrivalSeconds=1 with hops=10")
    s, d = client.create(SOURCE, DEST, overrides={"hops": 10, "arrivalSeconds": 1})
    if s == 400 and "MH_014" in json.dumps(d):
        print("  PASS")
    else:
        record(Finding(
            title="arrivalSeconds=1/hops=10 not rejected with MH_014",
            severity="Low", flow_step="POST /transfers (validation)",
            description="arrivalSeconds=1 with hops=10 should violate minimum arrival time per the docs (MH_014).",
            expected="HTTP 400 + MH_014", actual=f"HTTP {s}: {json.dumps(d)[:150]}",
            proposed_fix="Document minimum arrivalSeconds per hop count table. Return MH_014 with the actual minimum in the error body.",
        ))


def test_estimate_screening_fee_gap():
    print("\n[TEST] /estimate — screening fee presence")
    s, d = client.estimate("So11111111111111111111111111111111111111112", "1000000000", 9, 7)
    if s != 200:
        print(f"  SKIP: estimate HTTP {s}")
        return
    raw = json.dumps(d)
    if "screen" in raw.lower() or "compliance" in raw.lower():
        print("  PASS — screening fee mentioned")
    else:
        record(Finding(
            title="/estimate omits screening fee — agents will under-fund wallets",
            severity="Documentation", flow_step="POST /transfers/estimate",
            description="/estimate does not include the compliance screening fee (0.002 SOL mainnet). "
                        "Agents that use /estimate to pre-fund wallets will fail at /prepare with insufficient lamports.",
            expected="screeningFeeEstimateLamports field or explicit note in response",
            actual=f"Response keys: {list(d.keys())} — no screening fee",
            proposed_fix="Add screeningFeeEstimateLamports to /estimate response (0 on devnet). "
                         "Add a prominent callout in the API reference docs.",
        ))


def test_invalid_wallet():
    print("\n[TEST] Invalid sourceOwner wallet format")
    s, d = client.create("not-a-valid-pubkey", DEST)
    if s == 400:
        print("  PASS")
    else:
        record(Finding(
            title="Invalid wallet address accepted at creation",
            severity="Medium", flow_step="POST /transfers (validation)",
            description="sourceOwner='not-a-valid-pubkey' was not rejected at creation time. "
                        "Agents will hit a cryptic on-chain error at broadcast instead.",
            expected="HTTP 400 with wallet validation error",
            actual=f"HTTP {s}: {json.dumps(d)[:150]}",
            proposed_fix="Validate base58 Solana pubkey format at POST /transfers time.",
        ))


def test_signing_preserves_server_sigs():
    print("\n[TEST] Signing preserves server partial signatures")
    if not SIGNING:
        print("  SKIP: solders/base58 not installed")
        return
    keypair = load_keypair()
    if not keypair:
        print("  SKIP: SOLANA_PRIVATE_KEY not set")
        return

    s1, d1 = client.create(str(keypair.pubkey()), DEST)
    if skip_if_no_transfer("signing", s1, d1): return

    sp, dp = client.prepare(d1["id"])
    if sp != 200:
        print(f"  SKIP: prepare HTTP {sp}")
        return

    prepared = dp.get("preparedTxs", {})
    try:
        signed = sign_all(prepared, keypair)
        if prepared.get("keeperFundingTx") and signed.get("keeperFundingTx"):
            ok = server_sigs_preserved(prepared["keeperFundingTx"], signed["keeperFundingTx"])
            if ok:
                print("  PASS — server signatures preserved")
            else:
                record(Finding(
                    title="Server partial signature overwritten during client signing",
                    severity="Documentation blocker", flow_step="Client signing (VersionedTransaction)",
                    description="sign_versioned overwrote a server pre-signed ephemeral slot. "
                                "This will cause broadcast failure for any route using server partial sigs.",
                    expected="Server sigs in their original slots after client signing",
                    actual="Server sig slot overwritten",
                    proposed_fix="Only replace your pubkey's slot index. Never call tx.sign() (replaces all). "
                                 "Warn about this in the TypeScript signing example — web3.js tx.sign([kp]) "
                                 "DOES overwrite all slots.",
                    confidence="High",
                    evidence_level="Local signing helper corrupted partial signatures; no on-chain fund loss proven",
                    severity_rationale="Documentation/integration blocker rather than Critical until tied to live failed execution or fund impact.",
                ))
        else:
            print("  INFO: no keeperFundingTx to verify sig preservation")
    except Exception as e:
        record(Finding(
            title="sign_all() raises exception on real preparedTxs",
            severity="High", flow_step="Client signing",
            description=f"The signing helpers from the agentic guide failed on real /prepare output.",
            expected="Successful signing", actual=f"Exception: {e}",
            proposed_fix="Test signing helpers against real /prepare responses before publishing docs.",
        ))


def test_status_polling():
    print("\n[TEST] Status polling — GET /transfers/:id")
    import json as _json

    s, d = client.get(999999999)
    if s == 404:
        print("  PASS — 404 for unknown transfer")
        raw = _json.dumps(d).lower()
        has_code = "code" in d or "error" in d or "message" in d or "mh_" in raw
        if not has_code:
            record(Finding(
                title="GET /transfers/:id 404 missing machine-readable error code",
                severity="Documentation",
                flow_step="GET /transfers/:id",
                description="404 response for unknown transfer has no structured error code. "
                            "Agents must distinguish 'not found' from auth failures.",
                expected='{"code": "MH_XXX", "message": "..."}',
                actual=_json.dumps(d)[:200],
                proposed_fix="Return {code, message} in all error responses. Add MH_XXX codes "
                             "for not-found and auth failures in the API reference.",
            ))
    else:
        record(Finding(
            title="GET /transfers/:id with unknown ID does not return 404",
            severity="Low",
            flow_step="GET /transfers/:id",
            description=f"Expected 404 for a non-existent transfer ID 999999999.",
            expected="HTTP 404",
            actual=f"HTTP {s}: {_json.dumps(d)[:200]}",
            proposed_fix="Return 404 with a descriptive error for unknown transfer IDs.",
        ))

    if not SOURCE or not DEST:
        print("  SKIP: SOURCE_WALLET or RECIPIENT_WALLET not set")
        return

    s1, d1 = client.create(SOURCE, DEST)
    if s1 not in (200, 201):
        print(f"  SKIP: create failed HTTP {s1}")
        return

    transfer_id = d1.get("id")
    if not transfer_id:
        print("  SKIP: no id in create response")
        return
    s2, d2 = client.get(transfer_id)
    if s2 != 200:
        record(Finding(
            title="GET /transfers/:id fails on freshly created transfer",
            severity="High",
            flow_step="GET /transfers/:id",
            description=f"GET /transfers/{transfer_id} returned HTTP {s2} immediately after creation.",
            expected="HTTP 200 with status=awaiting_signature",
            actual=f"HTTP {s2}: {_json.dumps(d2)[:200]}",
            proposed_fix="Ensure newly created transfers are immediately queryable.",
        ))
        return

    print(f"  GET /transfers/{transfer_id} → HTTP {s2}")

    valid_statuses = {"quote", "awaiting_signature", "processing", "completed", "failed", "expired", "refunded"}
    status = d2.get("status")
    if status is None:
        record(Finding(
            title="GET /transfers/:id response missing 'status' field",
            severity="Medium",
            flow_step="GET /transfers/:id",
            description="The 'status' field is absent from the GET response. Agents rely on it to drive decisions.",
            expected="status in {quote, awaiting_signature, processing, completed, failed, expired, refunded}",
            actual=f"Response keys: {list(d2.keys())}",
            proposed_fix="Always include 'status' in the GET /transfers/:id response.",
        ))
    elif status not in valid_statuses:
        record(Finding(
            title=f"GET /transfers/:id returned undocumented status '{status}'",
            severity="Medium",
            flow_step="GET /transfers/:id",
            description=f"Status '{status}' is not in the documented enum. Agents will mishandle undocumented status values.",
            expected=f"One of: {valid_statuses}",
            actual=f"status='{status}'",
            proposed_fix="Document all possible status values in the API reference. Return only documented values.",
        ))
    else:
        print(f"  PASS — status='{status}'")

    if "progress" not in d2 and "phase" not in d2:
        record(Finding(
            title="GET /transfers/:id missing 'progress' object",
            severity="Low",
            flow_step="GET /transfers/:id",
            description="The 'progress' field (hopsCompleted, hopsTotal) is absent. "
                        "CLAUDE.md documents: progress: {hopsCompleted, hopsTotal}. "
                        "Agents need this for meaningful status reporting.",
            expected="progress: {hopsCompleted: N, hopsTotal: N}",
            actual=f"Response keys: {list(d2.keys())}",
            proposed_fix="Add 'progress' object to all GET /transfers/:id responses "
                         "(null before processing begins is acceptable).",
        ))
    else:
        print(f"  PASS — progress/phase field present")


def main():
    print("MultiHopper Agentic Flow Test Harness")
    print(f"  API Base:   {client.base}")
    print(f"  Key set:    {'yes' if client.key else 'NO'}")
    print(f"  Signing:    {'available' if SIGNING else 'unavailable'}")

    if not client.key:
        print("\nERROR: MH_API_KEY not set. Copy .env.example to .env and fill in your key.")
        return
    if not SOURCE or not DEST:
        print("\nERROR: SOURCE_WALLET or RECIPIENT_WALLET not set in .env")
        return

    test_typescript_signing_bug()
    test_claude_md_mainnet_url()

    test_missing_idempotency_key()
    test_duplicate_idempotency_key()
    test_conflicting_idempotency_key()
    test_hops_out_of_range()
    test_duplicate_external_id()
    test_prepare_unknown_id()
    test_confirm_broadcast_missing_keeper_sig()
    test_confirm_before_prepare()
    test_double_prepare_same_key()
    test_arrival_seconds_too_low()
    test_estimate_screening_fee_gap()
    test_invalid_wallet()
    test_status_polling()
    test_signing_preserves_server_sigs()

    test_fake_keeper_signature()
    test_amount_mismatch()
    test_self_transfer()
    test_zero_amount()
    test_invalid_token_mint()
    test_concurrent_prepare()
    run_deep_probes()

    generate_report("reports/mh_bug_report.md")

    if os.environ.get("MH_SKIP_AI") == "1":
        print("\n[AI] Skipping AI enrichment/red-team because MH_SKIP_AI=1")
        return

    from src.ai_enricher import enrich_report
    enrich_report()

    from src.ai_red_team import run_ai_red_team
    run_ai_red_team()


if __name__ == "__main__":
    main()
