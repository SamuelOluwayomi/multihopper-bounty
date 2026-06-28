import json
import os
import threading
import time
import uuid

from src.client import MultiHopperClient, SOL_MINT
from src.findings import Finding, record
from src.signer import AVAILABLE as SIGNING
from src.signer import load_keypair, sign_all


SOURCE = os.environ.get("SOURCE_WALLET", "")
DEST = os.environ.get("RECIPIENT_WALLET", "")
ENABLE_BROADCAST_PROBES = os.environ.get("MH_ENABLE_BROADCAST_PROBES") == "1"
ENABLE_SLOW_PROBES = os.environ.get("MH_ENABLE_SLOW_PROBES") == "1"

client = MultiHopperClient()


def _base_create_body(external_id: str | None = None, **overrides) -> dict:
    body = {
        "tokenMint": SOL_MINT,
        "amountRaw": "100000000",
        "amountTokens": "0.1",
        "tokenDecimals": 9,
        "tokenSymbol": "SOL",
        "sourceOwner": SOURCE,
        "recipientWallet": DEST,
        "hops": 3,
        "arrivalSeconds": 300,
        "externalId": external_id or f"mh-deep-{uuid.uuid4()}",
    }
    body.update(overrides)
    return body


def _has_code(data: dict, code: str) -> bool:
    return code in json.dumps(data)


def _valid_sig(label: str) -> str:
    # Syntactically valid-looking base58, intentionally not a real transaction signature.
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    seed = (label + alphabet) * 4
    return seed[:88]


def _transfer_id_from_create(data: dict, label: str) -> int | None:
    transfer_id = data.get("id")
    if isinstance(transfer_id, int):
        return transfer_id
    print(f"  SKIP: {label} create response missing integer id")
    return None


def test_idempotency_conflict_returns_mh071():
    print("\n[DEEP] Idempotency conflict should return MH_071")
    idem = str(uuid.uuid4())
    ext = f"mh-idem-conflict-{uuid.uuid4()}"
    first = _base_create_body(ext, hops=3)
    second = _base_create_body(ext, hops=5)

    s1, d1 = client.raw("POST", "/transfers", body=first, idem_key=idem)
    s2, d2 = client.raw("POST", "/transfers", body=second, idem_key=idem)

    if s1 not in (200, 201):
        print(f"  SKIP: first create failed HTTP {s1}")
        return

    if s2 == 409 and _has_code(d2, "MH_071"):
        print("  PASS - conflicting retry rejected with MH_071")
        return

    if d1.get("id") == d2.get("id") and d2.get("hops") == d1.get("hops"):
        print("  PASS - original response replayed")
        return

    severity = "High" if s2 in (200, 201) and d1.get("id") != d2.get("id") else "Medium"
    record(Finding(
        title="Conflicting Idempotency-Key is not rejected with documented MH_071",
        severity=severity,
        flow_step="POST /transfers (idempotency conflict)",
        description=(
            "The API documentation says reusing an Idempotency-Key with a different request body "
            "returns MH_071. Agents rely on this to distinguish a safe retry from a conflicting "
            "mutation after a crash or network timeout."
        ),
        request_payload={"first": first, "second": second, "idempotencyKey": "<same UUID>"},
        expected="HTTP 409 with MH_071, or exact replay of the original response",
        actual=f"first HTTP {s1}, second HTTP {s2}: {json.dumps(d2)[:300]}",
        proposed_fix=(
            "Persist a canonical request hash per Idempotency-Key. On reuse with a different "
            "hash, return 409/MH_071 and do not execute the mutation."
        ),
    ))


def test_concurrent_same_idempotency_key_is_locked_or_replayed():
    print("\n[DEEP] Concurrent same Idempotency-Key should lock or replay")
    idem = str(uuid.uuid4())
    body = _base_create_body(f"mh-concurrent-idem-{uuid.uuid4()}")
    results: dict[str, tuple[int, dict]] = {}

    def post(label: str):
        results[label] = client.raw("POST", "/transfers", body=body, idem_key=idem)

    t1 = threading.Thread(target=post, args=("a",))
    t2 = threading.Thread(target=post, args=("b",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    s1, d1 = results["a"]
    s2, d2 = results["b"]
    if s1 == 0 or s2 == 0:
        print(f"  SKIP: network/API request failed (HTTP {s1}, HTTP {s2})")
        return

    ids = {d1.get("id"), d2.get("id")} - {None}
    has_in_progress = (s1 == 409 and _has_code(d1, "MH_072")) or (s2 == 409 and _has_code(d2, "MH_072"))

    if len(ids) <= 1 and (has_in_progress or s1 == s2):
        print("  PASS - concurrent duplicate locked or replayed")
        return

    record(Finding(
        title="Concurrent duplicate Idempotency-Key can race into inconsistent create results",
        severity="High",
        flow_step="POST /transfers (concurrent idempotency)",
        description=(
            "Two simultaneous create requests used the same Idempotency-Key and same body. "
            "The docs define MH_072 for an in-progress idempotent request. If the API returns "
            "two different transfer IDs or two divergent responses, an agent retry can create "
            "duplicate routes while believing it performed a safe retry."
        ),
        request_payload={"body": body, "idempotencyKey": "<same UUID used concurrently>"},
        expected="One successful response plus MH_072, or identical replayed response",
        actual=f"a=HTTP {s1} id={d1.get('id')}; b=HTTP {s2} id={d2.get('id')}",
        proposed_fix=(
            "Acquire an idempotency lock before executing the mutation. Return 409/MH_072 while "
            "the first request is in progress, then replay the stored response after completion."
        ),
    ))


def test_idempotency_key_validation_is_strict():
    print("\n[DEEP] Idempotency-Key format validation")
    bad_keys = {
        "too_short": "abc",
        "too_long": "x" * 65,
        "bad_chars": "valid-length-but-bad-char-!",
    }
    body = _base_create_body()

    for label, key in bad_keys.items():
        s, d = client.raw("POST", "/transfers", body=body | {"externalId": f"mh-bad-idem-{label}-{uuid.uuid4()}"}, idem_key=key)
        if s == 400 and _has_code(d, "MH_070"):
            print(f"  PASS {label}")
            continue
        record(Finding(
            title=f"Invalid Idempotency-Key format not rejected ({label})",
            severity="Medium",
            flow_step="POST /transfers (idempotency validation)",
            description=(
                "The API documentation requires Idempotency-Key to be 8-64 characters and "
                "limited to [a-zA-Z0-9._-]. Accepting malformed keys makes agent retry "
                "behavior non-portable across clients and SDKs."
            ),
            expected="HTTP 400 with MH_070",
            actual=f"HTTP {s}: {json.dumps(d)[:250]}",
            proposed_fix="Validate Idempotency-Key before reading or executing the request body.",
        ))


def test_confirm_rejects_route_signatures_before_keeper_funding():
    print("\n[DEEP] confirm-broadcast should not accept route signatures before keeper funding")
    s1, d1 = client.create(SOURCE, DEST)
    if s1 not in (200, 201):
        print(f"  SKIP: create failed HTTP {s1}")
        return
    transfer_id = _transfer_id_from_create(d1, "route-before-keeper")
    if transfer_id is None:
        return
    s2, d2 = client.prepare(transfer_id) 
    if s2 != 200:
        print(f"  SKIP: prepare failed HTTP {s2}")
        return

    prepared = d2.get("preparedTxs") or {}
    route_count = len(prepared.get("routeInitTxs") or [])
    if not prepared.get("keeperFundingTx") or route_count == 0:
        print("  SKIP: no keeperFundingTx or routeInitTxs to test ordering")
        return

    body = {"routeInitSignatures": [_valid_sig("route") for _ in range(route_count)]}
    s3, d3 = client.confirm_broadcast(transfer_id, body)

    if s3 not in (200, 201):
        print(f"  PASS - rejected before keeper funding (HTTP {s3})")
        return

    record(Finding(
        title="confirm-broadcast accepts route signatures before keeper funding is recorded",
        severity="High",
        flow_step="POST /transfers/:id/confirm-broadcast (broadcast ordering)",
        description=(
            "The agentic flow requires keeperFundingTx to be broadcast and recorded before any "
            "route initialization signatures. Accepting route signatures first breaks the documented "
            "state machine and can leave agents unable to resume safely after an interruption."
        ),
        request_payload=body,
        expected="HTTP 400/409 with MH_039 or MH_035; transfer remains awaiting_signature",
        actual=f"HTTP {s3}: {json.dumps(d3)[:300]}",
        proposed_fix=(
            "Gate route/orchestrator/session signature recording on keeper funding being either "
            "confirmed on chain or explicitly recorded for this transfer."
        ),
    ))


def test_confirm_rejects_wrong_signature_cardinality():
    print("\n[DEEP] confirm-broadcast should reject wrong signature counts")
    s1, d1 = client.create(SOURCE, DEST)
    if s1 not in (200, 201):
        print(f"  SKIP: create failed HTTP {s1}")
        return
    transfer_id = _transfer_id_from_create(d1, "wrong-cardinality")
    if transfer_id is None:
        return
    s2, d2 = client.prepare(transfer_id)
    if s2 != 200:
        print(f"  SKIP: prepare failed HTTP {s2}")
        return

    prepared = d2.get("preparedTxs") or {}
    route_count = len(prepared.get("routeInitTxs") or [])
    session_count = len(prepared.get("sessionInitTxs") or [])
    if route_count == 0 and session_count == 0:
        print("  SKIP: no route/session txs to test cardinality")
        return

    body = {
        "keeperFundingSignature": _valid_sig("keeper"),
        "routeInitSignatures": [_valid_sig("route")] * (route_count + 1),
        "sessionInitSignatures": [_valid_sig("session")] * max(session_count - 1, 0),
    }
    s3, d3 = client.confirm_broadcast(transfer_id, body)

    if s3 not in (200, 201):
        print(f"  PASS - wrong cardinality rejected (HTTP {s3})")
        return

    record(Finding(
        title="confirm-broadcast accepts signature arrays with wrong cardinality",
        severity="High",
        flow_step="POST /transfers/:id/confirm-broadcast (signature binding)",
        description=(
            "confirm-broadcast accepted a body where route/session signature counts did not match "
            "the prepared transaction bundle. This means the API may be trusting client-supplied "
            "signatures without binding them to the exact prepared transaction list."
        ),
        confidence="Medium",
        evidence_level="API accepted malformed confirmation body; no on-chain fund movement proven",
        request_payload=body,
        expected="HTTP 400/422; one signature per prepared transaction, in exact order",
        actual=f"HTTP {s3}: {json.dumps(d3)[:300]}",
        proposed_fix=(
            "Store the prepared bundle fingerprint and enforce exact signature cardinality and order. "
            "For each signature, fetch the chain transaction and verify it matches the corresponding "
            "prepared message and invokes the MultiHopper program."
        ),
    ))


def test_prepare_after_blockhash_expiry_returns_fresh_bundle():
    print("\n[DEEP] Prepare after blockhash expiry should return a fresh bundle")
    if not ENABLE_SLOW_PROBES:
        print("  SKIP: set MH_ENABLE_SLOW_PROBES=1 to run 75s expiry probe")
        return

    s1, d1 = client.create(SOURCE, DEST)
    if s1 not in (200, 201):
        print(f"  SKIP: create failed HTTP {s1}")
        return
    transfer_id = _transfer_id_from_create(d1, "expiry")
    if transfer_id is None:
        return
    s2, d2 = client.prepare(transfer_id)
    if s2 != 200:
        print(f"  SKIP: prepare failed HTTP {s2}")
        return
    first = (d2.get("preparedTxs") or {}).get("recentBlockhash")
    time.sleep(75)
    s3, d3 = client.prepare(transfer_id, idem_key=str(uuid.uuid4()))
    second = (d3.get("preparedTxs") or {}).get("recentBlockhash")

    if s3 == 200 and second and second != first:
        print("  PASS - fresh blockhash returned after expiry")
        return

    record(Finding(
        title="/prepare after blockhash expiry does not return a fresh usable bundle",
        severity="High",
        flow_step="POST /transfers/:id/prepare (expiry/resume)",
        description=(
            "Agents are instructed to call /prepare again after blockhash expiry. If the API returns "
            "the stale bundle or an ambiguous error, the agent cannot safely resume a partially "
            "broadcast route."
        ),
        expected="HTTP 200 with a new recentBlockhash, or a structured terminal error",
        actual=f"first={first}; second HTTP {s3}, blockhash={second}, body={json.dumps(d3)[:250]}",
        proposed_fix=(
            "Treat /prepare responses as blockhash-TTL scoped. After expiry, rebuild the bundle with "
            "a fresh blockhash and null out already-confirmed transaction groups."
        ),
    ))


def test_docs_python_snippet_is_syntax_valid():
    print("\n[DEEP] Python docs snippet contains invalid v0 prefix literal")
    record(Finding(
        title="Agentic Python signing example contains invalid syntax: bytes([0x 80])",
        severity="Documentation",
        flow_step="Documentation / Python signing",
        description=(
            "The Python signing snippet in the agentic guide shows `bytes([0x 80])`, which is not "
            "valid Python syntax. An agent that copies the snippet directly will fail before it can "
            "sign any prepared transactions."
        ),
        expected="bytes([0x80]) + bytes(tx.message)",
        actual="bytes([0x 80]) + bytes(tx.message)",
        proposed_fix="Remove the space in the hex literal and add a tiny syntax-checked example test in docs CI.",
        confidence="High",
        evidence_level="Documentation snippet syntax defect",
    ))


def test_docs_webhook_security_gaps():
    print("\n[DEEP] Webhook docs should include replay protection and Idempotency-Key consistency")
    record(Finding(
        title="Webhook verification docs omit timestamp/replay protection and conflict with POST idempotency rule",
        severity="Documentation",
        flow_step="Documentation / Webhooks",
        description=(
            "The webhook verification example validates only HMAC(payload), with no timestamp, "
            "delivery ID, tolerance window, or replay cache. The register-webhook example also omits "
            "Idempotency-Key even though the API introduction says all POST mutations require it. "
            "Agentic workflows that trigger on webhooks can process replayed transfer.completed or "
            "transfer.failed events as fresh state changes."
        ),
        expected="Signed timestamp + event ID replay cache; webhook POST examples include Idempotency-Key or document exception",
        actual="HMAC over payload only; no timestamp/replay guidance; POST /webhooks example has no Idempotency-Key",
        proposed_fix=(
            "Sign `timestamp.payload`, include `x-multihopper-timestamp` and a stable event ID, "
            "reject events outside a 5 minute window, and document replay-cache handling. Clarify "
            "whether POST /webhooks is exempt from Idempotency-Key; otherwise add the header."
        ),
        confidence="Medium",
        evidence_level="Documentation/design gap; no live webhook replay exploit demonstrated",
    ))


def run_deep_probes():
    test_idempotency_conflict_returns_mh071()
    test_concurrent_same_idempotency_key_is_locked_or_replayed()
    test_idempotency_key_validation_is_strict()
    test_confirm_rejects_route_signatures_before_keeper_funding()
    test_confirm_rejects_wrong_signature_cardinality()
    test_prepare_after_blockhash_expiry_returns_fresh_bundle()
    test_docs_python_snippet_is_syntax_valid()
    test_docs_webhook_security_gaps()

    if ENABLE_BROADCAST_PROBES and SIGNING and load_keypair():
        print("\n[DEEP] Broadcast-enabled probes are configured, but destructive cross-transfer probes are intentionally manual.")
        print("  Build a separate one-off PoC before spending devnet SOL or submitting on-chain signatures.")
