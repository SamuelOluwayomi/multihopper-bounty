import json
import os
import threading
import time
import uuid
from typing import Any

from src.client import MultiHopperClient


SOURCE = os.environ.get("SOURCE_WALLET", "")
DEST = os.environ.get("RECIPIENT_WALLET", "")

client = MultiHopperClient() 


def _sig(label: str) -> str:
    alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    return ((label + alphabet) * 5)[:88]


def _create_transfer(**overrides) -> tuple[int, dict]:
    return client.create(
        SOURCE,
        DEST,
        external_id=f"oracle-{uuid.uuid4()}",
        overrides=overrides or None,
    )


def _status_snapshot(transfer_id: int) -> dict:
    status, data = client.get(transfer_id)
    return {"http": status, "body": data}


def _prepared_counts(prepared: dict) -> dict:
    txs = prepared.get("preparedTxs") or {}
    return {
        "hasKeeperFundingTx": bool(txs.get("keeperFundingTx")),
        "routeInitCount": len(txs.get("routeInitTxs") or []),
        "hasOrchestratorInitTx": bool(txs.get("orchestratorInitTx")),
        "sessionInitCount": len(txs.get("sessionInitTxs") or []),
        "keys": list(txs.keys()),
        "recentBlockhash": txs.get("recentBlockhash"),
        "lastValidBlockHeight": txs.get("lastValidBlockHeight"),
    }


def scenario_idempotency_conflict_mh071(args: dict[str, Any] | None = None) -> dict:
    idem = str(uuid.uuid4())
    external_id = f"oracle-idem-conflict-{uuid.uuid4()}"
    body_a = {
        "tokenMint": "So11111111111111111111111111111111111111112",
        "amountRaw": "100000000",
        "amountTokens": "0.1",
        "tokenDecimals": 9,
        "tokenSymbol": "SOL",
        "sourceOwner": SOURCE,
        "recipientWallet": DEST,
        "hops": 3,
        "arrivalSeconds": 300,
        "externalId": external_id,
    }
    body_b = body_a | {"hops": 5}
    s1, d1 = client.raw("POST", "/transfers", body=body_a, idem_key=idem)
    s2, d2 = client.raw("POST", "/transfers", body=body_b, idem_key=idem)
    return {
        "scenario": "idempotency_conflict_mh071",
        "expected": "Second request returns 409/MH_071 or exact original response replay",
        "first": {"http": s1, "id": d1.get("id"), "body": d1},
        "second": {"http": s2, "id": d2.get("id"), "body": d2},
    }


def scenario_concurrent_same_key(args: dict[str, Any] | None = None) -> dict:
    idem = str(uuid.uuid4())
    body = {
        "tokenMint": "So11111111111111111111111111111111111111112",
        "amountRaw": "100000000",
        "amountTokens": "0.1",
        "tokenDecimals": 9,
        "tokenSymbol": "SOL",
        "sourceOwner": SOURCE,
        "recipientWallet": DEST,
        "hops": 3,
        "arrivalSeconds": 300,
        "externalId": f"oracle-concurrent-{uuid.uuid4()}",
    }
    results: dict[str, tuple[int, dict]] = {}

    def post(label: str):
        results[label] = client.raw("POST", "/transfers", body=body, idem_key=idem)

    t1 = threading.Thread(target=post, args=("a",))
    t2 = threading.Thread(target=post, args=("b",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    s1, d1 = results.get("a", (0, {}))
    s2, d2 = results.get("b", (0, {}))
    return {
        "scenario": "concurrent_same_key",
        "expected": "One success plus 409/MH_072, or identical replayed response",
        "a": {"http": s1, "id": d1.get("id"), "body": d1},
        "b": {"http": s2, "id": d2.get("id"), "body": d2},
    }


def scenario_confirm_wrong_cardinality(args: dict[str, Any] | None = None) -> dict:
    s1, d1 = _create_transfer()
    if s1 not in (200, 201):
        return {"scenario": "confirm_wrong_cardinality", "skipped": True, "create": {"http": s1, "body": d1}}
    transfer_id = d1.get("id")
    if not isinstance(transfer_id, int):
        return {"scenario": "confirm_wrong_cardinality", "error": "id is not integer", "create": d1}
    s2, d2 = client.prepare(transfer_id)
    if s2 != 200:
        return {"scenario": "confirm_wrong_cardinality", "skipped": True, "create": d1, "prepare": {"http": s2, "body": d2}}

    counts = _prepared_counts(d2)
    route_count = counts["routeInitCount"]
    session_count = counts["sessionInitCount"]
    body = {
        "keeperFundingSignature": _sig("keeper"),
        "routeInitSignatures": [_sig("route")] * (route_count + 1),
        "sessionInitSignatures": [_sig("session")] * max(session_count - 1, 0),
    }
    before = _status_snapshot(transfer_id)
    s3, d3 = client.confirm_broadcast(transfer_id, body)
    after = _status_snapshot(transfer_id)
    return {
        "scenario": "confirm_wrong_cardinality",
        "expected": "HTTP 400/422 and transfer status unchanged",
        "transferId": transfer_id,
        "preparedCounts": counts,
        "before": before,
        "confirm": {"http": s3, "body": d3, "request": body},
        "after": after,
    }


def scenario_confirm_route_before_keeper(args: dict[str, Any] | None = None) -> dict:
    s1, d1 = _create_transfer()
    if s1 not in (200, 201):
        return {"scenario": "confirm_route_before_keeper", "skipped": True, "create": {"http": s1, "body": d1}}
    transfer_id = d1.get("id")
    if not isinstance(transfer_id, int):
        return {"scenario": "confirm_route_before_keeper", "error": "id is not integer", "create": d1}
    s2, d2 = client.prepare(transfer_id)
    if s2 != 200:
        return {"scenario": "confirm_route_before_keeper", "skipped": True, "create": d1, "prepare": {"http": s2, "body": d2}}

    counts = _prepared_counts(d2)
    body = {"routeInitSignatures": [_sig("route")] * max(counts["routeInitCount"], 1)}
    before = _status_snapshot(transfer_id)
    s3, d3 = client.confirm_broadcast(transfer_id, body)
    after = _status_snapshot(transfer_id)
    return {
        "scenario": "confirm_route_before_keeper",
        "expected": "Reject route signatures before keeper funding; status unchanged",
        "transferId": transfer_id,
        "preparedCounts": counts,
        "before": before,
        "confirm": {"http": s3, "body": d3, "request": body},
        "after": after,
    }


def scenario_confirm_before_prepare_valid_sigs(args: dict[str, Any] | None = None) -> dict:
    s1, d1 = _create_transfer()
    if s1 not in (200, 201):
        return {"scenario": "confirm_before_prepare_valid_sigs", "skipped": True, "create": {"http": s1, "body": d1}}
    transfer_id = d1.get("id")
    if not isinstance(transfer_id, int):
        return {"scenario": "confirm_before_prepare_valid_sigs", "error": "id is not integer", "create": d1}
    before = _status_snapshot(transfer_id)
    body = {
        "keeperFundingSignature": _sig("keeper"),
        "routeInitSignatures": [_sig("route")],
        "sessionInitSignatures": [_sig("session")],
    }
    s2, d2 = client.confirm_broadcast(transfer_id, body)
    after = _status_snapshot(transfer_id)
    return {
        "scenario": "confirm_before_prepare_valid_sigs",
        "expected": "State error such as 409/MH_INVALID_STATE, not format-only validation; status unchanged",
        "transferId": transfer_id,
        "before": before,
        "confirm": {"http": s2, "body": d2, "request": body},
        "after": after,
    }


def scenario_prepare_retry_consistency(args: dict[str, Any] | None = None) -> dict:
    s1, d1 = _create_transfer()
    if s1 not in (200, 201):
        return {"scenario": "prepare_retry_consistency", "skipped": True, "create": {"http": s1, "body": d1}}
    transfer_id = d1.get("id")
    if not isinstance(transfer_id, int):
        return {"scenario": "prepare_retry_consistency", "error": "id is not integer", "create": d1}
    idem = str(uuid.uuid4())
    s2, d2 = client.prepare(transfer_id, idem_key=idem)
    s3, d3 = client.prepare(transfer_id, idem_key=idem)
    s4, d4 = client.prepare(transfer_id, idem_key=str(uuid.uuid4()))
    return {
        "scenario": "prepare_retry_consistency",
        "expected": "Same prepare idempotency key replays exactly; fresh key within TTL is either same bundle or structured 409",
        "transferId": transfer_id,
        "sameKeyA": {"http": s2, "counts": _prepared_counts(d2), "body": d2},
        "sameKeyB": {"http": s3, "counts": _prepared_counts(d3), "body": d3},
        "freshKey": {"http": s4, "counts": _prepared_counts(d4), "body": d4},
        "sameKeyEqual": (d2.get("preparedTxs") == d3.get("preparedTxs")),
        "freshKeyEqual": (d2.get("preparedTxs") == d4.get("preparedTxs")),
    }


def scenario_prepare_after_expiry(args: dict[str, Any] | None = None) -> dict:
    wait_seconds = int((args or {}).get("waitSeconds", 75))
    s1, d1 = _create_transfer()
    if s1 not in (200, 201):
        return {"scenario": "prepare_after_expiry", "skipped": True, "create": {"http": s1, "body": d1}}
    transfer_id = d1.get("id")
    if not isinstance(transfer_id, int):
        return {"scenario": "prepare_after_expiry", "error": "id is not integer", "create": d1}
    s2, d2 = client.prepare(transfer_id)
    first_counts = _prepared_counts(d2)
    time.sleep(wait_seconds)
    s3, d3 = client.prepare(transfer_id, idem_key=str(uuid.uuid4()))
    second_counts = _prepared_counts(d3)
    return {
        "scenario": "prepare_after_expiry",
        "expected": "After blockhash expiry, prepare returns a fresh usable bundle or terminal structured error",
        "transferId": transfer_id,
        "waitSeconds": wait_seconds,
        "first": {"http": s2, "counts": first_counts, "body": d2},
        "second": {"http": s3, "counts": second_counts, "body": d3},
        "blockhashChanged": first_counts.get("recentBlockhash") != second_counts.get("recentBlockhash"),
    }


SCENARIOS = {
    "idempotency_conflict_mh071": scenario_idempotency_conflict_mh071,
    "concurrent_same_key": scenario_concurrent_same_key,
    "confirm_wrong_cardinality": scenario_confirm_wrong_cardinality,
    "confirm_route_before_keeper": scenario_confirm_route_before_keeper,
    "confirm_before_prepare_valid_sigs": scenario_confirm_before_prepare_valid_sigs,
    "prepare_retry_consistency": scenario_prepare_retry_consistency,
    "prepare_after_expiry": scenario_prepare_after_expiry,
}


def run_scenario(name: str, args: dict[str, Any] | None = None) -> tuple[int, dict]:
    fn = SCENARIOS.get(name)
    if not fn:
        return 0, {
            "error": f"Unknown scenario: {name}",
            "available": sorted(SCENARIOS.keys()),
        }
    result = fn(args or {})
    return 200, json.loads(json.dumps(result, default=str))
