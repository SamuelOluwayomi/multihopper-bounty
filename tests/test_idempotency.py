import uuid, json
import pytest

def test_missing_idempotency_key(client, wallets):
    src, dest = wallets
    s, d = client.raw("POST", "/transfers", body={
        "tokenMint": "So11111111111111111111111111111111111111112",
        "amountRaw": "100000000", "amountTokens": "0.1",
        "tokenDecimals": 9, "sourceOwner": src, "recipientWallet": dest,
        "hops": 3, "arrivalSeconds": 300, "externalId": f"mh-test-{uuid.uuid4()}",
    })
    assert s == 400 and "MH_070" in json.dumps(d), f"Expected 400/MH_070, got {s}: {d}"

def test_duplicate_idempotency_key_returns_same_id(client, wallets):
    src, dest = wallets
    idem = str(uuid.uuid4())
    s1, d1 = client.create(src, dest, idem_key=idem)
    s2, d2 = client.create(src, dest, idem_key=idem)
    assert s1 in (200, 201)
    assert d1.get("id") == d2.get("id"), f"Idempotency broken: id1={d1.get('id')} id2={d2.get('id')}"

def test_prepare_idempotency(client, wallets):
    src, dest = wallets
    _, d1 = client.create(src, dest)
    idem = str(uuid.uuid4())
    _, dp1 = client.prepare(d1["id"], idem_key=idem)
    _, dp2 = client.prepare(d1["id"], idem_key=idem)
    assert dp1.get("preparedTxs") == dp2.get("preparedTxs"), "preparedTxs differed on same Idempotency-Key"

