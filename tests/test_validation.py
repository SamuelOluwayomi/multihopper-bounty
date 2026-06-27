import uuid, json, time
import pytest

def test_hops_below_min(client, wallets):
    src, dest = wallets
    s, d = client.create(src, dest, overrides={"hops": 2})
    assert s == 400, f"Expected 400 for hops=2, got {s}: {d}"
    assert "MH_013" in json.dumps(d)

def test_hops_above_max(client, wallets):
    time.sleep(2)
    src, dest = wallets
    s, d = client.create(src, dest, overrides={"hops": 11})
    assert s == 400, f"Expected 400 for hops=11, got {s}: {d}"
    assert "MH_013" in json.dumps(d)

def test_arrival_seconds_too_low(client, wallets):
    time.sleep(2)
    src, dest = wallets
    s, d = client.create(src, dest, overrides={"hops": 10, "arrivalSeconds": 1})
    assert s == 400, f"Expected 400 for arrivalSeconds=1/hops=10, got {s}: {d}"
    assert "MH_014" in json.dumps(d)

def test_invalid_wallet_rejected(client, wallets):
    time.sleep(2)
    _, dest = wallets
    s, d = client.create("not-a-valid-pubkey", dest)
    assert s == 400, f"Expected 400 for invalid wallet, got {s}: {d}"

def test_duplicate_external_id(client, wallets):
    time.sleep(2)
    src, dest = wallets
    ext = f"mh-test-{uuid.uuid4()}"
    s1, _ = client.create(src, dest, overrides={"externalId": ext})
    time.sleep(2)
    s2, d2 = client.create(src, dest, overrides={"externalId": ext})
    assert s1 in (200, 201)
    assert s2 == 409 and "MH_033" in json.dumps(d2), f"Expected 409/MH_033, got {s2}: {d2}"
