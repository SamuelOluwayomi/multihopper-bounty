import threading
import json
import time
import pytest

from src.client import MultiHopperClient
from src.agent import (
    test_fake_keeper_signature,
    test_amount_mismatch,
    test_self_transfer,
    test_zero_amount,
    test_invalid_token_mint,
    test_concurrent_prepare,
)


@pytest.fixture(scope="module")
def client():
    return MultiHopperClient()


@pytest.fixture(scope="module")
def wallets(client):
    import os
    return os.environ["SOURCE_WALLET"], os.environ["RECIPIENT_WALLET"]


def test_fake_keeper_sig_rejected(client, wallets):
    src, dest = wallets
    s1, d1 = client.create(src, dest)
    if s1 not in (200, 201):
        pytest.skip(f"create failed HTTP {s1}")
    tid = d1.get("id")
    assert tid

    time.sleep(2)
    s2, _ = client.prepare(tid)
    if s2 != 200:
        pytest.skip(f"prepare failed HTTP {s2}")

    fake_sig = "5" * 87 + "A"
    s3, d3 = client.confirm_broadcast(tid, {
        "routeInitSignatures": [],
        "keeperFundingSignature": fake_sig,
    })
    assert s3 not in (200, 201), (
        f"SECURITY: confirm-broadcast accepted a fabricated signature (HTTP {s3}): {d3}"
    )


def test_amount_mismatch_rejected(client, wallets):
    time.sleep(2)
    src, dest = wallets
    s, d = client.create(src, dest, amount_raw="1000000000", amount_tokens="0.0001")
    assert s not in (200, 201), (
        f"amountRaw/amountTokens mismatch accepted (HTTP {s}): {d}"
    )


def test_self_transfer_rejected(client, wallets):
    time.sleep(2)
    src, _ = wallets
    s, d = client.create(src, src)
    assert s not in (200, 201), (
        f"Self-transfer (src==dest) accepted (HTTP {s}): {d}"
    )


def test_zero_amount_rejected(client, wallets):
    time.sleep(2)
    src, dest = wallets
    s, d = client.create(src, dest, amount_raw="0", amount_tokens="0")
    assert s not in (200, 201), (
        f"Zero-amount transfer accepted (HTTP {s}): {d}"
    )


def test_invalid_token_mint_rejected(client, wallets):
    time.sleep(2)
    src, dest = wallets
    s, d = client.create(src, dest, overrides={"tokenMint": "not-a-valid-pubkey-string"})
    assert s not in (200, 201), (
        f"Invalid tokenMint accepted at creation (HTTP {s}): {d}"
    )


def test_concurrent_prepare_same_blockhash(client, wallets):
    time.sleep(2)
    src, dest = wallets
    s, d = client.create(src, dest)
    if s not in (200, 201):
        pytest.skip(f"create failed HTTP {s}")
    tid = d.get("id")
    assert tid

    results = {}

    def do_prepare(label):
        results[label] = client.prepare(tid)

    t1 = threading.Thread(target=do_prepare, args=("r1",))
    t2 = threading.Thread(target=do_prepare, args=("r2",))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    s1, d1 = results["r1"]
    s2, d2 = results["r2"]

    bh1 = (d1.get("preparedTxs") or {}).get("recentBlockhash")
    bh2 = (d2.get("preparedTxs") or {}).get("recentBlockhash")

    if bh1 and bh2:
        assert bh1 == bh2, (
            f"Concurrent /prepare returned different blockhashes: "
            f"'{bh1[:20]}' vs '{bh2[:20]}'. "
            f"Race condition — agent retry could sign and broadcast two conflicting tx sets."
        )
