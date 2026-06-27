import uuid, json
import pytest

def test_confirm_before_prepare_rejected(client, wallets):
    src, dest = wallets
    _, d1 = client.create(src, dest)
    s, d = client.confirm_broadcast(d1["id"], {
        "routeInitSignatures": ["fakeSig"],
        "keeperFundingSignature": "fakeSig",
    })
    assert s in (400, 409, 422), f"Expected rejection, got {s}: {d}"

def test_prepare_unknown_id(client, wallets):
    s, _ = client.prepare(999999999)
    assert s == 404, f"Expected 404 for unknown transfer, got {s}"

def test_confirm_missing_keeper_sig(client, wallets):
    src, dest = wallets
    _, d1 = client.create(src, dest)
    _, d2 = client.prepare(d1["id"])
    has_keeper = d2.get("preparedTxs", {}).get("keeperFundingTx") is not None
    if not has_keeper:
        pytest.skip("No keeperFundingTx in preparedTxs")
    s, d3 = client.confirm_broadcast(d1["id"], {"routeInitSignatures": []})
    assert s == 400 and "MH_039" in json.dumps(d3), \
        f"Expected 400/MH_039 for missing keeperFundingSignature, got {s}: {d3}"

