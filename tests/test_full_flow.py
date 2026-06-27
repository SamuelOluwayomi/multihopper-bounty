import json
import time
import pytest

from src.client import MultiHopperClient


@pytest.fixture(scope="module")
def client():
    return MultiHopperClient()


@pytest.fixture(scope="module")
def wallets():
    import os
    return os.environ["SOURCE_WALLET"], os.environ["RECIPIENT_WALLET"]


class TestPrepareResponseShape:
    def test_prepare_returns_prepared_txs_key(self, client, wallets):
        time.sleep(2)
        src, dest = wallets
        s1, d1 = client.create(src, dest)
        if s1 not in (200, 201):
            pytest.skip(f"create failed HTTP {s1}")
        tid = d1.get("id")
        assert tid

        s2, d2 = client.prepare(tid)
        assert s2 == 200, f"prepare returned HTTP {s2}: {d2}"
        assert "preparedTxs" in d2, (
            "preparedTxs key absent — agents doing d['preparedTxs'] will raise KeyError"
        )

    def test_prepare_txs_fields_all_present(self, client, wallets):
        time.sleep(2)
        src, dest = wallets
        s1, d1 = client.create(src, dest)
        if s1 not in (200, 201):
            pytest.skip(f"create failed HTTP {s1}")
        tid = d1.get("id")

        s2, d2 = client.prepare(tid)
        if s2 != 200:
            pytest.skip(f"prepare HTTP {s2}")

        txs = d2.get("preparedTxs", {})
        documented_fields = ["keeperFundingTx", "routeInitTxs", "orchestratorInitTx", "sessionInitTxs"]
        missing = [f for f in documented_fields if f not in txs]
        assert not missing, (
            f"preparedTxs missing documented fields {missing}. "
            f"CLAUDE.md documents all four fields — agents will crash with KeyError. "
            f"Present keys: {list(txs.keys())}"
        )

    def test_prepare_blockhash_present(self, client, wallets):
        time.sleep(2)
        src, dest = wallets
        s1, d1 = client.create(src, dest)
        if s1 not in (200, 201):
            pytest.skip(f"create failed HTTP {s1}")
        tid = d1.get("id")

        s2, d2 = client.prepare(tid)
        if s2 != 200:
            pytest.skip(f"prepare HTTP {s2}")

        txs = d2.get("preparedTxs", {})
        assert txs.get("recentBlockhash"), (
            "recentBlockhash absent from preparedTxs — agent cannot verify expiry or log context"
        )

    def test_prepare_blockhash_in_transfer_too(self, client, wallets):
        time.sleep(2)
        src, dest = wallets
        s1, d1 = client.create(src, dest)
        if s1 not in (200, 201):
            pytest.skip(f"create failed HTTP {s1}")
        tid = d1.get("id")

        s2, d2 = client.prepare(tid)
        if s2 != 200:
            pytest.skip(f"prepare HTTP {s2}")

        assert "lastValidBlockHeight" in (d2.get("preparedTxs") or {}), (
            "lastValidBlockHeight missing — agents cannot calculate when blockhash expires. "
            "CLAUDE.md documents this field."
        )


class TestConfirmBroadcastShape:
    def test_confirm_broadcast_requires_body(self, client, wallets):
        time.sleep(2)
        src, dest = wallets
        s1, d1 = client.create(src, dest)
        if s1 not in (200, 201):
            pytest.skip(f"create HTTP {s1}")
        tid = d1.get("id")

        s2, _ = client.prepare(tid)
        if s2 != 200:
            pytest.skip(f"prepare HTTP {s2}")

        s3, d3 = client.raw("POST", f"/transfers/{tid}/confirm-broadcast",
                            body={}, idem_key=None)
        assert s3 != 500, (
            f"confirm-broadcast with empty body returned 500 (internal error) instead of 400. "
            f"Agents sending malformed bodies will see opaque server errors: {d3}"
        )

    def test_confirm_broadcast_error_is_machine_readable(self, client, wallets):
        time.sleep(2)
        src, dest = wallets
        s1, d1 = client.create(src, dest)
        if s1 not in (200, 201):
            pytest.skip(f"create HTTP {s1}")
        tid = d1.get("id")

        s2, _ = client.prepare(tid)
        if s2 != 200:
            pytest.skip(f"prepare HTTP {s2}")

        s3, d3 = client.confirm_broadcast(tid, {"keeperFundingSignature": None})
        if s3 not in (200, 201):
            body_str = json.dumps(d3)
            has_code = "code" in body_str or "MH_" in body_str
            assert has_code, (
                f"confirm-broadcast error (HTTP {s3}) has no machine-readable 'code' field. "
                f"Agents cannot programmatically distinguish error types. Body: {body_str[:300]}"
            )


class TestExpiredTransfer:
    def test_prepare_on_stale_transfer_id(self, client):
        stale_id = 1
        s, d = client.prepare(stale_id)
        assert s in (400, 404, 409, 410), (
            f"Prepare on stale/unknown transfer returned unexpected HTTP {s}: {d}"
        )
        body_str = json.dumps(d)
        assert "code" in body_str or "error" in body_str, (
            "Error response for stale prepare has no machine-readable structure"
        )

    def test_prepare_error_not_500(self, client):
        s, d = client.prepare(9999999)
        assert s != 500, (
            f"Prepare on non-existent ID returned 500 — internal error leaked to client: {d}"
        )
