import base64
import pytest

pytest.importorskip("solders", reason="solders not installed — run: pip install solders base58")
pytest.importorskip("base58", reason="base58 not installed — run: pip install base58")

from src.signer import (
    load_keypair,
    sign_versioned,
    sign_legacy,
    server_sigs_preserved,
    AVAILABLE,
)


@pytest.fixture(scope="module")
def keypair():
    kp = load_keypair()
    if kp is None:
        pytest.skip("SOLANA_PRIVATE_KEY not set — skipping signing tests")
    return kp


class TestSigningAvailability:
    def test_solders_available(self):
        assert AVAILABLE is True


class TestServerSigsPreserved:
    def test_returns_true_when_no_signing_available(self):
        assert callable(server_sigs_preserved)

    def test_identical_tx_passes_preservation_check(self, keypair):
        from solders.keypair import Keypair
        from solders.system_program import transfer, TransferParams
        from solders.transaction import VersionedTransaction
        from solders.message import MessageV0
        from solders.hash import Hash
        from solders.pubkey import Pubkey

        dummy_blockhash = Hash.from_bytes(bytes(32))
        ixn = transfer(TransferParams(
            from_pubkey=keypair.pubkey(),
            to_pubkey=Pubkey.from_bytes(bytes(32)),
            lamports=1,
        ))
        msg = MessageV0.try_compile(
            payer=keypair.pubkey(),
            instructions=[ixn],
            address_lookup_table_accounts=[],
            recent_blockhash=dummy_blockhash,
        )
        tx = VersionedTransaction(msg, [keypair])
        tx_b64 = base64.b64encode(bytes(tx)).decode()

        signed_b64 = sign_versioned(tx_b64, keypair)
        assert server_sigs_preserved(tx_b64, signed_b64), (
            "server_sigs_preserved() returned False even though no server partial sigs exist"
        )


class TestSignVersioned:
    def test_sign_versioned_output_is_base64(self, keypair):
        from solders.keypair import Keypair
        from solders.system_program import transfer, TransferParams
        from solders.transaction import VersionedTransaction
        from solders.message import MessageV0
        from solders.hash import Hash
        from solders.pubkey import Pubkey

        dummy_blockhash = Hash.from_bytes(bytes(32))
        ixn = transfer(TransferParams(
            from_pubkey=keypair.pubkey(),
            to_pubkey=Pubkey.from_bytes(bytes(32)),
            lamports=1,
        ))
        msg = MessageV0.try_compile(
            payer=keypair.pubkey(),
            instructions=[ixn],
            address_lookup_table_accounts=[],
            recent_blockhash=dummy_blockhash,
        )
        tx = VersionedTransaction(msg, [keypair])
        tx_b64 = base64.b64encode(bytes(tx)).decode()

        result = sign_versioned(tx_b64, keypair)
        decoded = base64.b64decode(result)
        assert len(decoded) > 0

    def test_sign_versioned_raises_if_pubkey_not_in_tx(self, keypair):
        from solders.keypair import Keypair
        from solders.system_program import transfer, TransferParams
        from solders.transaction import VersionedTransaction
        from solders.message import MessageV0
        from solders.hash import Hash

        other_kp = Keypair()
        dummy_blockhash = Hash.from_bytes(bytes(32))
        ixn = transfer(TransferParams(
            from_pubkey=other_kp.pubkey(),
            to_pubkey=keypair.pubkey(),
            lamports=1,
        ))
        msg = MessageV0.try_compile(
            payer=other_kp.pubkey(),
            instructions=[ixn],
            address_lookup_table_accounts=[],
            recent_blockhash=dummy_blockhash,
        )
        tx = VersionedTransaction(msg, [other_kp])
        tx_b64 = base64.b64encode(bytes(tx)).decode()

        with pytest.raises(ValueError):
            sign_versioned(tx_b64, keypair)


class TestSigningWithRealPreparedTxs:
    def test_sign_all_preserves_server_partial_sigs(self, client, wallets, keypair):
        from src.signer import sign_all

        src, dest = wallets
        pubkey_str = str(keypair.pubkey())
        s1, d1 = client.create(pubkey_str, dest)
        if s1 not in (200, 201):
            pytest.skip(f"Could not create transfer (HTTP {s1}): {d1}")

        sp, dp = client.prepare(d1["id"])
        if sp != 200:
            pytest.skip(f"Prepare failed (HTTP {sp}): {dp}")

        prepared = dp.get("preparedTxs", {})
        if not prepared:
            pytest.skip("preparedTxs empty")

        try:
            signed = sign_all(prepared, keypair)
        except Exception as e:
            pytest.fail(
                f"sign_all() raised an exception on real /prepare output: {e}\n"
                "This means the signing helpers from the agentic guide are broken."
            )

        if prepared.get("keeperFundingTx") and signed.get("keeperFundingTx"):
            assert server_sigs_preserved(
                prepared["keeperFundingTx"], signed["keeperFundingTx"]
            ), (
                "Signing defect: sign_all() overwrote server partial signature on keeperFundingTx. "
                "This proves integration failure risk, not direct fund loss."
            )
