import base64
import os
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    import base58
    from solders.keypair import Keypair
    from solders.transaction import VersionedTransaction
    from solders.transaction import Transaction as LegacyTransaction
    AVAILABLE = True
else:
    try:
        import base58
        from solders.keypair import Keypair
        from solders.transaction import VersionedTransaction
        from solders.transaction import Transaction as LegacyTransaction
        AVAILABLE = True
    except ImportError:
        base58 = None
        Keypair = None
        VersionedTransaction = None
        LegacyTransaction = None
        AVAILABLE = False 


def load_keypair(private_key_b58: Optional[str] = None) -> Optional["Keypair"]:
    if not AVAILABLE:
        return None
    key = private_key_b58 or os.environ.get("SOLANA_PRIVATE_KEY", "")
    if not key or "<" in key or ">" in key:
        return None
    try:
        return Keypair.from_bytes(base58.b58decode(key))
    except Exception:
        return None



def sign_versioned(base64_tx: str, keypair: "Keypair") -> str:
    tx = VersionedTransaction.from_bytes(base64.b64decode(base64_tx))
    msg_bytes = bytes([0x80]) + bytes(tx.message)
    our_sig = keypair.sign_message(msg_bytes)
    account_keys = list(tx.message.account_keys)
    pubkey = keypair.pubkey()
    matches = [i for i, k in enumerate(account_keys) if k == pubkey]
    if not matches:
        raise ValueError(f"Pubkey {pubkey} not found in transaction account keys")
    idx = matches[0]
    sigs = list(tx.signatures)
    if idx >= len(sigs):
        raise ValueError(f"Pubkey {pubkey} is at account index {idx} but only {len(sigs)} sig slots exist — not a required signer")
    sigs[idx] = our_sig
    return base64.b64encode(bytes(VersionedTransaction.populate(tx.message, sigs))).decode()


def sign_legacy(base64_tx: str, keypair: "Keypair") -> str:
    tx = LegacyTransaction.from_bytes(base64.b64decode(base64_tx))
    tx.partial_sign([keypair], tx.message.recent_blockhash)
    return base64.b64encode(bytes(tx)).decode()


def sign_all(prepared_txs: dict, keypair: "Keypair") -> dict:
    signed = {}
    if prepared_txs.get("keeperFundingTx"):
        signed["keeperFundingTx"] = sign_versioned(prepared_txs["keeperFundingTx"], keypair)
    if prepared_txs.get("routeInitTxs"):
        signed["routeInitTxs"] = [
            {"base64": sign_versioned(e["base64"], keypair)}
            for e in prepared_txs["routeInitTxs"]
        ]
    if prepared_txs.get("orchestratorInitTx"):
        signed["orchestratorInitTx"] = sign_legacy(prepared_txs["orchestratorInitTx"], keypair)
    if prepared_txs.get("sessionInitTxs"):
        signed["sessionInitTxs"] = [sign_versioned(b, keypair) for b in prepared_txs["sessionInitTxs"]]
    return signed


def server_sigs_preserved(original_b64: str, signed_b64: str) -> bool:
    if not AVAILABLE:
        return True
    orig = VersionedTransaction.from_bytes(base64.b64decode(original_b64))
    signed = VersionedTransaction.from_bytes(base64.b64decode(signed_b64))
    default = bytes(64)
    for i, (o, s) in enumerate(zip(orig.signatures, signed.signatures)):
        if bytes(o) != default and bytes(o) != bytes(s):
            print(f"  [!] Sig slot {i}: server signature was overwritten!")
            return False
    return True

