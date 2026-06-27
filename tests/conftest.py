import os
import sys

_ROOT = os.path.dirname(os.path.dirname(__file__))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import pytest
from dotenv import load_dotenv

load_dotenv(os.path.join(_ROOT, ".env"))


@pytest.fixture(scope="session")
def client():
    key = os.environ.get("MH_API_KEY", "")
    if not key or key == "mh_test_YOUR_KEY_HERE":
        pytest.skip("MH_API_KEY not set — copy .env.example to .env and fill in your key")
    from src.client import MultiHopperClient
    return MultiHopperClient()


@pytest.fixture(scope="session")
def wallets():
    src  = os.environ.get("SOURCE_WALLET", "")
    dest = os.environ.get("RECIPIENT_WALLET", "")
    if not src or not dest or "<" in src or "<" in dest:
        pytest.skip("SOURCE_WALLET or RECIPIENT_WALLET not set in .env")
    return src, dest


@pytest.fixture(scope="session")
def keypair():
    try:
        from src.signer import load_keypair, AVAILABLE
    except ImportError:
        pytest.skip("src.signer import failed")
    if not AVAILABLE:
        pytest.skip("solders/base58 not installed — run: pip install solders base58")
    kp = load_keypair()
    if kp is None:
        pytest.skip("SOLANA_PRIVATE_KEY not set in .env")
    return kp

