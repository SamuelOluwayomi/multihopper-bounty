import json
import os
import uuid
from typing import Optional

import requests
from dotenv import load_dotenv

load_dotenv()

API_BASE = os.environ.get("MH_API_BASE", "https://devnet.multihopper.com")
API_KEY  = os.environ.get("MH_API_KEY", "")
SOL_MINT = "So11111111111111111111111111111111111111112"


class MultiHopperClient:
    def __init__(self, api_base: str = API_BASE, api_key: str = API_KEY):
        self.base = api_base
        self.key  = api_key

    def _headers(self, idem_key: Optional[str] = None, extra: Optional[dict] = None) -> dict:
        h = {"x-api-key": self.key, "Content-Type": "application/json"}
        if idem_key:
            h["Idempotency-Key"] = idem_key
        if extra:
            h.update(extra)
        return h

    def raw(self, method: str, path: str, body: Optional[dict] = None,
            idem_key: Optional[str] = None, extra_headers: Optional[dict] = None
            ) -> tuple[int, dict]:
        url = f"{self.base}/api/v1{path}"
        try:
            r = requests.request(
                method, url, json=body,
                headers=self._headers(idem_key, extra_headers),
                timeout=30,
            )
            try:
                data = r.json()
            except Exception:
                data = {"raw": r.text}
            return r.status_code, data
        except Exception as e:
            return 0, {"error": str(e)}

    def estimate(self, token_mint: str, amount_raw: str, token_decimals: int, hops: int
                 ) -> tuple[int, dict]:
        return self.raw("POST", "/transfers/estimate", {
            "tokenMint": token_mint,
            "amountRaw": amount_raw,
            "tokenDecimals": token_decimals,
            "hops": hops,
        }, idem_key=str(uuid.uuid4()))

    def create(self, source_owner: str, recipient: str,
               amount_raw: str = "100000000", amount_tokens: str = "0.1",
               hops: int = 3, arrival_seconds: int = 300,
               token_mint: str = SOL_MINT, token_decimals: int = 9,
               token_symbol: str = "SOL", external_id: Optional[str] = None,
               idem_key: Optional[str] = None, overrides: Optional[dict] = None
               ) -> tuple[int, dict]:
        body = {
            "tokenMint": token_mint,
            "amountRaw": amount_raw,
            "amountTokens": amount_tokens,
            "tokenDecimals": token_decimals,
            "tokenSymbol": token_symbol,
            "sourceOwner": source_owner,
            "recipientWallet": recipient,
            "hops": hops,
            "arrivalSeconds": arrival_seconds,
            "externalId": external_id or f"mh-test-{uuid.uuid4()}",
        }
        if overrides:
            body.update(overrides)
        return self.raw("POST", "/transfers", body, idem_key or str(uuid.uuid4()))

    def prepare(self, transfer_id: int, idem_key: Optional[str] = None) -> tuple[int, dict]:
        return self.raw("POST", f"/transfers/{transfer_id}/prepare",
                        idem_key=idem_key or str(uuid.uuid4()))

    def confirm_broadcast(self, transfer_id: int, body: dict,
                          idem_key: Optional[str] = None) -> tuple[int, dict]:
        return self.raw("POST", f"/transfers/{transfer_id}/confirm-broadcast",
                        body=body, idem_key=idem_key or str(uuid.uuid4()))

    def get(self, transfer_id: int) -> tuple[int, dict]:
        return self.raw("GET", f"/transfers/{transfer_id}")

    def list(self, **params) -> tuple[int, dict]:
        path = "/transfers"
        if params:
            qs = "&".join(f"{k}={v}" for k, v in params.items())
            path += f"?{qs}"
        return self.raw("GET", path)

