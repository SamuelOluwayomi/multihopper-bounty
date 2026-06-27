# MultiHopper

REST API: https://devnet.multihopper.com/api/v1 (devnet) | https://multihopper.com/api/v1 (mainnet)
Auth: x-api-key header — mh_test_... (devnet) or mh_live_... (mainnet)

## Transfer flow — 3 API calls

### 1. Create
POST /transfers
Required: tokenMint, amountRaw, amountTokens, sourceOwner (sender), recipientWallet, hops (3–10), arrivalSeconds
Optional: tokenDecimals (default 6), tokenSymbol, externalId
→ returns { id, status: "awaiting_signature" }
All POST mutations require Idempotency-Key header (MH_070 if missing)

### 2. Prepare
POST /transfers/{id}/prepare
→ returns { preparedTxs: { routeInitTxs[], orchestratorInitTx, sessionInitTxs[], keeperFundingTx } }

BROADCAST ORDER (strict):
  keeperFundingTx → routeInitTxs → orchestratorInitTx → sessionInitTxs

null fields = already confirmed on-chain (skip them)
Blockhash expires ~60s after /prepare; call again with NEW Idempotency-Key on expiry

### 3. Confirm broadcast — called TWICE

First call (immediately after keeperFundingTx):
  POST /transfers/{id}/confirm-broadcast
  { routeInitSignatures: [], keeperFundingSignature: "..." }

Second call (after all remaining txs):
  POST /transfers/{id}/confirm-broadcast
  { routeInitSignatures[], orchestratorInitSignature, sessionInitSignatures[] }

keeperFundingSignature required if /prepare emitted keeperFundingTx → MH_039 if missing

## Signing rules
- keeperFundingTx, routeInitTxs, sessionInitTxs → VersionedTransaction (v0)
  ADD your sig to the correct slot only — do NOT replace all sigs (server has pre-signed ephemeral keys)
- orchestratorInitTx → Legacy Transaction (partialSign)
- Wait for confirmed before broadcasting next group
- Add 3s delay after last routeInitTx and after orchestratorInitTx

## Status polling
GET /transfers/{id} → { status, phase, progress: { hopsCompleted, hopsTotal } }
status: quote → awaiting_signature → processing → completed | failed | expired | refunded

## Common errors
MH_013  hops out of range (must be 3–10)
MH_014  arrivalSeconds below minimum for hop count
MH_033  duplicate externalId
MH_039  keeperFundingSignature missing
MH_070  Idempotency-Key header missing or invalid
