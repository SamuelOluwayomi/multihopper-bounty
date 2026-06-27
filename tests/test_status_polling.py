import json
import uuid
import pytest


class TestStatusPollingBasics:
    def test_get_nonexistent_transfer_returns_404(self, client):
        s, d = client.get(999999999)
        assert s == 404, f"Expected 404 for unknown transfer, got HTTP {s}: {d}"

    def test_get_nonexistent_transfer_has_error_body(self, client):
        s, d = client.get(999999999)
        raw = json.dumps(d).lower()
        has_code = "code" in d or "error" in d or "message" in d or "mh_" in raw
        assert has_code, (
            f"FINDING [Documentation]: 404 response for unknown transfer has no machine-readable "
            f"error code. Agents need structured errors (e.g. {{code, message}}) to distinguish "
            f"'not found' from auth failures. Got: {d}"
        )

    def test_create_then_get_returns_valid_status(self, client, wallets):
        src, dest = wallets
        s1, d1 = client.create(src, dest)
        assert s1 in (200, 201), f"Create failed HTTP {s1}: {d1}"

        transfer_id = d1.get("id")
        assert transfer_id is not None, "Create response has no 'id' field"

        s2, d2 = client.get(transfer_id)
        assert s2 == 200, f"GET /transfers/{transfer_id} returned HTTP {s2}: {d2}"

    def test_get_transfer_has_status_field(self, client, wallets):
        valid_statuses = {
            "quote", "awaiting_signature", "processing",
            "completed", "failed", "expired", "refunded",
        }
        src, dest = wallets
        _, d1 = client.create(src, dest)
        transfer_id = d1.get("id")
        if not transfer_id:
            pytest.skip("Could not get transfer id")

        _, d2 = client.get(transfer_id)
        status = d2.get("status")
        assert status is not None, (
            f"FINDING [Medium]: GET /transfers/:id response missing 'status' field. "
            f"Agents rely on this field to drive state machine decisions. Got: {d2}"
        )
        assert status in valid_statuses, (
            f"FINDING [Medium]: Unknown status value '{status}' returned. "
            f"Expected one of {valid_statuses}. "
            "Undocumented status values break agent state machines."
        )

    def test_get_transfer_has_progress_object(self, client, wallets):
        src, dest = wallets
        _, d1 = client.create(src, dest)
        transfer_id = d1.get("id")
        if not transfer_id:
            pytest.skip("Could not get transfer id")

        _, d2 = client.get(transfer_id)
        assert "progress" in d2 or "phase" in d2, (
            f"FINDING [Low]: GET /transfers/:id response missing 'progress' or 'phase' field. "
            f"Got keys: {list(d2.keys())}"
        )

    def test_freshly_created_transfer_status_is_awaiting_signature(self, client, wallets):
        src, dest = wallets
        _, d1 = client.create(src, dest)
        transfer_id = d1.get("id")
        if not transfer_id:
            pytest.skip("Could not get transfer id")

        _, d2 = client.get(transfer_id)
        status = d2.get("status", "")
        assert status in ("awaiting_signature", "quote"), (
            f"Unexpected initial status '{status}' after create."
        )


class TestStatusPollingList:
    def test_list_transfers_returns_200(self, client):
        s, d = client.list()
        assert s == 200, f"GET /transfers returned HTTP {s}: {d}"

    def test_list_transfers_is_array_or_paginated(self, client):
        _, d = client.list()
        is_list = isinstance(d, list)
        is_paginated = isinstance(d, dict) and (
            "data" in d or "items" in d or "transfers" in d or "results" in d
        )
        assert is_list or is_paginated, (
            f"FINDING [Documentation]: GET /transfers response shape is undocumented. "
            f"Got type {type(d).__name__}: {str(d)[:200]}"
        )

