"""
Integration Tests for API Gateway, Replay Engine, Counterfactual Sandbox & Webhook Edge Cases.
"""

import pytest
import hmac
import hashlib
import json
from httpx import AsyncClient, ASGITransport
from src.gateway.webhook_gateway import app, WEBHOOK_SECRET


def _make_signature(raw_bytes: bytes) -> str:
    return hmac.new(
        key=WEBHOOK_SECRET.encode("utf-8"),
        msg=raw_bytes,
        digestmod=hashlib.sha256
    ).hexdigest()


@pytest.mark.asyncio
async def test_replay_and_counterfactual_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        telemetry_res = await client.get("/api/v1/metrics/telemetry")
        assert telemetry_res.status_code == 200
        assert telemetry_res.json()["system_status"] == "HEALTHY"

        replay_res = await client.get("/api/v1/decisions/dec_pytest_001/replay")
        assert replay_res.status_code == 200
        timeline = replay_res.json()
        assert len(timeline["trace_steps"]) == 6

        counterfactual_req = {
            "original_decision_id": "dec_pytest_001",
            "perturbed_parameters": {"amount": 40000, "velocity_count": 1, "blacklisted_ip": False}
        }
        cf_res = await client.post("/api/v1/decisions/counterfactual", json=counterfactual_req)
        assert cf_res.status_code == 200
        delta = cf_res.json()
        assert delta["new_action"] == "APPROVE"


@pytest.mark.asyncio
async def test_webhook_security_and_parsing_edge_cases():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Valid Webhook with Dynamic Payload Parsing
        payload_1 = {"amount": 250000, "velocity_count": 1, "blacklisted_ip": False}
        body_1 = json.dumps(payload_1, sort_keys=True).encode("utf-8")
        sig_1 = _make_signature(body_1)
        headers_1 = {
            "X-Razorpay-Signature": sig_1, 
            "X-Razorpay-Event-Id": "evt_gateway_001", 
            "Content-Type": "application/json"
        }

        res_1 = await client.post("/api/v1/webhooks/razorpay", content=body_1, headers=headers_1)
        assert res_1.status_code == 200
        assert res_1.json()["status"] == "ACCEPTED"

        # 2. Duplicate Event Delivery (Idempotency Filter)
        res_dup = await client.post("/api/v1/webhooks/razorpay", content=body_1, headers=headers_1)
        assert res_dup.status_code == 200
        assert res_dup.json()["status"] == "SKIPPED_DUPLICATE"

        # 3. Missing Signature Header
        res_no_sig = await client.post(
            "/api/v1/webhooks/razorpay", 
            content=body_1, 
            headers={"X-Razorpay-Event-Id": "evt_gateway_002"}
        )
        assert res_no_sig.status_code == 400

        # 4. Invalid Signature Header (HMAC Mismatch)
        res_bad_sig = await client.post(
            "/api/v1/webhooks/razorpay", 
            content=body_1, 
            headers={"X-Razorpay-Signature": "invalid_sig_hash", "X-Razorpay-Event-Id": "evt_gateway_003"}
        )
        assert res_bad_sig.status_code == 401

        # 5. Missing Event ID Header
        res_no_evt = await client.post(
            "/api/v1/webhooks/razorpay", 
            content=body_1, 
            headers={"X-Razorpay-Signature": sig_1}
        )
        assert res_no_evt.status_code == 400

        # 6. Malformed JSON Body (Signature matches raw bytes, but payload is malformed JSON)
        bad_json_body = b"not_valid_json_string"
        bad_json_sig = _make_signature(bad_json_body)
        res_bad_json = await client.post(
            "/api/v1/webhooks/razorpay", 
            content=bad_json_body, 
            headers={"X-Razorpay-Signature": bad_json_sig, "X-Razorpay-Event-Id": "evt_gateway_004"}
        )
        assert res_bad_json.status_code == 400
        assert "Invalid JSON body" in res_bad_json.json()["detail"]
