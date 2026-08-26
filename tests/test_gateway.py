"""
Integration Tests for API Gateway, Replay Engine & Counterfactual Sandbox.
"""

import pytest
from httpx import AsyncClient, ASGITransport
from src.gateway.webhook_gateway import app, WEBHOOK_SECRET
import hmac
import hashlib
import json


@pytest.mark.asyncio
async def test_replay_and_counterfactual_endpoints():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        # Test Telemetry Endpoint
        telemetry_res = await client.get("/api/v1/metrics/telemetry")
        assert telemetry_res.status_code == 200
        assert telemetry_res.json()["system_status"] == "HEALTHY"

        # Test Replay Timeline Endpoint
        replay_res = await client.get("/api/v1/decisions/dec_pytest_001/replay")
        assert replay_res.status_code == 200
        timeline = replay_res.json()
        assert len(timeline["trace_steps"]) == 6
        assert timeline["trace_steps"][4]["node_name"] == "policy_gate"

        # Test Counterfactual Sandbox Endpoint
        counterfactual_req = {
            "original_decision_id": "dec_pytest_001",
            "perturbed_parameters": {"amount": 40000, "velocity_count": 1, "blacklisted_ip": False}
        }
        cf_res = await client.post("/api/v1/decisions/counterfactual", json=counterfactual_req)
        assert cf_res.status_code == 200
        delta = cf_res.json()
        assert delta["new_action"] == "APPROVE"
        assert delta["original_action"] == "STEP_UP_AUTH"
