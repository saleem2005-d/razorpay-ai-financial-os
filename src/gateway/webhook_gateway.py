"""
Gateway Microservice with Raw-Byte HMAC Verification, Dynamic Payload Parsing,
Transactional Idempotency, and Live Telemetry Counters.
"""

import hmac
import hashlib
import time
import json
from typing import Dict, Any, Optional, Set
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, HTTPException, Depends, status
from pydantic import BaseModel
import redis.asyncio as aioredis

from src.core.replay_engine import (
    replay_engine_instance, 
    CounterfactualRequest, 
    CounterfactualDelta, 
    DecisionReplayTimeline
)
from src.core.consistency_engine import (
    build_consistency_graph, 
    FinancialOSState, 
    resolve_final_action
)

redis_client: Optional[aioredis.Redis] = None
local_idempotency_cache: Set[str] = set()

# Live Operational Telemetry Counters
telemetry_counters = {
    "total_requests": 0,
    "valid_signatures": 0,
    "duplicate_events_skipped": 0,
    "policy_overrides_enforced": 0
}

WEBHOOK_SECRET = "RAZORPAY_BUILDATHON_WEBHOOK_SECRET_2026"
IDEMPOTENCY_TTL_SECONDS = 86400

graph_app = build_consistency_graph()


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    """FastAPI Lifespan Manager for Redis connection lifecycle."""
    global redis_client
    try:
        redis_client = aioredis.from_url("redis://localhost:6379", decode_responses=True)
        await redis_client.ping()
    except Exception:
        redis_client = None
    yield
    if redis_client:
        await redis_client.close()


app = FastAPI(
    title="Razorpay AI Financial OS - Internal Console API",
    description="API Gateway with Raw-Byte Webhook Verification, Idempotency, and Telemetry.",
    version="1.0.0",
    lifespan=lifespan
)


class WebhookResponse(BaseModel):
    status: str
    event_id: str
    message: str
    decision_summary: Optional[Dict[str, Any]] = None
    processed_at_ms: int


async def verify_raw_hmac_signature(request: Request) -> bytes:
    """Extracts raw byte payload prior to JSON parsing to guarantee exact HMAC verification."""
    telemetry_counters["total_requests"] += 1
    
    signature = request.headers.get("X-Razorpay-Signature")
    if not signature:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Razorpay-Signature header."
        )

    raw_body = await request.body()
    
    expected_signature = hmac.new(
        key=WEBHOOK_SECRET.encode("utf-8"),
        msg=raw_body,
        digestmod=hashlib.sha256
    ).hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook signature. HMAC mismatch detected."
        )

    telemetry_counters["valid_signatures"] += 1
    return raw_body


async def _is_duplicate_event(event_id: str) -> bool:
    """Checks whether an event ID has already been processed."""
    if redis_client:
        return await redis_client.exists(f"idempotency:{event_id}") == 1
    return event_id in local_idempotency_cache


async def _mark_event_processed(event_id: str):
    """Registers an event ID in idempotency storage after successful processing."""
    if redis_client:
        await redis_client.set(
            f"idempotency:{event_id}", "PROCESSED", ex=IDEMPOTENCY_TTL_SECONDS
        )
    else:
        local_idempotency_cache.add(event_id)


@app.post("/api/v1/webhooks/razorpay", response_model=WebhookResponse)
async def handle_razorpay_webhook(
    request: Request,
    raw_body: bytes = Depends(verify_raw_hmac_signature)
):
    """Inbound Webhook Endpoint executing signature checks, idempotency, and state machine routing."""
    event_id = request.headers.get("X-Razorpay-Event-Id")
    if not event_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing X-Razorpay-Event-Id header."
        )

    # 1. Check Idempotency Gate
    if await _is_duplicate_event(event_id):
        telemetry_counters["duplicate_events_skipped"] += 1
        return WebhookResponse(
            status="SKIPPED_DUPLICATE",
            event_id=event_id,
            message="Event previously processed by Idempotency Gate.",
            processed_at_ms=int(time.time() * 1000)
        )

    # 2. Parse raw bytes into JSON payload dynamically
    try:
        json_payload = json.loads(raw_body.decode("utf-8"))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON body in webhook payload."
        )

    # Extract payment fields (supports flat JSON or nested Razorpay entity wrapper)
    entity = json_payload.get("payload", {}).get("payment", {}).get("entity", json_payload)
    amount = entity.get("amount", 250000)
    velocity_count = entity.get("velocity_count", 1)
    blacklisted_ip = entity.get("blacklisted_ip", False)

    # 3. Execute State Graph Workflow
    initial_state: FinancialOSState = {
        "transaction_id": f"tx_{event_id}",
        "input_payload": {
            "amount": amount, 
            "velocity_count": velocity_count, 
            "blacklisted_ip": blacklisted_ip
        },
        "planner_instructions": [],
        "reasoner_outputs": [],
        "validated_outputs": [],
        "consensus_result": None,
        "policy_result": None,
        "final_decision_fingerprint": None,
        "execution_start_time": time.time(),
        "errors": []
    }

    graph_output = await graph_app.ainvoke(initial_state)
    fp = graph_output["final_decision_fingerprint"]
    consensus = graph_output["consensus_result"]
    policy = graph_output["policy_result"]

    resolved_action = resolve_final_action(consensus, policy)
    if policy and policy.override_action:
        telemetry_counters["policy_overrides_enforced"] += 1

    # 4. Commit Idempotency Key AFTER Successful Execution
    await _mark_event_processed(event_id)

    # 5. Record checkpoint for time-travel replay engine
    replay_engine_instance.record_checkpoint(
        decision_id=fp.decision_id,
        transaction_id=f"tx_{event_id}",
        payload=initial_state["input_payload"],
        risk_score=consensus.consensus_risk_score,
        action=resolved_action,
        latency_ms=fp.latency_ms
    )

    return WebhookResponse(
        status="ACCEPTED",
        event_id=event_id,
        message="Webhook signature verified and processed by Financial OS Graph.",
        decision_summary={
            "decision_id": fp.decision_id,
            "action": resolved_action,
            "consensus_confidence": consensus.consensus_confidence,
            "policy_passed": policy.passed,
            "hash_signature": fp.hash_signature,
            "latency_ms": fp.latency_ms
        },
        processed_at_ms=int(time.time() * 1000)
    )


@app.get("/api/v1/decisions/{decision_id}/replay", response_model=DecisionReplayTimeline)
async def get_decision_replay(decision_id: str):
    """Time-Travel Replay Endpoint: Returns step-by-step state graph execution steps."""
    return await replay_engine_instance.get_replay_timeline(decision_id)


@app.post("/api/v1/decisions/counterfactual", response_model=CounterfactualDelta)
async def run_counterfactual_analysis(req: CounterfactualRequest):
    """Counterfactual Sandbox Endpoint: Executes parameter perturbation simulation."""
    return await replay_engine_instance.calculate_counterfactual(req)


@app.get("/api/v1/metrics/telemetry")
async def get_engineering_telemetry():
    """Internal Engineering Metrics Console Endpoint exposing live execution counters."""
    return {
        "system_status": "HEALTHY",
        "active_graph_nodes": 8,
        "total_requests": telemetry_counters["total_requests"],
        "valid_signatures": telemetry_counters["valid_signatures"],
        "duplicate_events_skipped": telemetry_counters["duplicate_events_skipped"],
        "policy_overrides_enforced": telemetry_counters["policy_overrides_enforced"],
        "active_checkpoints": len(replay_engine_instance._checkpoints)
    }
