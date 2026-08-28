import os
import hmac
import hashlib
import time
import asyncio
from typing import Dict, Any, Optional, List
from fastapi import FastAPI, Header, HTTPException, Request, status
from pydantic import BaseModel, Field

app = FastAPI(
    title="SentinelAI - Webhook Risk Verifier",
    description="Defense-only payment risk verifier with raw-byte HMAC-SHA256 authentication, process-local duplicate event protection, sliding-window velocity tracking, and SHA-256 decision fingerprinting.",
    version="1.0.0"
)

WEBHOOK_SECRET = os.getenv("RAZORPAY_WEBHOOK_SECRET", "test_webhook_secret_key_123")
RISK_REVIEW_THRESHOLD_RUPEES = float(os.getenv("RISK_REVIEW_THRESHOLD_RUPEES", "100000.0"))
VELOCITY_REVIEW_THRESHOLD = int(os.getenv("VELOCITY_REVIEW_THRESHOLD", "4"))
VELOCITY_WINDOW_SECONDS = 60.0

# In-memory process-local state
IDEMPOTENCY_CACHE: Dict[str, Dict[str, Any]] = {}
AUDIT_STORE: Dict[str, Dict[str, Any]] = {}
VELOCITY_STORE: Dict[str, List[float]] = {}
BLACKLIST_STORE = {
    "acc_synthetic_blacklisted",
    "acc_fraud_entity_99",
    "acc_chargeback_ring_01"
}

STATE_LOCK = asyncio.Lock()

def reset_system_state():
    """Flushes all in-memory cache, audit, and velocity stores for isolated evaluation."""
    IDEMPOTENCY_CACHE.clear()
    AUDIT_STORE.clear()
    VELOCITY_STORE.clear()

class PaymentEntity(BaseModel):
    id: str
    amount: int = Field(..., description="Amount in paise")
    currency: str = "INR"
    status: Optional[str] = "captured"
    method: Optional[str] = "upi"

class PaymentContainer(BaseModel):
    entity: PaymentEntity

class WebhookPayloadDetails(BaseModel):
    payment: PaymentContainer

class SupportedPaymentCapturedEvent(BaseModel):
    event: str
    account_id: Optional[str] = "acc_default"
    event_id: Optional[str] = None
    created_at: Optional[float] = None
    payload: WebhookPayloadDetails

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "subsystems": {
            "gateway": "online",
            "idempotency_cache": "in-memory-locked",
            "velocity_tracker": "sliding-window-60s",
            "policy_gate": "multi-signal-rule-based",
            "audit_store": "in-memory-fingerprinted"
        },
        "config": {
            "risk_review_threshold_rupees": RISK_REVIEW_THRESHOLD_RUPEES,
            "velocity_review_threshold": VELOCITY_REVIEW_THRESHOLD
        }
    }

def verify_hmac_signature(raw_body: bytes, signature: Optional[str], secret: str) -> bool:
    if not signature:
        return False
    expected_sig = hmac.new(
        secret.encode("utf-8"),
        raw_body,
        hashlib.sha256
    ).hexdigest()
    return hmac.compare_digest(expected_sig, signature)

def generate_decision_fingerprint(event_id: str, account_id: str, amount_rupees: float, verdict: str, rule: str, risk_score: float) -> str:
    raw_fingerprint_data = f"{event_id}:{account_id}:{amount_rupees}:{verdict}:{rule}:{risk_score}"
    return hashlib.sha256(raw_fingerprint_data.encode("utf-8")).hexdigest()

@app.post("/api/v1/webhooks/razorpay")
async def ingest_razorpay_webhook(
    request: Request,
    x_razorpay_signature: Optional[str] = Header(None, alias="X-Razorpay-Signature"),
    x_razorpay_event_id: Optional[str] = Header(None, alias="X-Razorpay-Event-Id")
):
    raw_body = await request.body()

    # 1. Raw-body HMAC-SHA256 Verification Gate
    if not verify_hmac_signature(raw_body, x_razorpay_signature, WEBHOOK_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing HMAC SHA-256 signature."
        )

    # 2. Strict JSON and Schema Validation
    try:
        json_data = await request.json()
        event_obj = SupportedPaymentCapturedEvent.model_validate(json_data)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Malformed JSON or invalid schema: {str(e)}"
        )

    # 3. Explicit Event ID Requirement
    event_id = x_razorpay_event_id or event_obj.event_id
    if not event_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Missing required event ID in header and payload."
        )

    account_id = event_obj.account_id or "acc_default"
    event_timestamp = event_obj.created_at or time.time()

    # 4. Atomic Check-and-Reserve & Sliding-Window Velocity Calculation
    async with STATE_LOCK:
        if event_id in IDEMPOTENCY_CACHE:
            cached_entry = IDEMPOTENCY_CACHE[event_id]
            return {
                "status": "duplicate",
                "idempotent": True,
                "message": "Duplicate event detected. Returned cached state.",
                "original_result": cached_entry
            }
        IDEMPOTENCY_CACHE[event_id] = {"status": "processing", "reserved_at": event_timestamp}

        # Sliding-window velocity tracking (inclusive 60s cutoff)
        cutoff = event_timestamp - VELOCITY_WINDOW_SECONDS
        recent_timestamps = [t for t in VELOCITY_STORE.get(account_id, []) if t >= cutoff]
        recent_timestamps.append(event_timestamp)
        VELOCITY_STORE[account_id] = recent_timestamps
        velocity_count = len(recent_timestamps)

    # 5. Deterministic Multi-Signal Risk Policy
    amount_rupees = float(event_obj.payload.payment.entity.amount) / 100.0

    if account_id in BLACKLIST_STORE:
        risk_score = 0.95
        verdict = "MANUAL_REVIEW"
        rule_triggered = "BLACKLIST_MATCH"
    elif velocity_count >= VELOCITY_REVIEW_THRESHOLD:
        risk_score = 0.85
        verdict = "MANUAL_REVIEW"
        rule_triggered = "VELOCITY_THRESHOLD_EXCEEDED"
    elif amount_rupees > RISK_REVIEW_THRESHOLD_RUPEES:
        risk_score = 0.70
        verdict = "MANUAL_REVIEW"
        rule_triggered = "HIGH_VALUE_THRESHOLD"
    else:
        risk_score = 0.02
        verdict = "ALLOW"
        rule_triggered = "BASELINE_CLEAN"

    # 6. SHA-256 Decision Fingerprinting & Audit Store Record
    fingerprint_hash = generate_decision_fingerprint(event_id, account_id, amount_rupees, verdict, rule_triggered, risk_score)

    audit_record = {
        "event_id": event_id,
        "account_id": account_id,
        "amount_rupees": amount_rupees,
        "velocity_count_1m": velocity_count,
        "risk_score": risk_score,
        "rule_verdict": verdict,
        "rule_triggered": rule_triggered,
        "fingerprint_hash": fingerprint_hash,
        "timestamp": event_timestamp
    }

    async with STATE_LOCK:
        IDEMPOTENCY_CACHE[event_id] = audit_record
        AUDIT_STORE[event_id] = audit_record

    return {
        "status": "approved" if verdict == "ALLOW" else "flagged",
        "idempotent": False,
        "risk_score": risk_score,
        "decision": verdict,
        "rule_triggered": rule_triggered,
        "velocity_count": velocity_count,
        "fingerprint": fingerprint_hash
    }

@app.get("/api/v1/audit/fingerprint/{event_id}")
def get_audit_trail(event_id: str):
    if event_id not in AUDIT_STORE:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit record not found for this event ID."
        )
    return AUDIT_STORE[event_id]

from fastapi.responses import HTMLResponse
import os

@app.get("/", response_class=HTMLResponse)
async def serve_dashboard():
    template_path = os.path.join(os.path.dirname(__file__), "templates", "index.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>SentinelAI API Running</h1>"
