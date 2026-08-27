import hmac
import hashlib
import time
from typing import Dict, Any, Optional
from fastapi import FastAPI, Header, HTTPException, Request, Response, status
from pydantic import BaseModel

app = FastAPI(
    title="SentinelAI - Financial Risk Engine",
    description="Deterministic AI Risk & Webhook Gateway for Razorpay",
    version="1.0.0"
)

WEBHOOK_SECRET = "test_webhook_secret_key_123"

# In-memory storage for testing/idempotency/audit ledger
IDEMPOTENCY_CACHE: Dict[str, Dict[str, Any]] = {}
AUDIT_LEDGER: Dict[str, Dict[str, Any]] = {}

@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "version": "1.0.0",
        "subsystems": {
            "gateway": "online",
            "idempotency_engine": "online",
            "state_graph": "ready",
            "audit_ledger": "ready"
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

def generate_decision_fingerprint(event_id: str, amount: float, status: str, risk_score: float) -> str:
    raw_fingerprint_data = f"{event_id}:{amount}:{status}:{risk_score}"
    return hashlib.sha256(raw_fingerprint_data.encode("utf-8")).hexdigest()

@app.post("/api/v1/webhooks/razorpay")
async def ingest_razorpay_webhook(
    request: Request,
    x_razorpay_signature: Optional[str] = Header(None, alias="X-Razorpay-Signature"),
    x_razorpay_event_id: Optional[str] = Header(None, alias="X-Razorpay-Event-Id")
):
    raw_body = await request.body()

    # 1. HMAC Signature Verification Gate
    if not verify_hmac_signature(raw_body, x_razorpay_signature, WEBHOOK_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid HMAC SHA-256 signature."
        )

    try:
        payload = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    event_id = x_razorpay_event_id or payload.get("event_id", f"evt_{int(time.time()*1000)}")

    # 2. Redis / Idempotency Check (Replay Attack Defense)
    if event_id in IDEMPOTENCY_CACHE:
        return {
            "status": "duplicate",
            "idempotent": True,
            "message": "Event already processed and locked.",
            "original_result": IDEMPOTENCY_CACHE[event_id]
        }

    # 3. State & Risk Evaluation
    payment_entity = payload.get("payload", {}).get("payment", {}).get("entity", {})
    amount = float(payment_entity.get("amount", 0)) / 100.0

    # Risk Scoring Rule / Policy Gate
    risk_score = 0.02
    decision = "ALLOW"
    if amount > 100000:
        risk_score = 0.85
        decision = "MANUAL_REVIEW"

    # 4. Cryptographic Decision Fingerprint & Audit Trail
    fingerprint_hash = generate_decision_fingerprint(event_id, amount, decision, risk_score)

    audit_entry = {
        "event_id": event_id,
        "amount": amount,
        "risk_score": risk_score,
        "rule_verdict": decision,
        "fingerprint_hash": fingerprint_hash,
        "is_immutable": True,
        "timestamp": time.time()
    }

    # Store state
    AUDIT_LEDGER[event_id] = audit_entry
    IDEMPOTENCY_CACHE[event_id] = audit_entry

    return {
        "status": "approved" if decision == "ALLOW" else "flagged",
        "idempotent": False,
        "risk_score": risk_score,
        "decision": decision,
        "fingerprint": fingerprint_hash
    }

@app.get("/api/v1/audit/fingerprint/{event_id}")
def get_audit_trail(event_id: str):
    if event_id not in AUDIT_LEDGER:
        raise HTTPException(status_code=404, detail="Audit log not found for this event ID.")
    return AUDIT_LEDGER[event_id]
