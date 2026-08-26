"""
Typed Pydantic Schemas for AI Financial Operating System.
Guarantees strict boundary enforcement and schema validation across all agent nodes.
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
import time
import uuid
import hashlib
import json


class DecisionRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ActionType(str, Enum):
    APPROVE = "APPROVE"
    DECLINE = "DECLINE"
    STEP_UP_AUTH = "STEP_UP_AUTH"
    MANUAL_REVIEW = "MANUAL_REVIEW"
    RETRY_PAYMENT = "RETRY_PAYMENT"


class ReasonerOutput(BaseModel):
    """Output schema required from every individual LLM reasoner node."""
    reasoner_id: str = Field(..., description="Unique identifier of the reasoner node")
    action: ActionType = Field(..., description="Proposed transaction action")
    risk_score: float = Field(..., ge=0.0, le=100.0, description="Normalized risk score from 0 to 100")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Self-reported confidence level")
    reasoning_steps: List[str] = Field(..., min_length=1, description="Step-by-step logic trace")
    recommended_parameters: Dict[str, Any] = Field(default_factory=dict, description="Action arguments")


class ConsensusResult(BaseModel):
    """Aggregated output from the Consensus Engine comparing parallel reasoners."""
    final_action: ActionType
    consensus_risk_score: float
    consensus_confidence: float
    agreement_score: float = Field(..., ge=0.0, le=1.0, description="Jaccard/semantic similarity ratio")
    risk_variance: float = Field(..., description="Variance in risk scores across reasoners")
    disagreements: List[str] = Field(default_factory=list, description="Explicit points of logic divergence")


class PolicyCheckResult(BaseModel):
    """Result of deterministic financial policy checks executed post-consensus."""
    passed: bool
    rules_evaluated: List[str]
    rules_triggered: List[str]
    override_action: Optional[ActionType] = None
    override_reason: Optional[str] = None


class DecisionFingerprint(BaseModel):
    """Immutable, signed record of a financial decision for non-repudiable audit trails."""
    decision_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp_epoch_ms: int = Field(default_factory=lambda: int(time.time() * 1000))
    model_versions: Dict[str, str]
    confidence_score: float
    rules_triggered: List[str]
    evidence_used: List[str]
    risk_level: DecisionRiskLevel
    validation_status: bool
    latency_ms: float
    hash_signature: str = ""

    def generate_signature(self, secret_key: str = "RAZORPAY_BUILDATHON_SECRET") -> str:
        """Generates a cryptographic SHA-256 fingerprint hash of the decision context."""
        payload = {
            "decision_id": self.decision_id,
            "timestamp": self.timestamp_epoch_ms,
            "confidence": self.confidence_score,
            "rules": self.rules_triggered,
            "risk_level": self.risk_level.value,
            "validation_status": self.validation_status
        }
        raw_bytes = json.dumps(payload, sort_keys=True).encode("utf-8")
        return hashlib.sha256(raw_bytes + secret_key.encode("utf-8")).hexdigest()
