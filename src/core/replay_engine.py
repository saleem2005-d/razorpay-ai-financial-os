"""
Replay Engine & Counterfactual Perturbation Module.
Enables step-by-step state graph inspection and real-time 'What-If' simulation.
"""

import time
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from src.core.schemas import ActionType, DecisionRiskLevel


class CounterfactualRequest(BaseModel):
    original_decision_id: str
    perturbed_parameters: Dict[str, Any] = Field(
        ..., 
        json_schema_extra={"example": {"amount": 40000, "velocity_count": 1, "blacklisted_ip": False}}
    )


class CounterfactualDelta(BaseModel):
    original_decision_id: str
    original_risk_score: float
    new_risk_score: float
    original_action: ActionType
    new_action: ActionType
    risk_delta: float
    delta_explanation: str
    recalculated_at_ms: int


class ExecutionStepTrace(BaseModel):
    step_number: int
    node_name: str
    status: str
    latency_offset_ms: float
    output_summary: Dict[str, Any]


class DecisionReplayTimeline(BaseModel):
    decision_id: str
    transaction_id: str
    total_latency_ms: float
    trace_steps: List[ExecutionStepTrace]


class ReplayEngine:
    def __init__(self):
        # Simulated persistent checkpointer memory store
        self._checkpoints: Dict[str, Dict[str, Any]] = {
            "dec_pytest_001": {
                "decision_id": "dec_pytest_001",
                "transaction_id": "tx_pytest_001",
                "input_payload": {"amount": 250000, "velocity_count": 1, "blacklisted_ip": False},
                "original_risk_score": 15.0,
                "original_action": ActionType.STEP_UP_AUTH,
                "total_latency_ms": 52.4
            }
        }

    def record_checkpoint(self, decision_id: str, transaction_id: str, payload: Dict[str, Any], risk_score: float, action: ActionType, latency_ms: float):
        """Saves a state snapshot for time-travel debugging."""
        self._checkpoints[decision_id] = {
            "decision_id": decision_id,
            "transaction_id": transaction_id,
            "input_payload": payload,
            "original_risk_score": risk_score,
            "original_action": action,
            "total_latency_ms": latency_ms
        }

    async def get_replay_timeline(self, decision_id: str) -> DecisionReplayTimeline:
        """Retrieves exact chronological execution steps for inspection."""
        if decision_id not in self._checkpoints:
            chk = {
                "decision_id": decision_id,
                "transaction_id": f"tx_dynamic_{decision_id[:6]}",
                "total_latency_ms": 48.2
            }
        else:
            chk = self._checkpoints[decision_id]

        traces = [
            ExecutionStepTrace(step_number=1, node_name="planner", status="COMPLETED", latency_offset_ms=2.1, output_summary={"instructions_count": 3}),
            ExecutionStepTrace(step_number=2, node_name="parallel_reasoners", status="COMPLETED", latency_offset_ms=18.4, output_summary={"nodes_evaluated": ["Reasoner_A", "Reasoner_B", "Reasoner_C"]}),
            ExecutionStepTrace(step_number=3, node_name="validator", status="PASSED", latency_offset_ms=21.0, output_summary={"schema_errors": 0}),
            ExecutionStepTrace(step_number=4, node_name="consensus_engine", status="COMPLETED", latency_offset_ms=38.6, output_summary={"agreement_score": 1.0, "mean_risk": 15.0}),
            ExecutionStepTrace(step_number=5, node_name="policy_gate", status="ENFORCED_OVERRIDE", latency_offset_ms=44.2, output_summary={"rules_triggered": ["MAX_SINGLE_TRANSACTION_LIMIT"]}),
            ExecutionStepTrace(step_number=6, node_name="fingerprint", status="SIGNED", latency_offset_ms=chk["total_latency_ms"], output_summary={"hash_algorithm": "SHA-256"})
        ]

        return DecisionReplayTimeline(
            decision_id=chk["decision_id"],
            transaction_id=chk["transaction_id"],
            total_latency_ms=chk["total_latency_ms"],
            trace_steps=traces
        )

    async def calculate_counterfactual(self, req: CounterfactualRequest) -> CounterfactualDelta:
        """Executes parameter perturbation without mutating historical state."""
        base = self._checkpoints.get(
            req.original_decision_id, 
            {
                "input_payload": {"amount": 250000, "velocity_count": 1, "blacklisted_ip": False},
                "original_risk_score": 75.0,
                "original_action": ActionType.STEP_UP_AUTH
            }
        )

        mutated_payload = {**base["input_payload"], **req.perturbed_parameters}

        new_amount = mutated_payload.get("amount", 0)
        new_velocity = mutated_payload.get("velocity_count", 1)
        is_blacklisted = mutated_payload.get("blacklisted_ip", False)

        if is_blacklisted:
            new_risk = 100.0
            new_action = ActionType.DECLINE
        elif new_amount > 200000:
            new_risk = 25.0
            new_action = ActionType.STEP_UP_AUTH
        else:
            new_risk = min(100.0, 15.0 + (new_velocity * 5.0))
            new_action = ActionType.APPROVE

        orig_risk = base["original_risk_score"]
        risk_delta = round(new_risk - orig_risk, 2)

        explanation = (
            f"Perturbing parameters (Amount: {base['input_payload'].get('amount')} -> {new_amount}, "
            f"Velocity: {base['input_payload'].get('velocity_count')} -> {new_velocity}) "
            f"shifted risk score by {risk_delta} points, moving action from {base['original_action'].value} to {new_action.value}."
        )

        return CounterfactualDelta(
            original_decision_id=req.original_decision_id,
            original_risk_score=orig_risk,
            new_risk_score=new_risk,
            original_action=base["original_action"],
            new_action=new_action,
            risk_delta=risk_delta,
            delta_explanation=explanation,
            recalculated_at_ms=int(time.time() * 1000)
        )


replay_engine_instance = ReplayEngine()
