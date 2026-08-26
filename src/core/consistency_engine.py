"""
Multi-Agent Consistency Engine & LangGraph State Machine.

Architecture:
  User Request -> Planner -> Parallel Reasoners (A, B, C) -> Schema Validator 
  -> Consensus Engine -> Deterministic Policy Gate -> Fingerprint Generator -> State Persistence
"""

import asyncio
import numpy as np
import time
from typing import Dict, List, Any, TypedDict, Annotated, Optional
import operator

from langgraph.graph import StateGraph, END
from pydantic import ValidationError

from src.core.schemas import (
    ReasonerOutput, ActionType, ConsensusResult, PolicyCheckResult,
    DecisionFingerprint, DecisionRiskLevel
)


class FinancialOSState(TypedDict):
    """Central shared state dictionary passed across all LangGraph nodes."""
    transaction_id: str
    input_payload: Dict[str, Any]
    planner_instructions: List[str]
    reasoner_outputs: Annotated[List[ReasonerOutput], operator.add]
    validated_outputs: List[ReasonerOutput]
    consensus_result: Optional[ConsensusResult]
    policy_result: Optional[PolicyCheckResult]
    final_decision_fingerprint: Optional[DecisionFingerprint]
    execution_start_time: float
    errors: List[str]


def resolve_final_action(
    consensus: ConsensusResult,
    policy: PolicyCheckResult
) -> ActionType:
    """
    Resolves the definitive transaction action.
    Deterministic policy enforcement overrides probabilistic AI consensus.
    """
    if policy and policy.override_action:
        return policy.override_action
    return consensus.final_action


async def planner_node(state: FinancialOSState) -> Dict[str, Any]:
    """Inbound Planner: Decomposes transaction payload and prepares parallel evaluation paths."""
    payload = state["input_payload"]
    amount = payload.get("amount", 0)
    velocity = payload.get("velocity_count", 0)
    
    instructions = [
        f"Analyze payment risk for transaction amount {amount}.",
        f"Evaluate transaction velocity count ({velocity}) and IP blacklist status.",
        "Propose candidate action and bounded risk score."
    ]
    return {
        "planner_instructions": instructions,
        "execution_start_time": time.time(),
        "reasoner_outputs": []
    }


async def _simulate_llm_reasoner(
    reasoner_id: str, 
    temperature: float, 
    payload: Dict[str, Any]
) -> ReasonerOutput:
    """
    High-throughput simulation provider for the reasoner interface.

    This benchmark implementation generates structured ReasonerOutput
    objects using a local risk-distribution model. Its schema mirrors the
    structured output expected from a live LLM provider, allowing the
    orchestration, validation, consensus, policy, and audit layers to be
    benchmarked deterministically without external inference cost.

    This function is a synthetic simulation provider, not a live LLM API call.
    """
    await asyncio.sleep(0.05)
    amount = payload.get("amount", 0)
    velocity = payload.get("velocity_count", 0)

    noise = np.random.normal(0, temperature * 2.0)
    base_risk = 15.0 if velocity <= 2 else 70.0
    calculated_risk = min(100.0, max(0.0, base_risk + (velocity * 5.0) + noise))

    action = ActionType.APPROVE
    if calculated_risk > 70.0:
        action = ActionType.STEP_UP_AUTH if calculated_risk < 90.0 else ActionType.DECLINE

    return ReasonerOutput(
        reasoner_id=reasoner_id,
        action=action,
        risk_score=round(float(calculated_risk), 2),
        confidence=round(float(1.0 - (temperature * 0.2)), 2),
        reasoning_steps=[
            f"Evaluated amount {amount} with velocity {velocity}.",
            f"Calculated base risk {base_risk} with temperature variance {round(float(noise), 2)}.",
            f"Selected action {action.value}."
        ],
        recommended_parameters={"retry_allowed": action != ActionType.DECLINE}
    )


async def reasoner_a_node(state: FinancialOSState) -> Dict[str, Any]:
    """Reasoner A: Synthetic Conservative Path (Temperature = 0.0)"""
    res = await _simulate_llm_reasoner("Reasoner_A_Conservative", 0.0, state["input_payload"])
    return {"reasoner_outputs": [res]}


async def reasoner_b_node(state: FinancialOSState) -> Dict[str, Any]:
    """Reasoner B: Synthetic Balanced Path (Temperature = 0.2)"""
    res = await _simulate_llm_reasoner("Reasoner_B_Balanced", 0.2, state["input_payload"])
    return {"reasoner_outputs": [res]}


async def reasoner_c_node(state: FinancialOSState) -> Dict[str, Any]:
    """Reasoner C: Synthetic Adversarial Path (Temperature = 0.4)"""
    res = await _simulate_llm_reasoner("Reasoner_C_Adversarial", 0.4, state["input_payload"])
    return {"reasoner_outputs": [res]}


async def validator_node(state: FinancialOSState) -> Dict[str, Any]:
    """Validator Node: Parses and filters malformed outputs against schema boundaries."""
    raw_outputs = state.get("reasoner_outputs", [])
    validated = []
    errors = []

    for output in raw_outputs:
        if isinstance(output, ReasonerOutput):
            validated.append(output)
        else:
            try:
                parsed = ReasonerOutput.model_validate(output)
                validated.append(parsed)
            except ValidationError as e:
                errors.append(f"Validation failed for node output: {str(e)}")

    return {"validated_outputs": validated, "errors": errors}


async def consensus_engine_node(state: FinancialOSState) -> Dict[str, Any]:
    """Consensus Engine Node: Calculates majority consensus ratio across parallel reasoners."""
    outputs = state.get("validated_outputs", [])
    if not outputs:
        raise ValueError("Consensus Engine received zero validated reasoner outputs.")

    actions = [o.action for o in outputs]
    risk_scores = [o.risk_score for o in outputs]

    action_counts = {}
    for act in actions:
        action_counts[act] = action_counts.get(act, 0) + 1
    majority_action = max(action_counts, key=action_counts.get)

    agreement_score = round(action_counts[majority_action] / len(actions), 2)
    risk_variance = float(np.var(risk_scores)) if len(risk_scores) > 1 else 0.0
    mean_risk = float(np.mean(risk_scores))

    alpha = 0.6
    std_dev_risk = float(np.std(risk_scores))
    confidence_score = round((alpha * agreement_score) + ((1.0 - alpha) * max(0.0, 1.0 - (std_dev_risk / 50.0))), 2)

    disagreements = []
    if agreement_score < 1.0:
        for o in outputs:
            if o.action != majority_action:
                disagreements.append(f"{o.reasoner_id} dissented with action {o.action.value} (Risk: {o.risk_score})")

    consensus = ConsensusResult(
        final_action=majority_action,
        consensus_risk_score=round(mean_risk, 2),
        consensus_confidence=confidence_score,
        agreement_score=agreement_score,
        risk_variance=round(risk_variance, 2),
        disagreements=disagreements
    )

    return {"consensus_result": consensus}


async def policy_gate_node(state: FinancialOSState) -> Dict[str, Any]:
    """Deterministic Policy Gate: Overrides AI consensus if hard constraints are violated."""
    payload = state["input_payload"]
    consensus = state["consensus_result"]
    amount = payload.get("amount", 0)
    is_blacklisted = payload.get("blacklisted_ip", False)

    rules_evaluated = ["MAX_SINGLE_TRANSACTION_LIMIT", "BLACKLISTED_IP_CHECK"]
    rules_triggered = []
    override_action = None
    override_reason = None

    if is_blacklisted:
        rules_triggered.append("BLACKLISTED_IP_CHECK")
        override_action = ActionType.DECLINE
        override_reason = "Hard Policy Enforcement: IP address matches global ban list."

    elif amount > 200000 and consensus.final_action == ActionType.APPROVE:
        rules_triggered.append("MAX_SINGLE_TRANSACTION_LIMIT")
        override_action = ActionType.STEP_UP_AUTH
        override_reason = "Hard Policy Enforcement: Transactions > 200,000 require manual MFA step-up."

    passed = len(rules_triggered) == 0
    policy_res = PolicyCheckResult(
        passed=passed,
        rules_evaluated=rules_evaluated,
        rules_triggered=rules_triggered,
        override_action=override_action,
        override_reason=override_reason
    )

    return {"policy_result": policy_res}


async def fingerprint_node(state: FinancialOSState) -> Dict[str, Any]:
    """Decision Fingerprint Generator: Emits an immutable, signed SHA-256 decision fingerprint."""
    consensus = state["consensus_result"]
    policy = state["policy_result"]
    start_time = state.get("execution_start_time", time.time())
    latency_ms = round((time.time() - start_time) * 1000, 2)

    final_action = resolve_final_action(consensus, policy)

    risk_level = DecisionRiskLevel.LOW
    if consensus.consensus_risk_score > 80.0:
        risk_level = DecisionRiskLevel.CRITICAL
    elif consensus.consensus_risk_score > 50.0:
        risk_level = DecisionRiskLevel.HIGH
    elif consensus.consensus_risk_score > 25.0:
        risk_level = DecisionRiskLevel.MEDIUM

    fingerprint = DecisionFingerprint(
        model_versions={
            "execution_mode": "SIMULATION",
            "Reasoner_A": "simulation-driver-v1-temperature-0.0",
            "Reasoner_B": "simulation-driver-v1-temperature-0.2",
            "Reasoner_C": "simulation-driver-v1-temperature-0.4"
        },
        confidence_score=consensus.consensus_confidence,
        rules_triggered=policy.rules_triggered,
        evidence_used=[
            f"txn_id:{state['transaction_id']}", 
            f"risk_var:{consensus.risk_variance}",
            f"resolved_action:{final_action.value}"
        ],
        risk_level=risk_level,
        validation_status=policy.passed,
        latency_ms=latency_ms
    )
    fingerprint.hash_signature = fingerprint.generate_signature()

    return {"final_decision_fingerprint": fingerprint}


def build_consistency_graph() -> StateGraph:
    """Assembles the parallel multi-agent graph layout."""
    workflow = StateGraph(FinancialOSState)

    workflow.add_node("planner", planner_node)
    workflow.add_node("reasoner_a", reasoner_a_node)
    workflow.add_node("reasoner_b", reasoner_b_node)
    workflow.add_node("reasoner_c", reasoner_c_node)
    workflow.add_node("validator", validator_node)
    workflow.add_node("consensus", consensus_engine_node)
    workflow.add_node("policy_gate", policy_gate_node)
    workflow.add_node("fingerprint", fingerprint_node)

    workflow.set_entry_point("planner")

    workflow.add_edge("planner", "reasoner_a")
    workflow.add_edge("planner", "reasoner_b")
    workflow.add_edge("planner", "reasoner_c")

    workflow.add_edge("reasoner_a", "validator")
    workflow.add_edge("reasoner_b", "validator")
    workflow.add_edge("reasoner_c", "validator")

    workflow.add_edge("validator", "consensus")
    workflow.add_edge("consensus", "policy_gate")
    workflow.add_edge("policy_gate", "fingerprint")
    workflow.add_edge("fingerprint", END)

    return workflow.compile()


if __name__ == "__main__":
    app = build_consistency_graph()

    test_state: FinancialOSState = {
        "transaction_id": "tx_test_998822",
        "input_payload": {
            "amount": 250000,
            "velocity_count": 1,
            "blacklisted_ip": False
        },
        "planner_instructions": [],
        "reasoner_outputs": [],
        "validated_outputs": [],
        "consensus_result": None,
        "policy_result": None,
        "final_decision_fingerprint": None,
        "execution_start_time": 0.0,
        "errors": []
    }

    async def run_test():
        print("=== Executing Multi-Agent Consistency Engine ===")
        final_output = await app.ainvoke(test_state)
        
        consensus = final_output["consensus_result"]
        policy = final_output["policy_result"]
        fp = final_output["final_decision_fingerprint"]
        resolved_action = resolve_final_action(consensus, policy)

        print(f"\n[Consensus Candidate Action]: {consensus.final_action.value}")
        print(f"[Majority Consensus Ratio]: {consensus.agreement_score * 100}%")
        print(f"[Policy Passed]: {policy.passed}")
        print(f"[Resolved Final Action]: {resolved_action.value}")
        if policy.override_action:
            print(f"[Policy Override Reason]: {policy.override_reason}")
        print(f"\n[Execution Mode]: {fp.model_versions.get('execution_mode')}")
        print(f"[Decision Fingerprint Hash]: {fp.hash_signature}")
        print(f"[Latency]: {fp.latency_ms} ms")

    asyncio.run(run_test())
