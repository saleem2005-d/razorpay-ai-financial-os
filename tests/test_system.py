"""
Integration Tests for Razorpay AI Financial Operating System.
"""

import pytest
from src.core.consistency_engine import build_consistency_graph, FinancialOSState
from src.core.schemas import ActionType


@pytest.mark.asyncio
async def test_multi_agent_consistency_engine():
    app = build_consistency_graph()
    
    test_state: FinancialOSState = {
        "transaction_id": "tx_pytest_001",
        "input_payload": {"amount": 250000, "velocity_count": 1, "blacklisted_ip": False},
        "planner_instructions": [],
        "reasoner_outputs": [],
        "validated_outputs": [],
        "consensus_result": None,
        "policy_result": None,
        "final_decision_fingerprint": None,
        "execution_start_time": 0.0,
        "errors": []
    }

    output = await app.ainvoke(test_state)
    
    assert output["consensus_result"] is not None
    assert output["policy_result"] is not None
    assert output["final_decision_fingerprint"] is not None
    
    # Assert AI consensus voted APPROVE on clean transaction
    assert output["consensus_result"].final_action == ActionType.APPROVE
    
    # Assert Policy Gate intercepted AI approval and forced STEP_UP_AUTH due to limit > 200,000
    assert output["policy_result"].passed is False
    assert output["policy_result"].override_action == ActionType.STEP_UP_AUTH
    assert len(output["final_decision_fingerprint"].hash_signature) == 64
