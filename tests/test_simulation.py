"""
Integration Tests for Synthetic Load & Threat Injection Simulator.
"""

import pytest
from src.simulation.chaos_simulator import ChaosSimulator


@pytest.mark.asyncio
async def test_chaos_simulation_engine():
    sim = ChaosSimulator()
    metrics = await sim.run_batch_simulation(batch_size=20, inject_chaos=True)
    
    assert metrics.total_transactions_processed == 20
    assert metrics.successful_executions == 20
    assert metrics.chaos_injection_blocks == 4
    assert metrics.unanimous_consensus_agreements >= 0
    assert metrics.avg_latency_ms > 0
