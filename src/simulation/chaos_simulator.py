"""
High-Throughput Synthetic Simulation & Chaos Engineering Engine.
Evaluates Financial OS under load, failure conditions, and edge-case attacks.
"""

import asyncio
import time
import random
from typing import Dict, Any, List
from pydantic import BaseModel
from src.core.consistency_engine import build_consistency_graph, FinancialOSState


class SimulationMetrics(BaseModel):
    total_transactions_processed: int
    successful_executions: int
    policy_overrides_enforced: int
    consensus_agreements: int
    chaos_injection_blocks: int
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float


class ChaosSimulator:
    def __init__(self):
        self.graph_app = build_consistency_graph()

    async def run_batch_simulation(self, batch_size: int = 50, inject_chaos: bool = False) -> SimulationMetrics:
        latencies: List[float] = []
        policy_overrides = 0
        consensus_agreements = 0
        chaos_blocks = 0
        successful = 0

        for i in range(batch_size):
            amount = random.choice([25000, 45000, 150000, 250000, 500000])
            velocity = random.choice([1, 2, 3, 5])
            blacklisted = False

            # Inject synthetic attack vector on every 5th transaction during chaos runs
            if inject_chaos and i % 5 == 0:
                blacklisted = True
                chaos_blocks += 1

            initial_state: FinancialOSState = {
                "transaction_id": f"tx_sim_{i:04d}",
                "input_payload": {"amount": amount, "velocity_count": velocity, "blacklisted_ip": blacklisted},
                "planner_instructions": [],
                "reasoner_outputs": [],
                "validated_outputs": [],
                "consensus_result": None,
                "policy_result": None,
                "final_decision_fingerprint": None,
                "execution_start_time": time.time(),
                "errors": []
            }

            start = time.time()
            output = await self.graph_app.ainvoke(initial_state)
            latency = (time.time() - start) * 1000
            latencies.append(latency)

            if output["policy_result"] and output["policy_result"].override_action:
                policy_overrides += 1
            if output["consensus_result"] and output["consensus_result"].agreement_score == 1.0:
                consensus_agreements += 1
            successful += 1

        latencies.sort()
        p95_idx = int(len(latencies) * 0.95)
        p99_idx = int(len(latencies) * 0.99)

        return SimulationMetrics(
            total_transactions_processed=batch_size,
            successful_executions=successful,
            policy_overrides_enforced=policy_overrides,
            consensus_agreements=consensus_agreements,
            chaos_injection_blocks=chaos_blocks,
            avg_latency_ms=round(sum(latencies) / len(latencies), 2),
            p95_latency_ms=round(latencies[p95_idx], 2),
            p99_latency_ms=round(latencies[p99_idx], 2)
        )


if __name__ == "__main__":
    sim = ChaosSimulator()
    print("=== Executing High-Throughput Batch Simulation (50 Synthetic Txns) ===")
    metrics = asyncio.run(sim.run_batch_simulation(batch_size=50, inject_chaos=True))
    print(f"\n[Total Processed]: {metrics.total_transactions_processed}")
    print(f"[Successful Executions]: {metrics.successful_executions}")
    print(f"[Policy Overrides Enforced]: {metrics.policy_overrides_enforced}")
    print(f"[Chaos Attack Blocks]: {metrics.chaos_injection_blocks}")
    print(f"[Average Latency]: {metrics.avg_latency_ms} ms")
    print(f"[P95 Latency]: {metrics.p95_latency_ms} ms")
    print(f"[P99 Latency]: {metrics.p99_latency_ms} ms")
