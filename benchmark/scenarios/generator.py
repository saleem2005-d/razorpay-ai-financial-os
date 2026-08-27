import json
import random
import hmac
import hashlib

RANDOM_SEED = 42
SECRET = "test_webhook_secret_key_123"

def get_hmac_sig(payload_str: str, secret: str = SECRET) -> str:
    return hmac.new(secret.encode("utf-8"), payload_str.encode("utf-8"), hashlib.sha256).hexdigest()

def generate_dataset(output_path: str = "benchmark/scenarios/evaluation_dataset.json"):
    random.seed(RANDOM_SEED)
    risk_scenarios = []
    base_time = 1700000000.0

    # Archetype 1: LEGITIMATE_CLEAN (N=100) - Spaced timestamps to prevent false velocity saturation
    for i in range(1, 101):
        amount_rupees = round(random.uniform(500.0, 75000.0), 2)
        evt_id = f"evt_syn_clean_{i:03d}"
        acc_id = f"acc_clean_merchant_{i % 20:02d}"
        pay_id = f"pay_clean_{i:03d}"
        # Advance timestamp by 120s to ensure clean window
        event_time = base_time + (i * 120.0)
        
        payload_dict = {
            "event": "payment.captured",
            "account_id": acc_id,
            "event_id": evt_id,
            "created_at": event_time,
            "payload": {
                "payment": {
                    "entity": {
                        "id": pay_id,
                        "amount": int(amount_rupees * 100),
                        "currency": "INR",
                        "status": "captured",
                        "method": "upi"
                    }
                }
            }
        }
        risk_scenarios.append({
            "scenario_id": f"risk_clean_{i:03d}",
            "archetype": "LEGITIMATE_CLEAN",
            "expected_risk_class": "LEGITIMATE",
            "truth_basis": "standard_low_risk_purchase",
            "account_id": acc_id,
            "amount_rupees": amount_rupees,
            "payload": payload_dict
        })
        
    # Archetype 2: LEGITIMATE_HIGH_VALUE (N=40) - Generates genuine False Positives at low thresholds
    for i in range(1, 41):
        amount_rupees = round(random.uniform(110000.0, 350000.0), 2)
        evt_id = f"evt_syn_highlegit_{i:03d}"
        acc_id = f"acc_verified_enterprise_{i % 5:02d}"
        pay_id = f"pay_highlegit_{i:03d}"
        event_time = base_time + 50000.0 + (i * 120.0)
        
        payload_dict = {
            "event": "payment.captured",
            "account_id": acc_id,
            "event_id": evt_id,
            "created_at": event_time,
            "payload": {
                "payment": {
                    "entity": {
                        "id": pay_id,
                        "amount": int(amount_rupees * 100),
                        "currency": "INR",
                        "status": "captured",
                        "method": "bank_transfer"
                    }
                }
            }
        }
        risk_scenarios.append({
            "scenario_id": f"risk_highlegit_{i:03d}",
            "archetype": "LEGITIMATE_HIGH_VALUE",
            "expected_risk_class": "LEGITIMATE",
            "truth_basis": "verified_merchant_high_ticket_order",
            "account_id": acc_id,
            "amount_rupees": amount_rupees,
            "payload": payload_dict
        })

    # Archetype 3: BLACKLISTED_ENTITY (N=30)
    for i in range(1, 31):
        amount_rupees = round(random.uniform(2000.0, 45000.0), 2)
        evt_id = f"evt_syn_blacklisted_{i:03d}"
        acc_id = "acc_synthetic_blacklisted" if i % 2 == 0 else "acc_fraud_entity_99"
        pay_id = f"pay_blacklisted_{i:03d}"
        event_time = base_time + 100000.0 + (i * 120.0)
        
        payload_dict = {
            "event": "payment.captured",
            "account_id": acc_id,
            "event_id": evt_id,
            "created_at": event_time,
            "payload": {
                "payment": {
                    "entity": {
                        "id": pay_id,
                        "amount": int(amount_rupees * 100),
                        "currency": "INR",
                        "status": "captured",
                        "method": "card"
                    }
                }
            }
        }
        risk_scenarios.append({
            "scenario_id": f"risk_blacklisted_{i:03d}",
            "archetype": "BLACKLISTED_ENTITY",
            "expected_risk_class": "HIGH_RISK",
            "truth_basis": "known_malicious_account_match",
            "account_id": acc_id,
            "amount_rupees": amount_rupees,
            "payload": payload_dict
        })

    # Archetype 4: HIGH_VELOCITY_ABUSE (N=30) - Clustered in 5-event bursts within 10 seconds
    for burst in range(6):
        burst_base = base_time + 200000.0 + (burst * 500.0)
        acc_id = f"acc_burst_attacker_{burst:02d}"
        for step in range(5):
            idx = (burst * 5) + step + 1
            amount_rupees = round(random.uniform(500.0, 15000.0), 2)
            evt_id = f"evt_syn_velocity_{idx:03d}"
            pay_id = f"pay_velocity_{idx:03d}"
            event_time = burst_base + (step * 2.0)  # 2s apart within 60s window
            
            payload_dict = {
                "event": "payment.captured",
                "account_id": acc_id,
                "event_id": evt_id,
                "created_at": event_time,
                "payload": {
                    "payment": {
                        "entity": {
                            "id": pay_id,
                            "amount": int(amount_rupees * 100),
                            "currency": "INR",
                            "status": "captured",
                            "method": "card"
                        }
                    }
                }
            }
            risk_scenarios.append({
                "scenario_id": f"risk_velocity_{idx:03d}",
                "archetype": "HIGH_VELOCITY_ABUSE",
                "expected_risk_class": "HIGH_RISK",
                "truth_basis": "card_testing_velocity_burst",
                "account_id": acc_id,
                "amount_rupees": amount_rupees,
                "payload": payload_dict
            })

    # Archetype 5: DISTRIBUTED_SUB_THRESHOLD_ABUSE (N=20) - Generates genuine False Negatives
    for i in range(1, 21):
        amount_rupees = round(random.uniform(1000.0, 18000.0), 2)
        evt_id = f"evt_syn_subthresh_{i:03d}"
        acc_id = f"acc_distributed_bot_{i:03d}"
        pay_id = f"pay_subthresh_{i:03d}"
        event_time = base_time + 300000.0 + (i * 120.0)
        
        payload_dict = {
            "event": "payment.captured",
            "account_id": acc_id,
            "event_id": evt_id,
            "created_at": event_time,
            "payload": {
                "payment": {
                    "entity": {
                        "id": pay_id,
                        "amount": int(amount_rupees * 100),
                        "currency": "INR",
                        "status": "captured",
                        "method": "upi"
                    }
                }
            }
        }
        risk_scenarios.append({
            "scenario_id": f"risk_subthresh_{i:03d}",
            "archetype": "DISTRIBUTED_SUB_THRESHOLD_ABUSE",
            "expected_risk_class": "HIGH_RISK",
            "truth_basis": "distributed_bot_sub_threshold_probe",
            "account_id": acc_id,
            "amount_rupees": amount_rupees,
            "payload": payload_dict
        })

    # Archetype 6: BORDERLINE_BOUNDARY (N=20)
    boundary_values = [
        (99900.0, "LEGITIMATE"), (99950.0, "LEGITIMATE"), (99990.0, "LEGITIMATE"), (99999.0, "LEGITIMATE"), (100000.0, "LEGITIMATE"),
        (100001.0, "HIGH_RISK"), (100010.0, "HIGH_RISK"), (100050.0, "HIGH_RISK"), (100100.0, "HIGH_RISK"), (100500.0, "HIGH_RISK"),
        (98000.0, "LEGITIMATE"), (98500.0, "LEGITIMATE"), (99000.0, "LEGITIMATE"), (99500.0, "LEGITIMATE"), (99800.0, "LEGITIMATE"),
        (101000.0, "HIGH_RISK"), (102000.0, "HIGH_RISK"), (103000.0, "HIGH_RISK"), (104000.0, "HIGH_RISK"), (105000.0, "HIGH_RISK")
    ]
    for idx, (amount_rupees, exp_class) in enumerate(boundary_values, 1):
        evt_id = f"evt_syn_boundary_{idx:02d}"
        acc_id = f"acc_boundary_user_{idx:02d}"
        pay_id = f"pay_boundary_{idx:02d}"
        event_time = base_time + 400000.0 + (idx * 120.0)
        
        payload_dict = {
            "event": "payment.captured",
            "account_id": acc_id,
            "event_id": evt_id,
            "created_at": event_time,
            "payload": {
                "payment": {
                    "entity": {
                        "id": pay_id,
                        "amount": int(amount_rupees * 100),
                        "currency": "INR",
                        "status": "captured",
                        "method": "card"
                    }
                }
            }
        }
        risk_scenarios.append({
            "scenario_id": f"risk_boundary_{idx:02d}",
            "archetype": "BORDERLINE_BOUNDARY",
            "expected_risk_class": exp_class,
            "truth_basis": "boundary_threshold_sensitivity_point",
            "account_id": acc_id,
            "amount_rupees": amount_rupees,
            "payload": payload_dict
        })

    # Security Scenarios (N=60)
    security_scenarios = []
    
    # 15 Tampered Signatures (401)
    for i in range(1, 16):
        p_str = json.dumps({"event": "payment.captured", "event_id": f"evt_sec_tamper_{i}", "payload": {"payment": {"entity": {"id": f"pay_t_{i}", "amount": 50000}}}})
        security_scenarios.append({
            "scenario_id": f"sec_tamper_{i:02d}",
            "vector": "invalid_hmac_signature",
            "expected_status": 401,
            "payload_string": p_str,
            "signature": "tampered_hex_value_000000000000",
            "event_id_header": f"evt_sec_tamper_{i}"
        })

    # 15 Missing Signatures (401)
    for i in range(1, 16):
        p_str = json.dumps({"event": "payment.captured", "event_id": f"evt_sec_nosig_{i}", "payload": {"payment": {"entity": {"id": f"pay_ns_{i}", "amount": 50000}}}})
        security_scenarios.append({
            "scenario_id": f"sec_nosig_{i:02d}",
            "vector": "missing_signature_header",
            "expected_status": 401,
            "payload_string": p_str,
            "signature": None,
            "event_id_header": f"evt_sec_nosig_{i}"
        })

    # 10 Missing Event IDs (400)
    for i in range(1, 11):
        p_str = json.dumps({"event": "payment.captured", "payload": {"payment": {"entity": {"id": f"pay_noid_{i}", "amount": 50000}}}})
        security_scenarios.append({
            "scenario_id": f"sec_noid_{i:02d}",
            "vector": "missing_event_id",
            "expected_status": 400,
            "payload_string": p_str,
            "signature": get_hmac_sig(p_str),
            "event_id_header": None
        })

    # 10 Malformed JSON (400)
    for i in range(1, 11):
        p_str = '{"event": "payment.captured", "corrupted_json": '
        security_scenarios.append({
            "scenario_id": f"sec_malformed_{i:02d}",
            "vector": "malformed_json_payload",
            "expected_status": 400,
            "payload_string": p_str,
            "signature": get_hmac_sig(p_str),
            "event_id_header": f"evt_sec_badjson_{i}"
        })

    # 10 Sequential Duplicate Deliveries
    for i in range(1, 11):
        p_str = json.dumps({"event": "payment.captured", "event_id": f"evt_sec_dup_{i}", "payload": {"payment": {"entity": {"id": f"pay_dup_{i}", "amount": 50000}}}})
        security_scenarios.append({
            "scenario_id": f"sec_dup_{i:02d}",
            "vector": "sequential_duplicate_delivery",
            "expected_status": 200,
            "payload_string": p_str,
            "signature": get_hmac_sig(p_str),
            "event_id_header": f"evt_sec_dup_{i}"
        })

    dataset = {
        "metadata": {
            "dataset_version": "1.1.0",
            "random_seed": RANDOM_SEED,
            "total_risk_scenarios": len(risk_scenarios),
            "total_security_scenarios": len(security_scenarios),
            "disclaimer": "Synthetic benchmark scenarios generated with fixed seed for deterministic rule evaluation. Not derived from Razorpay proprietary data."
        },
        "risk_scenarios": risk_scenarios,
        "security_scenarios": security_scenarios
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(dataset, f, indent=2)

    print(f"[Generator] Generated {len(risk_scenarios)} Risk Scenarios and {len(security_scenarios)} Security Scenarios.")

if __name__ == "__main__":
    generate_dataset()
