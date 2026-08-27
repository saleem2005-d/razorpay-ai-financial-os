import os
import sys
import warnings
import pytest
import time
import json
import hmac
import hashlib
import asyncio

warnings.filterwarnings("ignore", category=DeprecationWarning)

from httpx import AsyncClient, ASGITransport
from fastapi.testclient import TestClient
import app.main as main_module
from app.main import app, WEBHOOK_SECRET, reset_system_state
from benchmark.evaluate import calculate_metrics, evaluate_risk_dataset_at_threshold, evaluate_concurrent_duplicates

client = TestClient(app)

def test_confusion_matrix_metric_calculations():
    m1 = calculate_metrics(tp=80, tn=120, fp=20, fn=20)
    assert m1["precision"] == 0.8
    assert m1["recall"] == 0.8
    assert m1["f1"] == 0.8
    assert m1["fpr"] == round(20 / 140, 4)

    m_zero = calculate_metrics(tp=0, tn=0, fp=0, fn=0)
    assert m_zero["precision"] == 0.0
    assert m_zero["recall"] == 0.0
    assert m_zero["f1"] == 0.0
    assert m_zero["fpr"] == 0.0

def test_sliding_window_velocity_semantics_and_eviction():
    reset_system_state()
    account = "acc_test_velocity_eviction"
    base_t = 1700000000.0

    # Event 1: at t=0
    payload1 = {
        "event": "payment.captured", "account_id": account, "event_id": "evt_v1", "created_at": base_t,
        "payload": {"payment": {"entity": {"id": "p1", "amount": 50000, "currency": "INR"}}}
    }
    b1 = json.dumps(payload1, separators=(",", ":"))
    sig1 = hmac.new(WEBHOOK_SECRET.encode("utf-8"), b1.encode("utf-8"), hashlib.sha256).hexdigest()
    res1 = client.post("/api/v1/webhooks/razorpay", content=b1, headers={"Content-Type": "application/json", "X-Razorpay-Signature": sig1})
    assert res1.json()["decision"] == "ALLOW"
    assert res1.json()["velocity_count"] == 1

    # Event 2 & 3: at t=10s, t=20s
    for idx, sec in enumerate([10.0, 20.0], 2):
        p = {
            "event": "payment.captured", "account_id": account, "event_id": f"evt_v{idx}", "created_at": base_t + sec,
            "payload": {"payment": {"entity": {"id": f"p{idx}", "amount": 50000, "currency": "INR"}}}
        }
        b = json.dumps(p, separators=(",", ":"))
        sig = hmac.new(WEBHOOK_SECRET.encode("utf-8"), b.encode("utf-8"), hashlib.sha256).hexdigest()
        res = client.post("/api/v1/webhooks/razorpay", content=b, headers={"Content-Type": "application/json", "X-Razorpay-Signature": sig})
        assert res.json()["decision"] == "ALLOW"
        assert res.json()["velocity_count"] == idx

    # Event 4: at t=70s (Cutoff: 10s -> Event 1 at 0s evicted. Window has Events 2, 3, 4 -> count = 3)
    payload4 = {
        "event": "payment.captured", "account_id": account, "event_id": "evt_v4", "created_at": base_t + 70.0,
        "payload": {"payment": {"entity": {"id": "p4", "amount": 50000, "currency": "INR"}}}
    }
    b4 = json.dumps(payload4, separators=(",", ":"))
    sig4 = hmac.new(WEBHOOK_SECRET.encode("utf-8"), b4.encode("utf-8"), hashlib.sha256).hexdigest()
    res4 = client.post("/api/v1/webhooks/razorpay", content=b4, headers={"Content-Type": "application/json", "X-Razorpay-Signature": sig4})
    assert res4.json()["decision"] == "ALLOW"
    assert res4.json()["velocity_count"] == 3

    # Event 5: at t=72s (Cutoff: 12s -> Event 2 at 10s evicted. Window has Events 3, 4, 5 -> count = 3)
    payload5 = {
        "event": "payment.captured", "account_id": account, "event_id": "evt_v5", "created_at": base_t + 72.0,
        "payload": {"payment": {"entity": {"id": "p5", "amount": 50000, "currency": "INR"}}}
    }
    b5 = json.dumps(payload5, separators=(",", ":"))
    sig5 = hmac.new(WEBHOOK_SECRET.encode("utf-8"), b5.encode("utf-8"), hashlib.sha256).hexdigest()
    res5 = client.post("/api/v1/webhooks/razorpay", content=b5, headers={"Content-Type": "application/json", "X-Razorpay-Signature": sig5})
    assert res5.json()["decision"] == "ALLOW"
    assert res5.json()["velocity_count"] == 3

    # Event 6: at t=74s (Cutoff: 14s -> Window has Events 3[20s], 4[70s], 5[72s], 6[74s] -> count = 4 -> TRIGGER)
    payload6 = {
        "event": "payment.captured", "account_id": account, "event_id": "evt_v6", "created_at": base_t + 74.0,
        "payload": {"payment": {"entity": {"id": "p6", "amount": 50000, "currency": "INR"}}}
    }
    b6 = json.dumps(payload6, separators=(",", ":"))
    sig6 = hmac.new(WEBHOOK_SECRET.encode("utf-8"), b6.encode("utf-8"), hashlib.sha256).hexdigest()
    res6 = client.post("/api/v1/webhooks/razorpay", content=b6, headers={"Content-Type": "application/json", "X-Razorpay-Signature": sig6})
    assert res6.json()["decision"] == "MANUAL_REVIEW"
    assert res6.json()["velocity_count"] == 4
    assert res6.json()["rule_triggered"] == "VELOCITY_THRESHOLD_EXCEEDED"

def test_blacklist_enforcement():
    reset_system_state()
    payload = {
        "event": "payment.captured",
        "account_id": "acc_synthetic_blacklisted",
        "event_id": "evt_bl_test",
        "payload": {"payment": {"entity": {"id": "pay_bl_1", "amount": 50000, "currency": "INR"}}}
    }
    body_str = json.dumps(payload, separators=(",", ":"))
    sig = hmac.new(WEBHOOK_SECRET.encode("utf-8"), body_str.encode("utf-8"), hashlib.sha256).hexdigest()
    res = client.post("/api/v1/webhooks/razorpay", content=body_str, headers={"Content-Type": "application/json", "X-Razorpay-Signature": sig})
    assert res.status_code == 200
    assert res.json()["decision"] == "MANUAL_REVIEW"
    assert res.json()["rule_triggered"] == "BLACKLIST_MATCH"

@pytest.mark.asyncio
async def test_concurrent_duplicate_deduplication():
    passed, total = await evaluate_concurrent_duplicates()
    assert passed == total == 5

def test_benchmark_invariants_and_exact_equality():
    dataset_path = "benchmark/scenarios/evaluation_dataset.json"
    with open(dataset_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    risk_scenarios = data["risk_scenarios"]
    
    for th in [75000.0, 100000.0, 125000.0, 150000.0]:
        cm, m, _, _, _, _, _ = evaluate_risk_dataset_at_threshold(risk_scenarios, th)
        assert cm["tp"] + cm["tn"] + cm["fp"] + cm["fn"] == len(risk_scenarios)
        assert m["precision"] == round(float(cm["tp"]) / (cm["tp"] + cm["fp"]), 4)
        assert m["recall"] == round(float(cm["tp"]) / (cm["tp"] + cm["fn"]), 4)
        assert m["fpr"] == round(float(cm["fp"]) / (cm["fp"] + cm["tn"]), 4)

    cm1, m1, _, _, _, _, _ = evaluate_risk_dataset_at_threshold(risk_scenarios, 100000.0)
    cm2, m2, _, _, _, _, _ = evaluate_risk_dataset_at_threshold(risk_scenarios, 100000.0)
    assert cm1 == cm2
    assert m1 == m2
