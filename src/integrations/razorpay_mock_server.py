"""
Razorpay Mock Server & Chaos Injection Test Harness.
"""

import hmac
import hashlib
import time
import requests
import json
from typing import Dict, Any

class RazorpayMockServer:
    def __init__(self, target_gateway_url: str, secret: str):
        self.target_url = target_gateway_url
        self.secret = secret

    def generate_signed_webhook_payload(
        self, 
        event_id: str, 
        event_type: str, 
        payload_data: Dict[str, Any],
        tamper_signature: bool = False
    ) -> Dict[str, Any]:
        """Generates valid or tampered webhook HTTP requests."""
        raw_body = json.dumps({
            "entity": "event",
            "account_id": "acc_buildathon_001",
            "event": event_type,
            "contains": ["payment"],
            "payload": payload_data,
            "created_at": int(time.time())
        }, sort_keys=True).encode("utf-8")

        signature = hmac.new(
            key=self.secret.encode("utf-8"),
            msg=raw_body,
            digestmod=hashlib.sha256
        ).hexdigest()

        if tamper_signature:
            signature = signature[:-5] + "BAD_SIG"

        headers = {
            "Content-Type": "application/json",
            "X-Razorpay-Signature": signature,
            "X-Razorpay-Event-Id": event_id
        }

        return {"url": self.target_url, "data": raw_body, "headers": headers}

    def emit_webhook(self, event_id: str, event_type: str, payload: Dict[str, Any], tamper: bool = False) -> int:
        req = self.generate_signed_webhook_payload(event_id, event_type, payload, tamper_signature=tamper)
        res = requests.post(req["url"], data=req["data"], headers=req["headers"])
        return res.status_code


if __name__ == "__main__":
    mock = RazorpayMockServer("http://localhost:8000/api/v1/webhooks/razorpay", "RAZORPAY_BUILDATHON_WEBHOOK_SECRET_2026")
    
    print("--- 1. Emitting Valid Webhook ---")
    try:
        status_1 = mock.emit_webhook("evt_001", "payment.captured", {"amount": 500000}, tamper=False)
        print(f"Server Response Status: {status_1}")
    except Exception as e:
        print(f"Server offline or unreachable: {e}")

    print("\n--- 2. Emitting Tampered Webhook (Chaos Test) ---")
    try:
        status_2 = mock.emit_webhook("evt_002", "payment.failed", {"amount": 100000}, tamper=True)
        print(f"Server Response Status: {status_2}")
    except Exception as e:
        print(f"Server offline or unreachable: {e}")
