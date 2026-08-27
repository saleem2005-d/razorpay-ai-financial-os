# SentinelAI: Multi-Signal Payment Risk Verifier
> A deterministic, defense-only payment webhook risk verifier with constant-time HMAC-SHA256 authentication, process-local duplicate protection, sliding-window velocity tracking, and cryptographically fingerprinted decisions.

---

## 📌 Executive Overview

Placing non-deterministic LLMs directly into synchronous payment ingestion paths introduces unacceptable latency spikes, failure modes, and unverified actions. **SentinelAI** provides a deterministic, multi-signal payment risk verification pipeline designed for high-throughput webhook processing.

The system evaluates incoming webhooks through a zero-trust raw-body cryptographic gateway, process-local idempotency locking, an entity blacklist check, and a 60-second sliding-window velocity tracker before enforcing high-value policy thresholds. Every decision is hashed into a SHA-256 decision fingerprint for transparent auditability.

### Key Engineering Signals
* **Cryptographic Ingestion Gate**: Constant-time HMAC-SHA256 signature verification computed directly over raw request bytes prior to JSON parsing (blocks payload tampering with HTTP 401).
* **Process-Local Idempotency Protection**: In-memory concurrency-safe reservation lock (`asyncio.Lock`) preventing race conditions and duplicate webhook execution.
* **Multi-Signal Deterministic Policy**: Combines entity blacklist matching, rolling 60-second sliding-window velocity tracking, and configurable monetary thresholds.
* **Decision Fingerprinting**: Deterministic SHA-256 hashing of event ID, account ID, transaction amount, rule verdict, and risk score for queryable audit verification.
* **Reproducible Evaluation Benchmark**: Independent 300-scenario synthetic evaluation suite measuring security rejection rates, rule-based classification performance, and operating-point financial trade-offs without synchronous LLM dependencies.

---

## 🎯 System Architecture

```mermaid
flowchart TD
    A["Incoming Webhook<br/>X-Razorpay-Signature & Event ID"] --> B{"1. Raw-Byte HMAC-SHA256 Gate"}
    
    B -- Invalid / Missing Sig --> C["HTTP 401 Unauthorized<br/>Payload Rejected"]
    B -- Valid Raw Sig --> D{"2. Pydantic Payload Schema Gate"}
    
    D -- Malformed JSON / Missing ID --> E["HTTP 400 Bad Request<br/>Schema Validation Error"]
    D -- Valid Event --> F{"3. Process-Local Idempotency Lock<br/>asyncio.Lock"}
    
    F -- Duplicate Event ID --> G["HTTP 200 Idempotent Response<br/>Serve Cached State"]
    F -- Unique Event ID --> H["4. Multi-Signal Deterministic Risk Gate"]
    
    subgraph Multi-Signal Risk Policy
        H --> I{"Blacklist Check"}
        I -- Match --> J["Score: 0.95 - Rule: BLACKLIST_MATCH"]
        I -- Clean --> K{"60s Sliding Velocity >= 4"}
        K -- Breached --> L["Score: 0.85 - Rule: VELOCITY_THRESHOLD_EXCEEDED"]
        K -- Normal --> M{"Amount > ₹100,000"}
        M -- Yes --> N["Score: 0.70 - Rule: HIGH_VALUE_THRESHOLD"]
        M -- No --> O["Score: 0.02 - Rule: BASELINE_CLEAN"]
    end
    
    J --> P["Verdict: MANUAL_REVIEW"]
    L --> P
    N --> P
    O --> Q["Verdict: ALLOW"]
    
    P --> R["5. SHA-256 Decision Fingerprinting"]
    Q --> R
    
    R --> S["6. In-Memory Audit Store<br/>/api/v1/audit/fingerprint/{event_id}"]
    S --> T["JSON Response Payload<br/>Sub-10ms Synchronous Path"]
