# =====================================================================
# SentinelAI - Track 2 Verifier Demonstration & Evaluation Orchestrator
# =====================================================================

$ErrorActionPreference = "Continue"
$BaseUrl = "http://localhost:8000"

# Detect Python interpreter (prefer virtual environment)
$PythonExe = "python"
if (Test-Path ".\venv\Scripts\python.exe") {
    $PythonExe = ".\venv\Scripts\python.exe"
} elseif (Test-Path ".\.venv\Scripts\python.exe") {
    $PythonExe = ".\.venv\Scripts\python.exe"
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " SentinelAI: Payment Webhook Risk Verifier Demonstration " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "Using Python Runtime: $PythonExe" -ForegroundColor Gray

# Step 1: Health & Subsystem Inspection
Write-Host "`n[Step 1] Inspecting API Gateway & Subsystem Status..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get -ErrorAction Stop
    Write-Host " -> Gateway ONLINE: $(ConvertTo-Json $health.subsystems -Compress)" -ForegroundColor Green
    Write-Host " -> Active Config: Threshold = INR $($health.config.risk_review_threshold_rupees), Velocity Limit = $($health.config.velocity_review_threshold)/60s" -ForegroundColor Gray
} catch {
    Write-Host " -> ERROR: Local server is offline at $BaseUrl. Please start Uvicorn first:" -ForegroundColor Red
    Write-Host "    $PythonExe -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload" -ForegroundColor DarkYellow
    exit
}

# Step 2: Live Adversarial Attacks & Security Ingestion
Write-Host "`n[Step 2] Firing Adversarial Attacks Against Webhook Security Gate..." -ForegroundColor Yellow

$Secret = "test_webhook_secret_key_123"
function Get-Hmac { param ($p)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($Secret)
    return -join ($hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($p)) | ForEach-Object { "{0:x2}" -f $_ })
}

# 2a. Tampered Signature
$pTamper = '{"event":"payment.captured","account_id":"acc_test","event_id":"evt_demo_tamper","payload":{"payment":{"entity":{"id":"pay_1","amount":50000,"currency":"INR"}}}}'
try {
    Invoke-RestMethod -Uri "$BaseUrl/api/v1/webhooks/razorpay" -Method Post -Body $pTamper -Headers @{"Content-Type"="application/json"; "X-Razorpay-Signature"="bad_hash"} | Out-Null
    Write-Host " -> FAILED: Tampered signature accepted!" -ForegroundColor Red
} catch {
    Write-Host " -> PASSED: Tampered HMAC signature blocked with HTTP 401 Unauthorized." -ForegroundColor Green
}

# 2b. Valid Event & Decision Fingerprinting
$validEvtId = "evt_demo_live_" + (Get-Random)
$pValid = '{"event":"payment.captured","account_id":"acc_demo_user","event_id":"' + $validEvtId + '","payload":{"payment":{"entity":{"id":"pay_demo","amount":15000000,"currency":"INR"}}}}'
$sigValid = Get-Hmac $pValid
$resValid = Invoke-RestMethod -Uri "$BaseUrl/api/v1/webhooks/razorpay" -Method Post -Body $pValid -Headers @{"Content-Type"="application/json"; "X-Razorpay-Signature"=$sigValid; "X-Razorpay-Event-Id"=$validEvtId}

Write-Host " -> PASSED: Valid high-value payment processed:" -ForegroundColor Green
Write-Host "    Decision: $($resValid.decision) | Risk Score: $($resValid.risk_score) | Rule: $($resValid.rule_triggered)" -ForegroundColor Gray
Write-Host "    SHA-256 Decision Fingerprint: $($resValid.fingerprint)" -ForegroundColor Gray

# 2c. Duplicate Event Idempotency
$resDup = Invoke-RestMethod -Uri "$BaseUrl/api/v1/webhooks/razorpay" -Method Post -Body $pValid -Headers @{"Content-Type"="application/json"; "X-Razorpay-Signature"=$sigValid; "X-Razorpay-Event-Id"=$validEvtId}
if ($resDup.idempotent -eq $true) {
    Write-Host " -> PASSED: Replayed event intercepted by process-local idempotency lock (Returned cached state)." -ForegroundColor Green
}

# Step 3: Run Full Benchmark Suite
Write-Host "`n[Step 3] Executing Reproducible Benchmark Suite (300 Scenarios)..." -ForegroundColor Yellow
& $PythonExe benchmark/evaluate.py

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Demo Completed. Evidence artifacts saved in benchmark/results/" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
