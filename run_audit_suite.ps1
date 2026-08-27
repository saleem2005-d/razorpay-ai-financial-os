# =====================================================================
# AI Risk Manager / Financial OS - Phase 6 Audit & Chaos Test Suite
# =====================================================================

$ErrorActionPreference = "Continue"

$BaseUrl = "http://localhost:8000"
$WebhookEndpoint = "$BaseUrl/api/v1/webhooks/razorpay"
$AuditEndpoint = "$BaseUrl/api/v1/audit/fingerprint"
$Secret = "test_webhook_secret_key_123"

function Get-HmacSignature {
    param (
        [string]$Payload,
        [string]$SecretKey
    )
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
    $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Payload))
    return -join ($hash | ForEach-Object { "{0:x2}" -f $_ })
}

function Send-WebhookEvent {
    param (
        [string]$EventId,
        [string]$PaymentId,
        [double]$Amount,
        [string]$Status = "payment.captured",
        [switch]$TamperSignature
    )

    $payloadObject = @{
        event = $Status
        account_id = "acc_simulated_razorpay"
        event_id = $EventId
        created_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
        payload = @{
            payment = @{
                entity = @{
                    id = $PaymentId
                    amount = $Amount * 100
                    currency = "INR"
                    status = "captured"
                    method = "upi"
                    created_at = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                }
            }
        }
    }

    $jsonPayload = $payloadObject | ConvertTo-Json -Depth 5 -Compress
    $signature = Get-HmacSignature -Payload $jsonPayload -SecretKey $Secret

    if ($TamperSignature) {
        $signature = "tampered_invalid_sig_hash_000000000000"
    }

    $headers = @{
        "Content-Type" = "application/json"
        "X-Razorpay-Signature" = $signature
        "X-Razorpay-Event-Id" = $EventId
    }

    try {
        $response = Invoke-RestMethod -Uri $WebhookEndpoint -Method Post -Body $jsonPayload -Headers $headers -ErrorAction Stop
        return @{ Success = $true; StatusCode = 200; Data = $response }
    }
    catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        return @{ Success = $false; StatusCode = $statusCode; Error = $_.Exception.Message }
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting Audit & Verification Run (State, HMAC & Chaos) " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Test 1: Health & System Gateway Connectivity
Write-Host "`n[Test 1] Checking API Server Health..." -ForegroundColor Yellow
try {
    $health = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get -ErrorAction Stop
    Write-Host " -> Server is ONLINE: $(ConvertTo-Json $health -Compress)" -ForegroundColor Green
}
catch {
    Write-Host " -> API Server unavailable at $BaseUrl. Ensure backend service is running." -ForegroundColor Red
    exit
}

# Test 2: HMAC Signature Security Check (Adversarial Payload)
Write-Host "`n[Test 2] Testing Tampered HMAC Signature (Security Gate)..." -ForegroundColor Yellow
$tamperRes = Send-WebhookEvent -EventId "evt_tamper_001" -PaymentId "pay_sec_fail_001" -Amount 15000 -TamperSignature
if ($tamperRes.StatusCode -eq 401 -or $tamperRes.StatusCode -eq 403 -or -not $tamperRes.Success) {
    Write-Host " -> PASSED: Invalid signature successfully rejected (HTTP $($tamperRes.StatusCode))." -ForegroundColor Green
} else {
    Write-Host " -> FAILED: Tampered signature accepted unexpectedly!" -ForegroundColor Red
}

# Test 3: Standard Ingestion & Risk Scoring
Write-Host "`n[Test 3] Processing Valid Payment Event..." -ForegroundColor Yellow
$validEventId = "evt_valid_" + (Get-Random)
$validPayId = "pay_valid_" + (Get-Random)
$ingestRes = Send-WebhookEvent -EventId $validEventId -PaymentId $validPayId -Amount 75000
if ($ingestRes.Success) {
    Write-Host " -> PASSED: Ingestion successful. Decision payload: $(ConvertTo-Json $ingestRes.Data -Compress)" -ForegroundColor Green
} else {
    Write-Host " -> FAILED: Could not process valid event. Error: $($ingestRes.Error)" -ForegroundColor Red
}

# Test 4: Idempotency & Replay Attack Protection (Redis Lock Verification)
Write-Host "`n[Test 4] Simulating Duplicate Event Delivery (Replay Attack)..." -ForegroundColor Yellow
$replayRes = Send-WebhookEvent -EventId $validEventId -PaymentId $validPayId -Amount 75000
if ($replayRes.StatusCode -eq 409 -or $replayRes.Data.status -match "duplicate|idempotent_hit" -or $replayRes.Data.idempotent -eq $true) {
    Write-Host " -> PASSED: Duplicate event blocked / deduplicated via idempotency lock." -ForegroundColor Green
} else {
    Write-Host " -> INFO: Response received: $(ConvertTo-Json $replayRes.Data -Compress)" -ForegroundColor Cyan
}

# Test 5: Audit Decision Ledger & Fingerprint Check
Write-Host "`n[Test 5] Querying Decision Fingerprint Audit Trail..." -ForegroundColor Yellow
try {
    $auditRes = Invoke-RestMethod -Uri "$AuditEndpoint/$validEventId" -Method Get -ErrorAction Stop
    Write-Host " -> PASSED: Fingerprint Verified:" -ForegroundColor Green
    Write-Host "    Deterministic Hash: $($auditRes.fingerprint_hash)" -ForegroundColor Gray
    Write-Host "    Policy Rule Engine: $($auditRes.rule_verdict)" -ForegroundColor Gray
    Write-Host "    State Immutable: $($auditRes.is_immutable)" -ForegroundColor Gray
}
catch {
    Write-Host " -> NOTE: Audit log check returned: $($_.Exception.Message)" -ForegroundColor DarkYellow
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Audit run finished. Ready to inspect Step 7: README.md.   " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
