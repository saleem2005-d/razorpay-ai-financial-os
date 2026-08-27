# =====================================================================
# SentinelAI - Phase 6 Defense Verifier Test Suite (8 Test Vectors)
# =====================================================================

$ErrorActionPreference = "Continue"

$BaseUrl = "http://localhost:8000"
$WebhookEndpoint = "$BaseUrl/api/v1/webhooks/razorpay"
$AuditEndpoint = "$BaseUrl/api/v1/audit/fingerprint"
$Secret = "test_webhook_secret_key_123"

function Get-HmacSignature {
    param ([string]$Payload, [string]$SecretKey)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [System.Text.Encoding]::UTF8.GetBytes($SecretKey)
    $hash = $hmac.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Payload))
    return -join ($hash | ForEach-Object { "{0:x2}" -f $_ })
}

function Invoke-WebhookTest {
    param (
        [string]$PayloadString,
        [string]$Signature,
        [string]$EventIdHeader,
        [switch]$OmitSignatureHeader
    )
    $headers = @{ "Content-Type" = "application/json" }
    if (-not $OmitSignatureHeader) { $headers["X-Razorpay-Signature"] = $Signature }
    if ($EventIdHeader) { $headers["X-Razorpay-Event-Id"] = $EventIdHeader }

    try {
        $res = Invoke-RestMethod -Uri $WebhookEndpoint -Method Post -Body $PayloadString -Headers $headers -ErrorAction Stop
        return @{ Success = $true; StatusCode = 200; Data = $res }
    } catch {
        $statusCode = $_.Exception.Response.StatusCode.value__
        return @{ Success = $false; StatusCode = $statusCode; Error = $_.Exception.Message }
    }
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " Starting Verification Suite: SentinelAI Defense Gate     " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# Test 1: Health Check
Write-Host "`n[Test 1] Health & Subsystem Status..." -ForegroundColor Yellow
try {
    $h = Invoke-RestMethod -Uri "$BaseUrl/health" -Method Get -ErrorAction Stop
    Write-Host " -> PASSED: Server online. Subsystems: $(ConvertTo-Json $h.subsystems -Compress)" -ForegroundColor Green
} catch {
    Write-Host " -> FAILED: Server offline at $BaseUrl." -ForegroundColor Red; exit
}

# Test 2: Invalid HMAC Signature
Write-Host "`n[Test 2] Tampered / Invalid Signature..." -ForegroundColor Yellow
$p2 = '{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_2","amount":500000,"currency":"INR"}}}}'
$r2 = Invoke-WebhookTest -PayloadString $p2 -Signature "tampered_sig_hash" -EventIdHeader "evt_test_2"
if ($r2.StatusCode -eq 401) { Write-Host " -> PASSED: Rejected with HTTP 401." -ForegroundColor Green } else { Write-Host " -> FAILED: HTTP $($r2.StatusCode)" -ForegroundColor Red }

# Test 3: Missing HMAC Signature
Write-Host "`n[Test 3] Missing Signature Header..." -ForegroundColor Yellow
$r3 = Invoke-WebhookTest -PayloadString $p2 -EventIdHeader "evt_test_3" -OmitSignatureHeader
if ($r3.StatusCode -eq 401) { Write-Host " -> PASSED: Rejected with HTTP 401." -ForegroundColor Green } else { Write-Host " -> FAILED: HTTP $($r3.StatusCode)" -ForegroundColor Red }

# Test 4: Missing Event ID
Write-Host "`n[Test 4] Missing Event ID (Header and Payload)..." -ForegroundColor Yellow
$p4 = '{"event":"payment.captured","payload":{"payment":{"entity":{"id":"pay_4","amount":500000,"currency":"INR"}}}}'
$sig4 = Get-HmacSignature -Payload $p4 -SecretKey $Secret
$r4 = Invoke-WebhookTest -PayloadString $p4 -Signature $sig4
if ($r4.StatusCode -eq 400) { Write-Host " -> PASSED: Rejected with HTTP 400 (Missing event ID)." -ForegroundColor Green } else { Write-Host " -> FAILED: HTTP $($r4.StatusCode)" -ForegroundColor Red }

# Test 5: Malformed JSON Payload
Write-Host "`n[Test 5] Malformed JSON Payload..." -ForegroundColor Yellow
$badJson = '{"event": "payment.captured", "broken_json": '
$sig5 = Get-HmacSignature -Payload $badJson -SecretKey $Secret
$r5 = Invoke-WebhookTest -PayloadString $badJson -Signature $sig5 -EventIdHeader "evt_test_5"
if ($r5.StatusCode -eq 400) { Write-Host " -> PASSED: Rejected with HTTP 400 (Malformed payload)." -ForegroundColor Green } else { Write-Host " -> FAILED: HTTP $($r5.StatusCode)" -ForegroundColor Red }

# Test 6: Valid Ingestion & Risk Scoring
Write-Host "`n[Test 6] Valid Payment Event Ingestion..." -ForegroundColor Yellow
$evt6 = "evt_valid_" + (Get-Random)
$p6 = '{"event":"payment.captured","event_id":"' + $evt6 + '","payload":{"payment":{"entity":{"id":"pay_6","amount":7500000,"currency":"INR"}}}}'
$sig6 = Get-HmacSignature -Payload $p6 -SecretKey $Secret
$r6 = Invoke-WebhookTest -PayloadString $p6 -Signature $sig6 -EventIdHeader $evt6
if ($r6.Success -and $r6.Data.decision -eq "ALLOW") {
    Write-Host " -> PASSED: Ingestion successful. Decision: $($r6.Data.decision), Risk Score: $($r6.Data.risk_score)" -ForegroundColor Green
} else { Write-Host " -> FAILED: Ingestion failed." -ForegroundColor Red }

# Test 7: Duplicate Event Protection (Sequential)
Write-Host "`n[Test 7] Sequential Duplicate Event Delivery..." -ForegroundColor Yellow
$r7 = Invoke-WebhookTest -PayloadString $p6 -Signature $sig6 -EventIdHeader $evt6
if ($r7.Data.idempotent -eq $true -and $r7.Data.status -eq "duplicate") {
    Write-Host " -> PASSED: Duplicate detected and returned cached state." -ForegroundColor Green
} else { Write-Host " -> FAILED: Duplicate not blocked." -ForegroundColor Red }

# Test 8: Audit Decision Fingerprint Lookup
Write-Host "`n[Test 8] Querying SHA-256 Decision Fingerprint..." -ForegroundColor Yellow
try {
    $audit = Invoke-RestMethod -Uri "$AuditEndpoint/$evt6" -Method Get -ErrorAction Stop
    Write-Host " -> PASSED: SHA-256 Fingerprint Record Verified:" -ForegroundColor Green
    Write-Host "    Hash: $($audit.fingerprint_hash)" -ForegroundColor Gray
    Write-Host "    Rule Verdict: $($audit.rule_verdict)" -ForegroundColor Gray
} catch {
    Write-Host " -> FAILED: Could not retrieve audit record." -ForegroundColor Red
}

Write-Host "`n==========================================================" -ForegroundColor Cyan
Write-Host " Test suite completed. Ready for review.                  " -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan
