import React, { useState } from "react";
import { 
  ShieldCheck, 
  ShieldAlert, 
  ShieldX, 
  Terminal, 
  CheckCircle2, 
  XCircle, 
  Copy, 
  Check, 
  Play, 
  RefreshCw, 
  Activity 
} from "lucide-react";

const PRESETS = {
  normal: {
    id: "normal",
    name: "Normal Payment",
    description: "Standard checkout event under policy thresholds.",
    signature: "valid_sha256_mock_sig_9f83a2",
    payload: {
      event: "payment.captured",
      entity: "event",
      contains: ["payment"],
      payload: {
        payment: {
          entity: {
            id: "pay_Nx81J92Mks81a",
            amount: 450000,
            currency: "INR",
            status: "captured",
            method: "upi",
            email: "alex.doe@example.com",
            contact: "+919876543210"
          }
        }
      }
    }
  },
  high_value: {
    id: "high_value",
    name: "High Value Review",
    description: "Triggers policy threshold (Amount ≥ ₹100,000).",
    signature: "valid_sha256_mock_sig_3b71c8",
    payload: {
      event: "payment.captured",
      entity: "event",
      contains: ["payment"],
      payload: {
        payment: {
          entity: {
            id: "pay_Kx92L01Pqa99z",
            amount: 12500000,
            currency: "INR",
            status: "captured",
            method: "card",
            email: "vip.customer@enterprise.io",
            contact: "+919988776655"
          }
        }
      }
    }
  },
  tampered: {
    id: "tampered",
    name: "Tampered Signature",
    description: "Simulates byte manipulation or forged HMAC token.",
    signature: "tampered_invalid_sig_00000000",
    payload: {
      event: "payment.captured",
      entity: "event",
      contains: ["payment"],
      payload: {
        payment: {
          entity: {
            id: "pay_Nx81J92Mks81a",
            amount: 9999900,
            currency: "INR",
            status: "captured",
            method: "upi"
          }
        }
      }
    }
  }
};

export default function SentinelConsole() {
  const [selectedPreset, setSelectedPreset] = useState("normal");
  const [jsonPayload, setJsonPayload] = useState(
    JSON.stringify(PRESETS.normal.payload, null, 2)
  );
  const [signature, setSignature] = useState(PRESETS.normal.signature);
  const [isVerifying, setIsVerifying] = useState(false);
  const [decision, setDecision] = useState(null);
  const [errorState, setErrorState] = useState(null);
  const [copied, setCopied] = useState(false);

  const handlePresetChange = (presetKey) => {
    const preset = PRESETS[presetKey];
    setSelectedPreset(presetKey);
    setJsonPayload(JSON.stringify(preset.payload, null, 2));
    setSignature(preset.signature);
    setDecision(null);
    setErrorState(null);
  };

  const handleVerify = async () => {
    setIsVerifying(true);
    setDecision(null);
    setErrorState(null);

    try {
      await new Promise((res) => setTimeout(res, 280));

      if (selectedPreset === "tampered") {
        setErrorState({
          status: "401 Unauthorized",
          code: "HTTP 401",
          reason: "Invalid HMAC-SHA256 Signature Token",
          details: "Raw byte comparison mismatch against configured secret key.",
          fingerprint: "NOT_GENERATED"
        });
      } else if (selectedPreset === "high_value") {
        setDecision({
          verdict: "MANUAL REVIEW",
          statusColor: "amber",
          riskScore: 0.70,
          confidence: "Rule-Based Deterministic",
          triggeredRule: "POLICY_HIGH_VALUE_THRESHOLD (> ₹100,000)",
          fingerprint: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
          evalTime: "3.84 ms",
          details: "Transaction routed to out-of-band asynchronous review queue. Gateway ACK: 200 OK."
        });
      } else {
        setDecision({
          verdict: "ALLOW",
          statusColor: "green",
          riskScore: 0.05,
          confidence: "Deterministic Pass",
          triggeredRule: "ALL_SYSTEM_INVARIANTS_SATISFIED",
          fingerprint: "9f83a2e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7",
          evalTime: "3.84 ms",
          details: "HMAC verified, idempotency key unique, velocity invariant valid."
        });
      }
    } catch (err) {
      setErrorState({
        status: "500 Internal Error",
        code: "HTTP 500",
        reason: "Failed to evaluate payload invariants.",
        fingerprint: "ERR_EXEC_FAILURE"
      });
    } finally {
      setIsVerifying(false);
    }
  };

  const copyFingerprint = (text) => {
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="min-h-screen bg-[#0B1220] text-gray-200 font-sans antialiased selection:bg-blue-600 selection:text-white pb-12">
      <header className="border-b border-[#1F2937] bg-[#111827]/80 backdrop-blur-md sticky top-0 z-50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="h-9 w-9 rounded-lg bg-blue-600/10 border border-blue-500/30 flex items-center justify-center text-blue-400 font-bold">
              <ShieldCheck className="h-5 w-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <span className="font-semibold text-white tracking-tight">SentinelAI</span>
                <span className="text-[10px] uppercase font-mono px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 border border-gray-700">v2.4.0</span>
              </div>
              <p className="text-xs text-gray-400">Webhook Risk Verification Console</p>
            </div>
          </div>

          <div className="hidden md:flex items-center space-x-6 text-xs">
            <div className="flex items-center space-x-2">
              <span className="text-gray-400">Gateway Status</span>
              <span className="inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-[11px] font-medium bg-emerald-950 text-emerald-400 border border-emerald-800/60">
                <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
                ONLINE
              </span>
            </div>
            <div className="h-4 w-px bg-gray-800" />
            <div>
              <span className="text-gray-400">p50 Latency:</span>{" "}
              <span className="font-mono font-medium text-blue-400">3.84 ms</span>
            </div>
            <div className="h-4 w-px bg-gray-800" />
            <div>
              <span className="text-gray-400">Active Policy:</span>{" "}
              <span className="font-mono font-medium text-gray-200">Max ₹100,000</span>
            </div>
          </div>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 mt-6">
        <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-3.5 mb-6 shadow-sm">
          <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-6 gap-3 text-xs">
            <div className="flex items-center space-x-2">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <span className="text-gray-300 font-medium">Gateway Online</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <span className="text-gray-300 font-medium">HMAC SHA-256</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="h-2 w-2 rounded-full bg-emerald-500" />
              <span className="text-gray-300 font-medium">Idempotency Guard</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-gray-400">Velocity Window:</span>
              <span className="font-mono text-gray-200 font-medium">60s</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-gray-400">Review Threshold:</span>
              <span className="font-mono text-gray-200 font-medium">₹100k</span>
            </div>
            <div className="flex items-center space-x-2">
              <span className="text-gray-400">Median Engine:</span>
              <span className="font-mono text-emerald-400 font-medium">3.84ms</span>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
          <div className="lg:col-span-7 space-y-5">
            <div className="bg-[#111827] border border-[#1F2937] rounded-xl p-4 shadow-sm">
              <label className="block text-xs font-semibold uppercase tracking-wider text-gray-400 mb-3">
                Preset Scenario
              </label>
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
                {Object.values(PRESETS).map((p) => {
                  const isSelected = selectedPreset === p.id;
                  return (
                    <button
                      key={p.id}
                      onClick={() => handlePresetChange(p.id)}
                      className={`text-left p-3 rounded-lg border transition-all text-xs flex flex-col justify-between ${
                        isSelected
                          ? "bg-blue-600/10 border-blue-500/60 text-white shadow-sm ring-1 ring-blue-500/30"
                          : "bg-[#0B1220]/60 border-[#1F2937] text-gray-400 hover:border-gray-700 hover:text-gray-300"
                      }`}
                    >
                      <div className="flex items-center justify-between w-full mb-1">
                        <span className="font-semibold">{p.name}</span>
                        <span className={`h-2 w-2 rounded-full ${isSelected ? "bg-blue-400" : "bg-gray-700"}`} />
                      </div>
                      <p className="text-[11px] text-gray-400 leading-tight mt-1">
                        {p.description}
                      </p>
                    </button>
                  );
                })}
              </div>
            </div>

            <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden shadow-sm">
              <div className="bg-[#0B1220] px-4 py-2.5 border-b border-[#1F2937] flex items-center justify-between">
                <div className="flex items-center space-x-2">
                  <Terminal className="h-3.5 w-3.5 text-gray-400" />
                  <span className="text-xs font-mono text-gray-300">webhook_payload.json</span>
                </div>
                <span className="text-[11px] font-mono text-gray-500">application/json</span>
              </div>

              <div className="relative font-mono text-xs p-4 bg-[#0B1220]/70 text-gray-200">
                <textarea
                  rows={13}
                  value={jsonPayload}
                  onChange={(e) => setJsonPayload(e.target.value)}
                  className="w-full bg-transparent border-0 outline-none resize-none font-mono text-xs leading-relaxed text-blue-100 selection:bg-blue-800"
                  spellCheck={false}
                />
              </div>

              <div className="bg-[#0e1626] p-3.5 border-t border-[#1F2937] space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-gray-400">
                    X-Razorpay-Signature
                  </label>
                  {signature.includes("invalid") || signature.includes("tampered") ? (
                    <span className="inline-flex items-center gap-1 text-[11px] text-rose-400 font-medium">
                      <XCircle className="h-3 w-3" /> Invalid Signature
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[11px] text-emerald-400 font-medium">
                      <CheckCircle2 className="h-3 w-3" /> Valid Signature
                    </span>
                  )}
                </div>
                <input
                  type="text"
                  value={signature}
                  onChange={(e) => setSignature(e.target.value)}
                  className="w-full bg-[#0B1220] border border-[#1F2937] rounded-lg px-3 py-2 text-xs font-mono text-gray-300 focus:outline-none focus:border-blue-500"
                />
              </div>

              <div className="p-3.5 bg-[#111827] border-t border-[#1F2937]">
                <button
                  disabled={isVerifying}
                  onClick={handleVerify}
                  className="w-full py-2.5 px-4 rounded-lg bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white text-xs font-semibold tracking-wide transition-all shadow-md hover:shadow-blue-500/10 flex items-center justify-center space-x-2 disabled:opacity-60 disabled:cursor-not-allowed"
                >
                  {isVerifying ? (
                    <>
                      <RefreshCw className="h-4 w-4 animate-spin text-white" />
                      <span>Evaluating Invariants (3.84ms)...</span>
                    </>
                  ) : (
                    <>
                      <Play className="h-3.5 w-3.5 fill-current" />
                      <span>Verify Webhook</span>
                    </>
                  )}
                </button>
              </div>
            </div>
          </div>

          <div className="lg:col-span-5">
            <div className="bg-[#111827] border border-[#1F2937] rounded-xl overflow-hidden shadow-sm min-h-[540px] flex flex-col justify-between">
              <div className="px-4 py-3 border-b border-[#1F2937] bg-[#0B1220]/50 flex items-center justify-between">
                <span className="text-xs font-semibold uppercase tracking-wider text-gray-400">
                  Verification Verdict
                </span>
                <span className="text-[11px] font-mono text-gray-500">Real-time Stream</span>
              </div>

              {!decision && !errorState && !isVerifying && (
                <div className="p-8 text-center flex flex-col items-center justify-center flex-1 my-auto">
                  <div className="h-12 w-12 rounded-full bg-gray-800/60 border border-gray-700 flex items-center justify-center text-gray-400 mb-3">
                    <Activity className="h-5 w-5" />
                  </div>
                  <h4 className="text-sm font-semibold text-gray-200">Awaiting Webhook Verification</h4>
                  <p className="text-xs text-gray-400 max-w-xs mt-1.5 leading-relaxed">
                    Submit or select a preset simulated Razorpay webhook to evaluate authenticity, HMAC integrity, and policy rules.
                  </p>
                </div>
              )}

              {errorState && (
                <div className="p-6 flex-1 flex flex-col justify-between space-y-6">
                  <div>
                    <div className="bg-rose-950/40 border border-rose-800/60 rounded-lg p-4 flex items-start space-x-3">
                      <ShieldX className="h-5 w-5 text-rose-400 shrink-0 mt-0.5" />
                      <div>
                        <div className="flex items-center space-x-2">
                          <span className="text-sm font-bold text-rose-400">{errorState.status}</span>
                          <span className="text-[10px] font-mono px-1.5 py-0.2 bg-rose-900/60 text-rose-300 rounded border border-rose-700/50">
                            {errorState.code}
                          </span>
                        </div>
                        <p className="text-xs text-rose-200 mt-1 font-medium">{errorState.reason}</p>
                        <p className="text-[11px] text-rose-300/80 mt-1 leading-relaxed">{errorState.details}</p>
                      </div>
                    </div>

                    <div className="mt-6 space-y-3 text-xs">
                      <div className="flex justify-between py-2 border-b border-[#1F2937]">
                        <span className="text-gray-400">Execution Action</span>
                        <span className="font-mono text-rose-400 font-semibold">FAST DROP (No Allocation)</span>
                      </div>
                      <div className="flex justify-between py-2 border-b border-[#1F2937]">
                        <span className="text-gray-400">Response Code</span>
                        <span className="font-mono text-gray-200">401 Signature Failure</span>
                      </div>
                      <div className="flex justify-between py-2 border-b border-[#1F2937]">
                        <span className="text-gray-400">Audit Fingerprint</span>
                        <span className="font-mono text-gray-500 italic">Not Generated (Pre-auth Drop)</span>
                      </div>
                    </div>
                  </div>

                  <div className="p-3 bg-[#0B1220] rounded-lg border border-[#1F2937] text-[11px] text-gray-400">
                    Byte-level constant-time HMAC check failed in <span className="font-mono text-gray-200">1.12 ms</span>. Payload dropped before JSON serialization.
                  </div>
                </div>
              )}

              {decision && (
                <div className="p-6 flex-1 flex flex-col justify-between space-y-6">
                  <div className="space-y-5">
                    <div
                      className={`p-4 rounded-xl border flex items-center justify-between ${
                        decision.verdict === "ALLOW"
                          ? "bg-emerald-950/30 border-emerald-800/60 text-emerald-400"
                          : "bg-amber-950/30 border-amber-800/60 text-amber-400"
                      }`}
                    >
                      <div className="flex items-center space-x-3">
                        {decision.verdict === "ALLOW" ? (
                          <ShieldCheck className="h-6 w-6" />
                        ) : (
                          <ShieldAlert className="h-6 w-6" />
                        )}
                        <div>
                          <span className="text-xs uppercase font-mono tracking-wider opacity-75">Decision</span>
                          <h3 className="text-base font-bold tracking-tight">{decision.verdict}</h3>
                        </div>
                      </div>
                      <span className="text-xs font-mono px-2 py-1 rounded bg-black/40 border border-current">
                        {decision.evalTime}
                      </span>
                    </div>

                    <div className="grid grid-cols-2 gap-3 p-3.5 bg-[#0B1220] rounded-xl border border-[#1F2937]">
                      <div>
                        <span className="text-[11px] text-gray-400 block mb-1">Risk Score</span>
                        <div className="flex items-baseline space-x-2">
                          <span className={`text-xl font-bold font-mono ${
                            decision.riskScore > 0.5 ? "text-amber-400" : "text-emerald-400"
                          }`}>
                            {(decision.riskScore * 100).toFixed(0)}%
                          </span>
                          <span className="text-[11px] text-gray-500">
                            ({decision.riskScore.toFixed(2)})
                          </span>
                        </div>
                      </div>
                      <div>
                        <span className="text-[11px] text-gray-400 block mb-1">Confidence Model</span>
                        <span className="text-xs font-semibold text-gray-200">{decision.confidence}</span>
                      </div>
                    </div>

                    <div className="space-y-2.5 text-xs">
                      <div className="flex justify-between py-1.5 border-b border-[#1F2937]">
                        <span className="text-gray-400">Triggered Rule</span>
                        <span className="font-mono text-gray-200 text-right">{decision.triggeredRule}</span>
                      </div>
                      <div className="flex justify-between py-1.5 border-b border-[#1F2937]">
                        <span className="text-gray-400">Evaluation Engine</span>
                        <span className="font-mono text-blue-400">Deterministic In-Line</span>
                      </div>
                    </div>

                    <div>
                      <div className="flex items-center justify-between mb-1.5">
                        <span className="text-[11px] font-medium text-gray-400">Audit Fingerprint (SHA-256)</span>
                        <span className="text-[10px] text-gray-500">Immutable Trace</span>
                      </div>
                      <div className="flex items-center space-x-2 bg-[#0B1220] border border-[#1F2937] rounded-lg p-2 font-mono text-xs">
                        <span className="text-gray-300 truncate flex-1">{decision.fingerprint}</span>
                        <button
                          onClick={() => copyFingerprint(decision.fingerprint)}
                          className="p-1 rounded hover:bg-gray-800 text-gray-400 hover:text-white transition-colors"
                          title="Copy fingerprint for audit traceability"
                        >
                          {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
                        </button>
                      </div>
                    </div>
                  </div>

                  <p className="text-[11px] text-gray-400 leading-relaxed border-t border-[#1F2937] pt-3">
                    {decision.details}
                  </p>
                </div>
              )}

              <div className="px-4 py-2 bg-[#0B1220] border-t border-[#1F2937] flex items-center justify-between text-[10px] text-gray-500 font-mono">
                <span>SENTINEL-INSPECTOR-CORE</span>
                <span>THREAD: 0x8F9A</span>
              </div>
            </div>
          </div>
        </div>
      </main>
    </div>
  );
}
