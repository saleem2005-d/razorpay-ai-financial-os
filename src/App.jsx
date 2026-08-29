import React from "react";
import SentinelConsole from "./SentinelConsole";

export default function App() {
  return (
    <div className="min-h-screen w-full bg-[#0B1220] text-slate-100 flex flex-col justify-between">
      <div className="flex-1 w-full">
        <SentinelConsole />
      </div>

      <footer className="w-full border-t border-[#1F2937] bg-[#0B1220] py-3 px-6 text-xs text-gray-500 flex flex-col sm:flex-row items-center justify-between gap-2">
        <div className="flex items-center space-x-2">
          <span className="h-1.5 w-1.5 rounded-full bg-emerald-500"></span>
          <span>Sentinel Core Gateway Active: SHA-256 HMAC Byte-Level Verification</span>
        </div>
        <div className="font-mono text-[11px] text-gray-400">
          Deterministic SLA: <span className="text-emerald-400 font-semibold">&lt; 5.00ms</span> | Engine p50: <span className="text-blue-400 font-semibold">3.84ms</span>
        </div>
      </footer>
    </div>
  );
}
