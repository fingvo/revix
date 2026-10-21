/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Heuristic Threat Intelligence & Suspicious Capability Scanner.
 * ============================================================================
 */

import React from 'react';
import { ThreatReport } from '../types/binary';
import { ShieldAlert, Crosshair, AlertTriangle, Cpu, CheckCircle } from 'lucide-react';

interface HeuristicScannerProps {
  threatReport?: ThreatReport;
}

export const HeuristicScanner: React.FC<HeuristicScannerProps> = ({ threatReport }) => {
  if (!threatReport) {
    return (
      <div className="sre-panel p-8 text-center space-y-3">
        <ShieldAlert className="w-10 h-10 text-slate-500 mx-auto" />
        <h3 className="text-sm font-semibold text-slate-200">No Heuristic Threat Analysis Available</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Upload a binary executable (.exe, .elf, .dll, .so) to run automated capability inspection and threat signature matching.
        </p>
      </div>
    );
  }

  const report = threatReport;
  const isHighRisk = report.risk_score >= 70;
  const isMediumRisk = report.risk_score >= 40 && report.risk_score < 70;

  return (
    <div className="sre-panel p-4 space-y-6">
      {/* Risk Gauge Header */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[rgba(255,255,255,0.06)] pb-4">
        <div className="flex items-center gap-3">
          <div
            className={`w-12 h-12 rounded flex items-center justify-center font-mono font-bold text-lg ${
              isHighRisk
                ? 'bg-rose-500/10 text-rose-400 border border-rose-500/30'
                : isMediumRisk
                ? 'bg-amber-500/10 text-amber-400 border border-amber-500/30'
                : 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
            }`}
          >
            {report.risk_score}
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-semibold text-slate-100 uppercase tracking-wider">
                Heuristic Capability Threat Score
              </h2>
              <span
                className={`sre-badge ${
                  isHighRisk ? 'sre-badge-rose' : isMediumRisk ? 'sre-badge-amber' : 'sre-badge-emerald'
                }`}
              >
                {report.risk_level}
              </span>
            </div>
            <p className="text-xs text-slate-400 mt-0.5">
              Automated behavioral classification powered by the Revix Python heuristic engine.
            </p>
          </div>
        </div>
      </div>

      {/* Identified Signatures Section */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-200 uppercase tracking-wider">
          <Cpu className="w-4 h-4 text-[#00f2fe]" />
          <span>Compiler & Toolchain Signatures</span>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          {report.detected_signatures.map((sig, idx) => (
            <div
              key={idx}
              className="bg-[#0a0d13] p-3 rounded border border-[rgba(255,255,255,0.06)] space-y-1"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold text-slate-100">{sig.name}</span>
                <span className="sre-badge sre-badge-cyan text-[10px]">{sig.category}</span>
              </div>
              <p className="text-[11px] text-slate-400">{sig.description}</p>
              <span className="text-[10px] font-mono text-slate-400 block pt-1">
                Offset: {sig.offset}
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Detected Capabilities Grid */}
      <div className="space-y-3">
        <div className="flex items-center gap-2 text-xs font-semibold text-slate-200 uppercase tracking-wider">
          <Crosshair className="w-4 h-4 text-rose-400" />
          <span>High-Risk Behavioral Capabilities</span>
        </div>

        <div className="space-y-3">
          {Object.entries(report.detected_capabilities).map(([category, apis], idx) => (
            <div
              key={idx}
              className="bg-[#0a0d13] p-3 rounded border border-[rgba(255,255,255,0.06)] space-y-2"
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-medium text-slate-200 flex items-center gap-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 text-amber-400" />
                  {category}
                </span>
                <span className="text-[10px] font-mono text-slate-400">
                  {apis.length} APIs Flagged
                </span>
              </div>

              <div className="flex flex-wrap gap-2 pt-1">
                {apis.map((api, aIdx) => (
                  <span
                    key={aIdx}
                    className="font-mono text-[11px] bg-[#161c2b] border border-[rgba(255,255,255,0.08)] text-[#00f2fe] px-2 py-0.5 rounded"
                  >
                    {api}
                  </span>
                ))}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
