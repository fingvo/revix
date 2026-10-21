/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Binary Overview Panel displaying cryptographic hashes,
 *              architecture, entry point, and Shannon entropy distributions.
 * ============================================================================
 */

import React, { useState } from 'react';
import { UnifiedBinaryReport } from '../types/binary';
import { Hash, Activity, Check, Copy, AlertTriangle, Layers } from 'lucide-react';

interface OverviewPanelProps {
  report: UnifiedBinaryReport;
}

export const OverviewPanel: React.FC<OverviewPanelProps> = ({ report }) => {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const copyToClipboard = (text: string, key: string) => {
    navigator.clipboard.writeText(text);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const formatFileSize = (bytes: number) => {
    if (bytes >= 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(2)} MB`;
    if (bytes >= 1024) return `${(bytes / 1024).toFixed(2)} KB`;
    return `${bytes} Bytes`;
  };

  return (
    <div className="space-y-6">
      {/* Top Attributes Bento Grid */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <div className="sre-panel p-3">
          <span className="text-[11px] text-slate-400 block mb-1">File Size</span>
          <span className="text-sm font-semibold text-slate-100 font-mono">{formatFileSize(report.file_size)}</span>
        </div>

        <div className="sre-panel p-3">
          <span className="text-[11px] text-slate-400 block mb-1">Format</span>
          <span className="text-sm font-semibold text-[#00f2fe] font-mono">{report.format}</span>
        </div>

        <div className="sre-panel p-3">
          <span className="text-[11px] text-slate-400 block mb-1">Architecture</span>
          <span className="text-sm font-semibold text-slate-100 font-mono">{report.architecture}</span>
        </div>

        <div className="sre-panel p-3">
          <span className="text-[11px] text-slate-400 block mb-1">Bitness</span>
          <span className="text-sm font-semibold text-slate-100 font-mono">{report.bitness}-bit</span>
        </div>

        <div className="sre-panel p-3">
          <span className="text-[11px] text-slate-400 block mb-1">Endianness</span>
          <span className="text-sm font-semibold text-slate-100 font-mono">{report.endianness}</span>
        </div>

        <div className="sre-panel p-3">
          <span className="text-[11px] text-slate-400 block mb-1">Entry Point</span>
          <span className="text-sm font-semibold text-emerald-400 font-mono">
            0x{report.entry_point.toString(16).toUpperCase()}
          </span>
        </div>
      </div>

      {/* Cryptographic Verification Hashes */}
      <div className="sre-panel p-4">
        <div className="flex items-center gap-2 mb-3">
          <Hash className="w-4 h-4 text-[#00f2fe]" />
          <h2 className="text-xs font-semibold text-slate-200 tracking-wider uppercase">Cryptographic Integrity Hashes</h2>
        </div>

        <div className="space-y-2">
          {/* MD5 */}
          <div className="flex items-center justify-between gap-3 bg-[#0a0d13] p-2.5 rounded border border-[rgba(255,255,255,0.05)]">
            <div className="flex items-center gap-3 overflow-hidden">
              <span className="text-[11px] font-mono text-slate-400 w-16 uppercase">MD5:</span>
              <span className="text-xs font-mono text-slate-200 truncate">{report.md5}</span>
            </div>
            <button
              onClick={() => copyToClipboard(report.md5, 'md5')}
              className="text-slate-400 hover:text-white p-1 rounded hover:bg-[#1a2234] transition-colors"
              title="Copy MD5"
            >
              {copiedKey === 'md5' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* SHA256 */}
          <div className="flex items-center justify-between gap-3 bg-[#0a0d13] p-2.5 rounded border border-[rgba(255,255,255,0.05)]">
            <div className="flex items-center gap-3 overflow-hidden">
              <span className="text-[11px] font-mono text-slate-400 w-16 uppercase">SHA-256:</span>
              <span className="text-xs font-mono text-slate-200 truncate">{report.sha256}</span>
            </div>
            <button
              onClick={() => copyToClipboard(report.sha256, 'sha256')}
              className="text-slate-400 hover:text-white p-1 rounded hover:bg-[#1a2234] transition-colors"
              title="Copy SHA-256"
            >
              {copiedKey === 'sha256' ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Shannon Entropy Visualizer */}
      <div className="sre-panel p-4">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-4 h-4 text-emerald-400" />
            <h2 className="text-xs font-semibold text-slate-200 tracking-wider uppercase">Shannon Entropy Analysis</h2>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-slate-300">
              Score: <strong className="text-emerald-400">{report.entropy.total_entropy}</strong> / 8.0
            </span>
            {report.entropy.is_likely_packed && (
              <span className="sre-badge sre-badge-rose flex items-center gap-1">
                <AlertTriangle className="w-3 h-3" />
                Likely Packed / Encrypted
              </span>
            )}
          </div>
        </div>

        {/* Dynamic Entropy Distribution Bars */}
        <div className="space-y-1">
          <div className="h-16 flex items-end gap-1 bg-[#0a0d13] p-2 rounded border border-[rgba(255,255,255,0.05)] overflow-x-auto">
            {report.entropy.blocks.map((block, idx) => {
              const heightPercent = Math.min(100, Math.max(10, (block.score / 8.0) * 100));
              const isHigh = block.score > 7.0;
              const isMedium = block.score > 5.0 && block.score <= 7.0;

              return (
                <div
                  key={idx}
                  style={{ height: `${heightPercent}%` }}
                  className={`flex-1 min-w-[6px] rounded-t-sm transition-all duration-150 ${
                    isHigh
                      ? 'bg-rose-500/80 hover:bg-rose-400'
                      : isMedium
                      ? 'bg-amber-500/80 hover:bg-amber-400'
                      : 'bg-[#00f2fe]/80 hover:bg-[#00f2fe]'
                  }`}
                  title={`Block ${idx}: Offset 0x${block.offset.toString(16)} | Entropy: ${block.score.toFixed(2)}`}
                />
              );
            })}
          </div>

          <div className="flex justify-between text-[10px] text-slate-400 font-mono px-1">
            <span>0x00000000 (File Header)</span>
            <span>Entropy Scale: 0.0 (Null/Padded) to 8.0 (Encrypted/Compressed)</span>
            <span>0x{report.file_size.toString(16)} (End of File)</span>
          </div>
        </div>
      </div>
    </div>
  );
};
