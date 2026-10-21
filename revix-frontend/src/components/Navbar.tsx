/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Top application navigation bar displaying Revix branding,
 *              engine connection status, and author credit metadata.
 * ============================================================================
 */

import React from 'react';
import { ShieldAlert, Terminal, RefreshCw, Cpu } from 'lucide-react';

interface NavbarProps {
  fileName?: string;
  onClearBinary?: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({ fileName, onClearBinary }) => {
  return (
    <header className="border-b border-[rgba(255,255,255,0.08)] bg-[#0d111a] px-6 py-3 flex flex-wrap items-center justify-between gap-4 sticky top-0 z-50">
      {/* Brand & Project Identity */}
      <div className="flex items-center gap-3">
        <div className="w-9 h-9 rounded bg-gradient-to-tr from-[#00f2fe] to-[#4facfe] flex items-center justify-center shadow-lg shadow-[#00f2fe]/20">
          <Cpu className="w-5 h-5 text-[#0a0d13]" />
        </div>
        <div>
          <div className="flex items-center gap-2">
            <h1 className="text-lg font-bold tracking-wider text-slate-100 font-mono">REVIX</h1>
            <span className="sre-badge sre-badge-cyan">v0.1.0-alpha</span>
          </div>
          <p className="text-xs text-slate-400">Software Reverse Engineering & Binary Inspection Workbench</p>
        </div>
      </div>

      {/* Loaded Target File Status */}
      <div className="flex items-center gap-3 bg-[#111622] border border-[rgba(255,255,255,0.06)] px-3 py-1.5 rounded">
        <Terminal className="w-4 h-4 text-[#00f2fe]" />
        <span className="text-xs text-slate-400">Target:</span>
        <span className="text-xs font-mono font-medium text-slate-200">
          {fileName ? fileName : 'No Binary Ingested'}
        </span>
      </div>

      {/* Author & Actions Section */}
      <div className="flex items-center gap-4">
        {fileName && onClearBinary && (
          <button
            onClick={onClearBinary}
            className="text-xs text-slate-300 hover:text-white bg-[#182030] hover:bg-[#222c42] border border-[rgba(255,255,255,0.1)] px-3 py-1.5 rounded flex items-center gap-2 transition-colors cursor-pointer"
          >
            <RefreshCw className="w-3.5 h-3.5 text-[#00f2fe]" />
            <span>Unload Binary</span>
          </button>
        )}

        {/* Author Credit Badge */}
        <div className="hidden md:flex flex-col text-right">
          <span className="text-xs text-slate-200 font-semibold">Sohail MN (Aka Fingvo)</span>
          <span className="text-[10px] text-slate-400">Full Stack Engineer | (c) 2026 Fingvo</span>
        </div>
      </div>
    </header>
  );
};
