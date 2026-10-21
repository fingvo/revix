/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Interactive Hex & ASCII memory editor view for raw byte inspection.
 * ============================================================================
 */

import React, { useState } from 'react';
import { Binary, ArrowRight, Search } from 'lucide-react';

interface HexViewerProps {
  rawBytes?: Uint8Array;
  initialOffset?: number;
}

export const HexViewer: React.FC<HexViewerProps> = ({ rawBytes, initialOffset = 0 }) => {
  const [currentOffset, setCurrentOffset] = useState(initialOffset);
  const [jumpInput, setJumpInput] = useState('');
  const [hoveredIndex, setHoveredIndex] = useState<number | null>(null);

  if (!rawBytes || rawBytes.length === 0) {
    return (
      <div className="sre-panel p-8 text-center space-y-3">
        <Binary className="w-10 h-10 text-slate-500 mx-auto" />
        <h3 className="text-sm font-semibold text-slate-200">No Raw Binary Loaded</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Upload an executable or binary file to inspect live hexadecimal offsets and ASCII byte representations.
        </p>
      </div>
    );
  }

  // Generate rows of 16-bytes directly from REAL uploaded binary bytes
  const rows = [];
  const maxRows = Math.min(32, Math.ceil((rawBytes.length - currentOffset) / 16));

  for (let r = 0; r < maxRows; r++) {
    const rowOffset = currentOffset + r * 16;
    if (rowOffset >= rawBytes.length) break;
    const sliceEnd = Math.min(rowOffset + 16, rawBytes.length);
    const bytes = Array.from(rawBytes.subarray(rowOffset, sliceEnd));
    rows.push({ offset: rowOffset, bytes });
  }

  const handleJump = (e: React.FormEvent) => {
    e.preventDefault();
    const parsed = parseInt(jumpInput, 16);
    if (!isNaN(parsed) && parsed >= 0 && parsed < rawBytes.length) {
      setCurrentOffset(Math.floor(parsed / 16) * 16);
    }
  };

  return (
    <div className="sre-panel p-4 space-y-4">
      {/* Toolbar & Jump offset input */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[rgba(255,255,255,0.06)] pb-3">
        <div className="flex items-center gap-2">
          <Binary className="w-4 h-4 text-[#00f2fe]" />
          <h2 className="text-xs font-semibold text-slate-200 tracking-wider uppercase">Interactive Hexadecimal Inspector</h2>
        </div>

        <form onSubmit={handleJump} className="flex items-center gap-2">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Jump Offset (e.g. 0x40)"
              value={jumpInput}
              onChange={(e) => setJumpInput(e.target.value)}
              className="bg-[#0a0d13] border border-[rgba(255,255,255,0.1)] rounded pl-8 pr-3 py-1 text-xs font-mono text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-[#00f2fe]"
            />
          </div>
          <button
            type="submit"
            className="bg-[#182030] hover:bg-[#222c42] border border-[rgba(255,255,255,0.1)] px-3 py-1 rounded text-xs text-slate-200 flex items-center gap-1 cursor-pointer transition-colors"
          >
            <span>Jump</span>
            <ArrowRight className="w-3 h-3 text-[#00f2fe]" />
          </button>
        </form>
      </div>

      {/* Hex Stream Grid */}
      <div className="overflow-x-auto font-mono text-xs select-text bg-[#080b10] p-3 rounded border border-[rgba(255,255,255,0.04)]">
        {/* Column Headers */}
        <div className="flex items-center text-slate-400 border-b border-[rgba(255,255,255,0.06)] pb-1 mb-2">
          <span className="w-24">Offset</span>
          <div className="flex gap-2 flex-1 max-w-[420px]">
            {['00', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0A', '0B', '0C', '0D', '0E', '0F'].map((col, idx) => (
              <span key={col} className={`w-5 text-center ${idx === 7 ? 'mr-2' : ''}`}>{col}</span>
            ))}
          </div>
          <span className="w-36 pl-4">Decoded ASCII</span>
        </div>

        {/* Rows */}
        <div className="space-y-1">
          {rows.map((row, rIdx) => (
            <div key={row.offset} className="flex items-center hover:bg-[#111622] rounded px-1 py-0.5">
              {/* Offset Column */}
              <span className="hex-offset w-24">
                0x{row.offset.toString(16).padStart(8, '0').toUpperCase()}
              </span>

              {/* 16 Hex Bytes */}
              <div className="flex gap-2 flex-1 max-w-[420px]">
                {row.bytes.map((byte, bIdx) => {
                  const globalIdx = rIdx * 16 + bIdx;
                  const isHovered = hoveredIndex === globalIdx;
                  const isNull = byte === 0x00;

                  return (
                    <span
                      key={bIdx}
                      onMouseEnter={() => setHoveredIndex(globalIdx)}
                      onMouseLeave={() => setHoveredIndex(null)}
                      className={`w-5 text-center cursor-default rounded transition-colors ${
                        isHovered
                          ? 'bg-[#00f2fe] text-[#0a0d13] font-bold'
                          : isNull
                          ? 'text-slate-400'
                          : 'text-[#38bdf8]'
                      } ${bIdx === 7 ? 'mr-2' : ''}`}
                    >
                      {byte.toString(16).padStart(2, '0').toUpperCase()}
                    </span>
                  );
                })}
              </div>

              {/* ASCII Representation */}
              <div className="w-36 pl-4 flex font-mono">
                {row.bytes.map((byte, bIdx) => {
                  const globalIdx = rIdx * 16 + bIdx;
                  const isHovered = hoveredIndex === globalIdx;
                  const char = byte >= 0x20 && byte <= 0x7e ? String.fromCharCode(byte) : '.';

                  return (
                    <span
                      key={bIdx}
                      onMouseEnter={() => setHoveredIndex(globalIdx)}
                      onMouseLeave={() => setHoveredIndex(null)}
                      className={`w-[9px] text-center rounded transition-colors ${
                        isHovered
                          ? 'bg-[#00f2fe] text-[#0a0d13] font-bold'
                          : char === '.'
                          ? 'text-slate-400'
                          : 'text-slate-200'
                      }`}
                    >
                      {char}
                    </span>
                  );
                })}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};
