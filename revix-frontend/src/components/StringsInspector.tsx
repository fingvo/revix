/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Searchable Strings Inspector for identifying hardcoded URLs,
 *              API names, error messages, and embedded registry keys.
 * ============================================================================
 */

import React, { useState } from 'react';
import { ExtractedString } from '../types/binary';
import { Type, Search, SlidersHorizontal, Copy, Check } from 'lucide-react';

interface StringsInspectorProps {
  strings: ExtractedString[];
}

export const StringsInspector: React.FC<StringsInspectorProps> = ({ strings }) => {
  const [searchTerm, setSearchTerm] = useState('');
  const [minLength, setMinLength] = useState(4);
  const [copiedOffset, setCopiedOffset] = useState<number | null>(null);

  const filtered = strings.filter(
    (s) =>
      s.length >= minLength &&
      s.value.toLowerCase().includes(searchTerm.toLowerCase())
  );

  const handleCopy = (val: string, offset: number) => {
    navigator.clipboard.writeText(val);
    setCopiedOffset(offset);
    setTimeout(() => setCopiedOffset(null), 1500);
  };

  return (
    <div className="sre-panel p-4 space-y-4">
      {/* Search & Filter Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-[rgba(255,255,255,0.06)] pb-3">
        <div className="flex items-center gap-2">
          <Type className="w-4 h-4 text-[#00f2fe]" />
          <h2 className="text-xs font-semibold text-slate-200 tracking-wider uppercase">
            Extracted String Table ({filtered.length} Discovered)
          </h2>
        </div>

        <div className="flex flex-wrap items-center gap-4">
          {/* Min Length Slider */}
          <div className="flex items-center gap-2 bg-[#0a0d13] px-3 py-1 rounded border border-[rgba(255,255,255,0.06)]">
            <SlidersHorizontal className="w-3.5 h-3.5 text-slate-400" />
            <span className="text-[11px] text-slate-400">Min Length: {minLength}</span>
            <input
              type="range"
              min="4"
              max="24"
              value={minLength}
              onChange={(e) => setMinLength(Number(e.target.value))}
              className="w-20 accent-[#00f2fe] cursor-pointer"
            />
          </div>

          {/* Search Box */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-2.5 top-2.5" />
            <input
              type="text"
              placeholder="Search strings (URL, API, key)..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="bg-[#0a0d13] border border-[rgba(255,255,255,0.1)] rounded pl-8 pr-3 py-1 text-xs font-mono text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-[#00f2fe] w-64"
            />
          </div>
        </div>
      </div>

      {/* String Items Table */}
      <div className="overflow-x-auto font-mono text-xs bg-[#080b10] rounded border border-[rgba(255,255,255,0.04)] max-h-[500px] overflow-y-auto">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-[#0d111a] border-b border-[rgba(255,255,255,0.06)] z-10">
            <tr className="text-slate-400 text-[11px]">
              <th className="py-2 px-3 w-32">Byte Offset</th>
              <th className="py-2 px-3 w-20">Length</th>
              <th className="py-2 px-3 w-28">Encoding</th>
              <th className="py-2 px-3">String Value</th>
              <th className="py-2 px-3 w-16 text-right">Action</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((item, idx) => {
              const isUrl = item.value.startsWith('http://') || item.value.startsWith('https://');
              const isApi = item.value.includes('Alloc') || item.value.includes('Thread') || item.value.includes('Debug');

              return (
                <tr
                  key={idx}
                  className="border-b border-[rgba(255,255,255,0.02)] hover:bg-[#111622] transition-colors"
                >
                  <td className="py-1.5 px-3 text-slate-400 select-all">
                    0x{item.offset.toString(16).toUpperCase()}
                  </td>
                  <td className="py-1.5 px-3 text-slate-400">{item.length}</td>
                  <td className="py-1.5 px-3">
                    <span className="sre-badge sre-badge-cyan text-[10px]">{item.encoding}</span>
                  </td>
                  <td className="py-1.5 px-3 text-slate-200 break-all">
                    <span
                      className={`${
                        isUrl
                          ? 'text-[#00f2fe] underline'
                          : isApi
                          ? 'text-amber-300 font-semibold'
                          : ''
                      }`}
                    >
                      {item.value}
                    </span>
                  </td>
                  <td className="py-1.5 px-3 text-right">
                    <button
                      onClick={() => handleCopy(item.value, item.offset)}
                      className="p-1 rounded hover:bg-[#182030] text-slate-400 hover:text-white transition-colors"
                      title="Copy string"
                    >
                      {copiedOffset === item.offset ? (
                        <Check className="w-3.5 h-3.5 text-emerald-400" />
                      ) : (
                        <Copy className="w-3.5 h-3.5" />
                      )}
                    </button>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
};
