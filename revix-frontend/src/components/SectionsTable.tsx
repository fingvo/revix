/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Binary Sections Table detailing virtual addresses, memory sizes,
 *              and executable/writable memory access flags.
 * ============================================================================
 */

import React from 'react';
import { PeSection } from '../types/binary';
import { Layers, AlertCircle, ShieldCheck } from 'lucide-react';

interface SectionsTableProps {
  sections?: PeSection[];
}

export const SectionsTable: React.FC<SectionsTableProps> = ({ sections }) => {
  if (!sections || sections.length === 0) {
    return (
      <div className="sre-panel p-6 text-center text-slate-400">
        <Layers className="w-8 h-8 mx-auto mb-2 text-slate-400" />
        <p className="text-sm">No structured PE section headers available for this binary format.</p>
      </div>
    );
  }

  return (
    <div className="sre-panel p-4 space-y-4">
      <div className="flex items-center justify-between border-b border-[rgba(255,255,255,0.06)] pb-3">
        <div className="flex items-center gap-2">
          <Layers className="w-4 h-4 text-[#00f2fe]" />
          <h2 className="text-xs font-semibold text-slate-200 tracking-wider uppercase">
            Binary Sections Header Map ({sections.length} Sections)
          </h2>
        </div>
        <span className="text-xs text-slate-400 font-mono">Memory Segments & Characteristics</span>
      </div>

      <div className="overflow-x-auto font-mono text-xs bg-[#080b10] rounded border border-[rgba(255,255,255,0.04)]">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[rgba(255,255,255,0.06)] text-slate-400 text-[11px] bg-[#0d111a]">
              <th className="py-2 px-3 w-28">Name</th>
              <th className="py-2 px-3 w-36">Virtual Address</th>
              <th className="py-2 px-3 w-32">Virtual Size</th>
              <th className="py-2 px-3 w-32">Raw Size</th>
              <th className="py-2 px-3 w-36">Permissions</th>
              <th className="py-2 px-3">Security Assessment</th>
            </tr>
          </thead>
          <tbody>
            {sections.map((sec, idx) => {
              const isWx = sec.is_writable && sec.is_executable;

              return (
                <tr
                  key={idx}
                  className={`border-b border-[rgba(255,255,255,0.02)] hover:bg-[#111622] transition-colors ${
                    isWx ? 'bg-rose-500/10' : ''
                  }`}
                >
                  {/* Name */}
                  <td className="py-2.5 px-3 font-semibold text-[#00f2fe]">
                    {sec.name}
                  </td>

                  {/* Virtual Address */}
                  <td className="py-2.5 px-3 text-slate-400 select-all">
                    0x{sec.virtual_address.toString(16).toUpperCase()}
                  </td>

                  {/* Virtual Size */}
                  <td className="py-2.5 px-3 text-slate-200">
                    {sec.virtual_size.toLocaleString()} B
                  </td>

                  {/* Raw Size */}
                  <td className="py-2.5 px-3 text-slate-200">
                    {sec.raw_data_size.toLocaleString()} B
                  </td>

                  {/* Permissions */}
                  <td className="py-2.5 px-3">
                    <div className="flex items-center gap-1.5">
                      {sec.is_readable && <span className="sre-badge sre-badge-cyan text-[10px]">R</span>}
                      {sec.is_writable && <span className="sre-badge sre-badge-amber text-[10px]">W</span>}
                      {sec.is_executable && <span className="sre-badge sre-badge-emerald text-[10px]">X</span>}
                    </div>
                  </td>

                  {/* Security Assessment */}
                  <td className="py-2.5 px-3">
                    {isWx ? (
                      <div className="flex items-center gap-1.5 text-rose-400 text-xs">
                        <AlertCircle className="w-3.5 h-3.5" />
                        <span>High Risk: W+X self-modifying code permission detected</span>
                      </div>
                    ) : (
                      <div className="flex items-center gap-1.5 text-slate-400 text-xs">
                        <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />
                        <span>Standard segment bounds</span>
                      </div>
                    )}
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
