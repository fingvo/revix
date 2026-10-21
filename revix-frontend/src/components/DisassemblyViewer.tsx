/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Linear Sweep & Recursive Disassembly instruction stream viewer.
 * ============================================================================
 */

import React, { useState } from 'react';
import { DisassembledInstruction } from '../types/binary';
import { Code2, Filter, CornerDownRight } from 'lucide-react';

interface DisassemblyViewerProps {
  instructions: DisassembledInstruction[];
}

export const DisassemblyViewer: React.FC<DisassemblyViewerProps> = ({ instructions }) => {
  const [filterText, setFilterText] = useState('');

  if (!instructions || instructions.length === 0) {
    return (
      <div className="sre-panel p-8 text-center space-y-3">
        <Code2 className="w-10 h-10 text-slate-500 mx-auto" />
        <h3 className="text-sm font-semibold text-slate-200">No Disassembly Stream Available</h3>
        <p className="text-xs text-slate-400 max-w-md mx-auto">
          Upload an x86 or x86_64 binary file to disassemble raw machine instructions into assembly mnemonics.
        </p>
      </div>
    );
  }

  const filtered = instructions.filter(
    (inst) =>
      inst.mnemonic.toLowerCase().includes(filterText.toLowerCase()) ||
      inst.operands.toLowerCase().includes(filterText.toLowerCase()) ||
      inst.address.toString(16).toLowerCase().includes(filterText.toLowerCase())
  );

  return (
    <div className="sre-panel p-4 space-y-4">
      {/* Top Bar Filter */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-[rgba(255,255,255,0.06)] pb-3">
        <div className="flex items-center gap-2">
          <Code2 className="w-4 h-4 text-[#00f2fe]" />
          <h2 className="text-xs font-semibold text-slate-200 tracking-wider uppercase">
            Disassembly Instruction Stream (x86_64)
          </h2>
        </div>

        <div className="flex items-center gap-2">
          <Filter className="w-3.5 h-3.5 text-slate-400" />
          <input
            type="text"
            placeholder="Filter mnemonic/operands (e.g. call, jmp)"
            value={filterText}
            onChange={(e) => setFilterText(e.target.value)}
            className="bg-[#0a0d13] border border-[rgba(255,255,255,0.1)] rounded px-3 py-1 text-xs font-mono text-slate-200 placeholder:text-slate-400 focus:outline-none focus:border-[#00f2fe]"
          />
        </div>
      </div>

      {/* Disassembly Table */}
      <div className="overflow-x-auto font-mono text-xs bg-[#080b10] rounded border border-[rgba(255,255,255,0.04)]">
        <table className="w-full text-left border-collapse">
          <thead>
            <tr className="border-b border-[rgba(255,255,255,0.06)] text-slate-400 text-[11px] bg-[#0d111a]">
              <th className="py-2 px-3 w-36">Virtual Address</th>
              <th className="py-2 px-3 w-40">Opcode Bytes</th>
              <th className="py-2 px-3 w-24">Mnemonic</th>
              <th className="py-2 px-3 w-64">Operands</th>
              <th className="py-2 px-3">Decompiler Comment / Analysis</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((inst, index) => {
              const isCallOrJump = ['call', 'jmp', 'je', 'jne', 'jz', 'jnz'].includes(inst.mnemonic.toLowerCase());
              const isRet = inst.mnemonic.toLowerCase() === 'ret';

              return (
                <tr
                  key={index}
                  className={`border-b border-[rgba(255,255,255,0.02)] hover:bg-[#111622] transition-colors ${
                    isCallOrJump ? 'bg-[#00f2fe]/5' : ''
                  }`}
                >
                  {/* Address */}
                  <td className="py-2 px-3 text-slate-400 select-all">
                    0x{inst.address.toString(16).toUpperCase()}
                  </td>

                  {/* Raw Opcode Bytes */}
                  <td className="py-2 px-3 text-slate-400 tracking-wider">
                    {inst.bytes.match(/.{1,2}/g)?.join(' ').toUpperCase()}
                  </td>

                  {/* Mnemonic */}
                  <td className="py-2 px-3">
                    <span
                      className={`font-semibold ${
                        isCallOrJump
                          ? 'text-[#00f2fe]'
                          : isRet
                          ? 'text-rose-400'
                          : 'text-amber-300'
                      }`}
                    >
                      {inst.mnemonic}
                    </span>
                  </td>

                  {/* Operands */}
                  <td className="py-2 px-3 text-slate-200">
                    {inst.operands}
                  </td>

                  {/* Comment */}
                  <td className="py-2 px-3 text-emerald-400 text-[11px] italic">
                    {inst.comment ? (
                      <div className="flex items-center gap-1.5">
                        <CornerDownRight className="w-3 h-3 text-slate-400" />
                        <span>; {inst.comment}</span>
                      </div>
                    ) : (
                      <span className="text-slate-400">-</span>
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
