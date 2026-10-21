/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Main Master Workbench layout managing state, binary ingestion,
 *              active tab switching, and SRE modular views.
 *              Strict ZERO MOCK DATA policy.
 * ============================================================================
 */

import React, { useState } from 'react';
import { UnifiedBinaryReport } from './types/binary';
import { uploadAndInspectBinary } from './services/api';
import { Navbar } from './components/Navbar';
import { FileUpload } from './components/FileUpload';
import { OverviewPanel } from './components/OverviewPanel';
import { HexViewer } from './components/HexViewer';
import { DisassemblyViewer } from './components/DisassemblyViewer';
import { StringsInspector } from './components/StringsInspector';
import { SectionsTable } from './components/SectionsTable';
import { HeuristicScanner } from './components/HeuristicScanner';
import {
  Layers,
  Binary,
  Code2,
  Type,
  LayoutDashboard,
  ShieldAlert,
  Cpu,
} from 'lucide-react';

type TabKey = 'overview' | 'hex' | 'disassembly' | 'strings' | 'sections' | 'heuristics';

export const App: React.FC = () => {
  const [report, setReport] = useState<UnifiedBinaryReport | null>(null);
  const [activeTab, setActiveTab] = useState<TabKey>('overview');
  const [isLoading, setIsLoading] = useState<boolean>(false);

  const handleFileSelect = async (file: File) => {
    setIsLoading(true);
    try {
      const parsed = await uploadAndInspectBinary(file);
      setReport(parsed);
      setActiveTab('overview');
    } catch (err) {
      console.error('Failed to inspect binary:', err);
    } finally {
      setIsLoading(false);
    }
  };

  const handleClearBinary = () => {
    setReport(null);
    setActiveTab('overview');
  };

  const tabs: Array<{ key: TabKey; label: string; icon: React.ReactNode; count?: number }> = [
    { key: 'overview', label: 'Overview', icon: <LayoutDashboard className="w-4 h-4" /> },
    { key: 'hex', label: 'Hex Inspector', icon: <Binary className="w-4 h-4" /> },
    {
      key: 'disassembly',
      label: 'Disassembly',
      icon: <Code2 className="w-4 h-4" />,
      count: report?.disassembly?.length,
    },
    {
      key: 'strings',
      label: 'Strings',
      icon: <Type className="w-4 h-4" />,
      count: report?.strings?.length,
    },
    {
      key: 'sections',
      label: 'Sections',
      icon: <Layers className="w-4 h-4" />,
      count: report?.pe_info?.sections?.length,
    },
    {
      key: 'heuristics',
      label: 'Threat Heuristics',
      icon: <ShieldAlert className="w-4 h-4" />,
    },
  ];

  return (
    <div className="min-h-screen bg-[#0a0d13] flex flex-col font-sans">
      {/* Top Navbar */}
      <Navbar fileName={report?.file_name} onClearBinary={handleClearBinary} />

      {/* Main Container */}
      <main className="flex-1 max-w-7xl w-full mx-auto p-4 md:p-6 space-y-6">
        {/* Upload Zone */}
        <FileUpload onFileSelect={handleFileSelect} isLoading={isLoading} />

        {/* Tab Navigation */}
        <div className="flex flex-wrap items-center gap-2 border-b border-[rgba(255,255,255,0.08)] pb-2">
          {tabs.map((tab) => {
            const isActive = activeTab === tab.key;
            return (
              <button
                key={tab.key}
                onClick={() => setActiveTab(tab.key)}
                className={`flex items-center gap-2 px-4 py-2 rounded text-xs font-medium cursor-pointer transition-all duration-150 ${
                  isActive
                    ? 'bg-[#182030] text-[#00f2fe] border border-[rgba(0,242,254,0.3)] shadow-sm'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-[#111622]'
                }`}
              >
                {tab.icon}
                <span>{tab.label}</span>
                {tab.count !== undefined && (
                  <span className="text-[10px] bg-[#0a0d13] px-1.5 py-0.5 rounded text-slate-400 font-mono">
                    {tab.count}
                  </span>
                )}
              </button>
            );
          })}
        </div>

        {/* Active Tab View */}
        <div className="transition-all duration-200">
          {!report ? (
            <div className="sre-panel p-12 text-center space-y-4">
              <div className="w-14 h-14 rounded-full bg-[#111622] border border-[rgba(255,255,255,0.08)] flex items-center justify-center mx-auto text-[#00f2fe]">
                <Cpu className="w-7 h-7" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-semibold text-slate-100 font-mono">No Binary Target Ingested</h3>
                <p className="text-xs text-slate-400 max-w-md mx-auto">
                  Drag and drop any Windows executable (.exe, .dll), Linux ELF binary, or raw firmware byte stream into the upload box above to execute real-time reverse engineering analysis.
                </p>
              </div>
              <div className="flex flex-wrap items-center justify-center gap-2 pt-2">
                <span className="sre-badge sre-badge-cyan text-[10px]">Real Shannon Entropy</span>
                <span className="sre-badge sre-badge-emerald text-[10px]">Live Disassembly</span>
                <span className="sre-badge sre-badge-amber text-[10px]">PE / ELF Sections</span>
                <span className="sre-badge sre-badge-rose text-[10px]">Threat Capabilities</span>
              </div>
            </div>
          ) : (
            <>
              {activeTab === 'overview' && <OverviewPanel report={report} />}
              {activeTab === 'hex' && <HexViewer rawBytes={report.raw_bytes} />}
              {activeTab === 'disassembly' && (
                <DisassemblyViewer instructions={report.disassembly || []} />
              )}
              {activeTab === 'strings' && <StringsInspector strings={report.strings} />}
              {activeTab === 'sections' && (
                <SectionsTable sections={report.pe_info?.sections} />
              )}
              {activeTab === 'heuristics' && (
                <HeuristicScanner threatReport={report.threat_report} />
              )}
            </>
          )}
        </div>
      </main>

      {/* Global SRE Footer with Mandated Author Credits */}
      <footer className="border-t border-[rgba(255,255,255,0.06)] bg-[#0d111a] px-6 py-4 mt-auto text-center text-xs text-slate-400">
        <div className="max-w-7xl mx-auto flex flex-col md:flex-row items-center justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="font-mono font-semibold text-slate-200">Revix v0.1.0</span>
            <span>-</span>
            <span>React.js (TypeScript) + Rust Core + Python Heuristics</span>
          </div>

          <div>
            <span>Author: <strong>Sohail MN (Aka Fingvo)</strong> - Full Stack Engineer</span>
            <span className="mx-2">|</span>
            <span>Copyright (c) 2026 Fingvo. All rights reserved. (MIT License)</span>
          </div>
        </div>
      </footer>
    </div>
  );
};
