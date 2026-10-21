/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Drag-and-drop file ingestion zone for raw executable binaries.
 * ============================================================================
 */

import React, { useRef, useState } from 'react';
import { UploadCloud, FileCode } from 'lucide-react';

interface FileUploadProps {
  onFileSelect: (file: File) => void;
  isLoading: boolean;
}

export const FileUpload: React.FC<FileUploadProps> = ({ onFileSelect, isLoading }) => {
  const [isDragging, setIsDragging] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(true);
  };

  const handleDragLeave = () => {
    setIsDragging(false);
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    setIsDragging(false);
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      onFileSelect(e.dataTransfer.files[0]);
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      onFileSelect(e.target.files[0]);
    }
  };

  return (
    <div
      onDragOver={handleDragOver}
      onDragLeave={handleDragLeave}
      onDrop={handleDrop}
      onClick={() => fileInputRef.current?.click()}
      className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-all duration-200 ${
        isDragging
          ? 'border-[#00f2fe] bg-[#00f2fe]/5'
          : 'border-[rgba(255,255,255,0.12)] hover:border-[rgba(255,255,255,0.25)] bg-[#111622]/60'
      }`}
    >
      <input
        ref={fileInputRef}
        type="file"
        onChange={handleChange}
        className="hidden"
        accept=".exe,.dll,.bin,.elf,.so,.dylib,.sys,.o"
      />

      <div className="flex flex-col items-center justify-center gap-2">
        <div className="w-10 h-10 rounded-full bg-[#182030] flex items-center justify-center text-[#00f2fe]">
          <UploadCloud className="w-5 h-5" />
        </div>
        <div className="text-sm font-medium text-slate-200">
          {isLoading ? 'Processing & Dissecting Binary...' : 'Drop Binary or Click to Inspect'}
        </div>
        <p className="text-xs text-slate-400">
          Supports Windows PE (.exe, .dll), Linux ELF (.bin, .so), macOS Mach-O, and raw firmware dumps.
        </p>
      </div>
    </div>
  );
};
