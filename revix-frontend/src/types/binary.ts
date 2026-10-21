/**
 * ============================================================================
 * Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
 * Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
 * Copyright: (c) 2026 Fingvo. All rights reserved.
 * License: MIT License
 * ============================================================================
 * Description: Core TypeScript interfaces and types for binary metadata,
 *              hex inspection, disassembly streams, and threat scanning.
 * ============================================================================
 */

export type BinaryFormat = 'ELF' | 'PE' | 'MachO' | 'RawBinary';

export interface PeSection {
  name: string;
  virtual_size: number;
  virtual_address: number;
  raw_data_size: number;
  pointer_to_raw_data: number;
  characteristics: number;
  is_executable: boolean;
  is_readable: boolean;
  is_writable: boolean;
}

export interface PeHeaderInfo {
  is_64bit: boolean;
  machine: string;
  number_of_sections: number;
  timestamp: number;
  entry_point: number;
  image_base: number;
  subsystem: string;
  sections: PeSection[];
}

export interface ElfHeaderInfo {
  bitness: number;
  endianness: string;
  os_abi: string;
  object_type: string;
  architecture: string;
  entry_point: number;
  program_headers_offset: number;
  section_headers_offset: number;
  section_header_count: number;
}

export interface EntropyBlock {
  offset: number;
  size: number;
  score: number;
}

export interface EntropyReport {
  total_entropy: number;
  is_likely_packed: boolean;
  blocks: EntropyBlock[];
}

export interface ExtractedString {
  offset: number;
  length: number;
  encoding: 'ASCII' | 'UTF-16LE';
  value: string;
}

export interface DisassembledInstruction {
  address: number;
  bytes: string;
  mnemonic: string;
  operands: string;
  comment?: string;
}

export interface UnifiedBinaryReport {
  file_name: string;
  file_size: number;
  format: BinaryFormat;
  md5: string;
  sha256: string;
  architecture: string;
  bitness: number;
  endianness: string;
  entry_point: number;
  elf_info?: ElfHeaderInfo;
  pe_info?: PeHeaderInfo;
  entropy: EntropyReport;
  strings: ExtractedString[];
  raw_bytes?: Uint8Array;
  disassembly?: DisassembledInstruction[];
  threat_report?: ThreatReport;
}

export interface ThreatCapability {
  category: string;
  indicators: string[];
}

export interface ThreatReport {
  risk_score: number;
  risk_level: string;
  detected_signatures: Array<{
    category: string;
    name: string;
    description: string;
    offset: string;
  }>;
  detected_capabilities: Record<string, string[]>;
}
