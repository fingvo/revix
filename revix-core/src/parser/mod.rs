// ============================================================================
// Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
// Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
// Copyright: (c) 2026 Fingvo. All rights reserved.
// License: MIT License
// ============================================================================
// Description: Unified binary format detection and parser coordinator.
// ============================================================================

pub mod elf;
pub mod pe;

use serde::{Deserialize, Serialize};

/// BinaryFormat enum describes the identified file category.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BinaryFormat {
    ELF,
    PE,
    MachO,
    RawBinary,
}

/// UnifiedBinaryReport aggregates metadata, hashes, sections, entropy, and strings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnifiedBinaryReport {
    pub file_name: String,
    pub file_size: usize,
    pub format: BinaryFormat,
    pub md5: String,
    pub sha256: String,
    pub architecture: String,
    pub bitness: u8,
    pub endianness: String,
    pub entry_point: u64,
    pub elf_info: Option<elf::ElfHeaderInfo>,
    pub pe_info: Option<pe::PeHeaderInfo>,
    pub entropy: crate::analyzer::entropy::EntropyReport,
    pub strings: Vec<crate::analyzer::strings::ExtractedString>,
}

/// Detects binary format based on magic bytes.
pub fn detect_format(data: &[u8]) -> BinaryFormat {
    if elf::is_elf(data) {
        BinaryFormat::ELF
    } else if pe::is_pe(data) {
        BinaryFormat::PE
    } else if data.len() >= 4 && (
        (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA && (data[3] == 0xCE || data[3] == 0xCF)) ||
        (data[0] == 0xCF && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE)
    ) {
        BinaryFormat::MachO
    } else {
        BinaryFormat::RawBinary
    }
}
