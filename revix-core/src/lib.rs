// ============================================================================
// Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
// Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
// Copyright: (c) 2026 Fingvo. All rights reserved.
// License: MIT License
// ============================================================================
// Description: Revix Core native library root exporting parsing, analysis,
//              and disassembling capabilities.
// ============================================================================

pub mod analyzer;
pub mod disassembler;
pub mod parser;

use md5::{Digest, Md5};
use sha2::Sha256;

/// Inspect a binary file from its raw in-memory byte slice.
/// Computes cryptographic hashes (MD5, SHA256), extracts format headers,
/// measures Shannon entropy, and extracts embedded strings.
///
/// Parameters:
/// - file_name: Original or provided name of the target file
/// - data: Byte slice containing the full binary content
pub fn inspect_binary(file_name: &str, data: &[u8]) -> parser::UnifiedBinaryReport {
    // 1. Calculate cryptographic verification hashes
    let mut md5_hasher = Md5::new();
    md5_hasher.update(data);
    let md5_hash = format!("{:x}", md5_hasher.finalize());

    let mut sha256_hasher = Sha256::new();
    sha256_hasher.update(data);
    let sha256_hash = format!("{:x}", sha256_hasher.finalize());

    // 2. Identify file format and parse corresponding headers
    let format = parser::detect_format(data);

    let mut architecture = "Unknown".to_string();
    let mut bitness = 0u8;
    let mut endianness = "Unknown".to_string();
    let mut entry_point = 0u64;

    let mut elf_info = None;
    let mut pe_info = None;

    match format {
        parser::BinaryFormat::ELF => {
            if let Ok(info) = parser::elf::parse_elf_header(data) {
                architecture = info.architecture.clone();
                bitness = info.bitness;
                endianness = info.endianness.clone();
                entry_point = info.entry_point;
                elf_info = Some(info);
            }
        }
        parser::BinaryFormat::PE => {
            if let Ok(info) = parser::pe::parse_pe_header(data) {
                architecture = info.machine.clone();
                bitness = if info.is_64bit { 64 } else { 32 };
                endianness = "Little Endian".to_string();
                entry_point = info.entry_point;
                pe_info = Some(info);
            }
        }
        parser::BinaryFormat::MachO => {
            architecture = "Mach-O Universal / Native".to_string();
            bitness = 64;
            endianness = "Native".to_string();
        }
        parser::BinaryFormat::RawBinary => {
            architecture = "Raw / Shellcode".to_string();
            bitness = 0;
            endianness = "Raw".to_string();
        }
    }

    // 3. Perform Shannon entropy calculations
    let entropy = analyzer::entropy::analyze_entropy(data, 64);

    // 4. Extract printable strings (min length 4)
    let strings = analyzer::strings::extract_all_strings(data, 4);

    parser::UnifiedBinaryReport {
        file_name: file_name.to_string(),
        file_size: data.len(),
        format,
        md5: md5_hash,
        sha256: sha256_hash,
        architecture,
        bitness,
        endianness,
        entry_point,
        elf_info,
        pe_info,
        entropy,
        strings,
    }
}
