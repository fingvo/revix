// ============================================================================
// Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
// Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
// Copyright: (c) 2026 Fingvo. All rights reserved.
// License: MIT License
// ============================================================================
// Description: Windows Portable Executable (PE / PE32+) header and section parser.
// ============================================================================

use serde::{Deserialize, Serialize};

/// PeSection holds metadata for a single section inside a PE file (e.g. .text, .data).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeSection {
    pub name: String,
    pub virtual_size: u32,
    pub virtual_address: u32,
    pub raw_data_size: u32,
    pub pointer_to_raw_data: u32,
    pub characteristics: u32,
    pub is_executable: bool,
    pub is_writable: bool,
    pub is_readable: bool,
}

/// PeHeaderInfo stores top-level attributes of a parsed Windows PE binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeHeaderInfo {
    pub is_64bit: bool,
    pub machine: String,
    pub number_of_sections: u16,
    pub timestamp: u32,
    pub entry_point: u64,
    pub image_base: u64,
    pub subsystem: String,
    pub sections: Vec<PeSection>,
}

/// Checks if data starts with DOS signature 'MZ' (0x4D, 0x5A).
pub fn is_pe(data: &[u8]) -> bool {
    data.len() >= 64 && data[0] == 0x4D && data[1] == 0x5A
}

/// Parses Windows PE header and section table.
pub fn parse_pe_header(data: &[u8]) -> Result<PeHeaderInfo, String> {
    if !is_pe(data) {
        return Err("Not a valid PE binary (Missing MZ signature)".to_string());
    }

    // Byte 0x3C in DOS header holds offset to PE signature (e_lfanew)
    let e_lfanew = u32::from_le_bytes([data[0x3C], data[0x3D], data[0x3E], data[0x3F]]) as usize;
    if e_lfanew + 24 > data.len() {
        return Err("Invalid e_lfanew offset pointing past EOF".to_string());
    }

    // Validate PE signature "PE\0\0" (0x50, 0x45, 0x00, 0x00)
    if data[e_lfanew] != b'P' || data[e_lfanew + 1] != b'E' || data[e_lfanew + 2] != 0 || data[e_lfanew + 3] != 0 {
        return Err("Missing valid PE\\0\\0 signature at e_lfanew".to_string());
    }

    // COFF Header starts at e_lfanew + 4
    let coff_offset = e_lfanew + 4;
    let machine_raw = u16::from_le_bytes([data[coff_offset], data[coff_offset + 1]]);
    let number_of_sections = u16::from_le_bytes([data[coff_offset + 2], data[coff_offset + 3]]);
    let timestamp = u32::from_le_bytes([data[coff_offset + 4], data[coff_offset + 5], data[coff_offset + 6], data[coff_offset + 7]]);
    let size_of_opt_header = u16::from_le_bytes([data[coff_offset + 16], data[coff_offset + 17]]) as usize;

    let machine = match machine_raw {
        0x014c => "x86 (Intel 386)",
        0x8664 => "x86_64 (AMD64)",
        0xaa64 => "ARM64",
        0x01c0 => "ARM",
        _ => "Unknown Machine",
    }.to_string();

    // Optional Header starts at coff_offset + 20
    let opt_offset = coff_offset + 20;
    let magic = u16::from_le_bytes([data[opt_offset], data[opt_offset + 1]]);
    let is_64bit = magic == 0x20b; // 0x10b is PE32 (32-bit), 0x20b is PE32+ (64-bit)

    let entry_point_raw = u32::from_le_bytes([data[opt_offset + 16], data[opt_offset + 17], data[opt_offset + 18], data[opt_offset + 19]]);
    let image_base: u64;

    let subsystem_raw = if is_64bit {
        image_base = u64::from_le_bytes([
            data[opt_offset + 24], data[opt_offset + 25], data[opt_offset + 26], data[opt_offset + 27],
            data[opt_offset + 28], data[opt_offset + 29], data[opt_offset + 30], data[opt_offset + 31]
        ]);
        u16::from_le_bytes([data[opt_offset + 68], data[opt_offset + 69]])
    } else {
        image_base = u32::from_le_bytes([data[opt_offset + 28], data[opt_offset + 29], data[opt_offset + 30], data[opt_offset + 31]]) as u64;
        u16::from_le_bytes([data[opt_offset + 68], data[opt_offset + 69]])
    };

    let subsystem = match subsystem_raw {
        1 => "Native Driver",
        2 => "Windows GUI",
        3 => "Windows CUI (Console)",
        _ => "Other / Unknown",
    }.to_string();

    let entry_point = image_base + (entry_point_raw as u64);

    // Section table immediately follows Optional Header
    let section_table_offset = opt_offset + size_of_opt_header;
    let mut sections = Vec::new();

    for i in 0..(number_of_sections as usize) {
        let sec_offset = section_table_offset + (i * 40);
        if sec_offset + 40 > data.len() { break; }

        let name_bytes = &data[sec_offset..sec_offset + 8];
        let name = String::from_utf8_lossy(name_bytes).trim_end_matches('\0').to_string();

        let virtual_size = u32::from_le_bytes([data[sec_offset + 8], data[sec_offset + 9], data[sec_offset + 10], data[sec_offset + 11]]);
        let virtual_address = u32::from_le_bytes([data[sec_offset + 12], data[sec_offset + 13], data[sec_offset + 14], data[sec_offset + 15]]);
        let raw_data_size = u32::from_le_bytes([data[sec_offset + 16], data[sec_offset + 17], data[sec_offset + 18], data[sec_offset + 19]]);
        let pointer_to_raw_data = u32::from_le_bytes([data[sec_offset + 20], data[sec_offset + 21], data[sec_offset + 22], data[sec_offset + 23]]);
        let characteristics = u32::from_le_bytes([data[sec_offset + 36], data[sec_offset + 37], data[sec_offset + 38], data[sec_offset + 39]]);

        let is_executable = (characteristics & 0x20000000) != 0;
        let is_readable = (characteristics & 0x40000000) != 0;
        let is_writable = (characteristics & 0x80000000) != 0;

        sections.push(PeSection {
            name,
            virtual_size,
            virtual_address,
            raw_data_size,
            pointer_to_raw_data,
            characteristics,
            is_executable,
            is_readable,
            is_writable,
        });
    }

    Ok(PeHeaderInfo {
        is_64bit,
        machine,
        number_of_sections,
        timestamp,
        entry_point,
        image_base,
        subsystem,
        sections,
    })
}
