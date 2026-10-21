// ============================================================================
// Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
// Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
// Copyright: (c) 2026 Fingvo. All rights reserved.
// License: MIT License
// ============================================================================
// Description: Linux Executable and Linkable Format (ELF) header and section parser.
// ============================================================================

use serde::{Deserialize, Serialize};

/// ElfHeaderInfo holds extracted metadata from an ELF binary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElfHeaderInfo {
    pub bitness: u8,              // 32 or 64 bit
    pub endianness: String,       // "Little Endian" or "Big Endian"
    pub os_abi: String,           // e.g., "UNIX - System V", "Linux"
    pub object_type: String,      // e.g., "EXEC (Executable file)", "DYN (Shared object)"
    pub architecture: String,     // e.g., "x86_64", "ARM", "AArch64", "RISC-V"
    pub entry_point: u64,         // Memory virtual address of entry point
    pub program_headers_offset: u64,
    pub section_headers_offset: u64,
    pub section_header_count: u16,
}

/// Checks if data starts with the standard ELF magic bytes: 0x7F, 'E', 'L', 'F'.
pub fn is_elf(data: &[u8]) -> bool {
    data.len() >= 4 && data[0] == 0x7F && data[1] == b'E' && data[2] == b'L' && data[3] == b'F'
}

/// Parses the ELF Identification and Main Header.
/// Supports both 32-bit (ELFCLASS32) and 64-bit (ELFCLASS64) formats.
pub fn parse_elf_header(data: &[u8]) -> Result<ElfHeaderInfo, String> {
    if !is_elf(data) {
        return Err("Not a valid ELF binary header".to_string());
    }

    if data.len() < 52 {
        return Err("File too small to contain complete ELF header".to_string());
    }

    // Byte 4: EI_CLASS (1 = 32-bit, 2 = 64-bit)
    let bitness = match data[4] {
        1 => 32,
        2 => 64,
        _ => return Err("Unknown ELF Class (bitness)".to_string()),
    };

    // Byte 5: EI_DATA (1 = Little Endian, 2 = Big Endian)
    let is_little_endian = data[5] == 1;
    let endianness = if is_little_endian {
        "Little Endian".to_string()
    } else {
        "Big Endian".to_string()
    };

    // Byte 7: EI_OSABI
    let os_abi = match data[7] {
        0x00 => "UNIX - System V",
        0x03 => "Linux",
        0x06 => "Solaris",
        0x09 => "FreeBSD",
        0x0C => "OpenBSD",
        _ => "Other / Unknown",
    }.to_string();

    // Helper functions to read numbers respecting endianness
    let read_u16 = |offset: usize| -> u16 {
        if offset + 2 > data.len() { return 0; }
        if is_little_endian {
            u16::from_le_bytes([data[offset], data[offset + 1]])
        } else {
            u16::from_be_bytes([data[offset], data[offset + 1]])
        }
    };

    let read_u64 = |offset: usize| -> u64 {
        if offset + 8 > data.len() { return 0; }
        if is_little_endian {
            u64::from_le_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
                data[offset+4], data[offset+5], data[offset+6], data[offset+7]
            ])
        } else {
            u64::from_be_bytes([
                data[offset], data[offset+1], data[offset+2], data[offset+3],
                data[offset+4], data[offset+5], data[offset+6], data[offset+7]
            ])
        }
    };

    let read_u32 = |offset: usize| -> u32 {
        if offset + 4 > data.len() { return 0; }
        if is_little_endian {
            u32::from_le_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
        } else {
            u32::from_be_bytes([data[offset], data[offset+1], data[offset+2], data[offset+3]])
        }
    };

    // Bytes 16-17: e_type
    let raw_type = read_u16(16);
    let object_type = match raw_type {
        1 => "REL (Relocatable object)",
        2 => "EXEC (Executable file)",
        3 => "DYN (Shared object / PIE Executable)",
        4 => "CORE (Core file)",
        _ => "Unknown ELF Type",
    }.to_string();

    // Bytes 18-19: e_machine
    let raw_machine = read_u16(18);
    let architecture = match raw_machine {
        0x03 => "x86 (Intel 80386)",
        0x3E => "x86_64 (AMD64 / Intel 64)",
        0x28 => "ARM",
        0xB7 => "AArch64 (ARM 64-bit)",
        0xF3 => "RISC-V",
        0x08 => "MIPS",
        _ => "Other / Unknown",
    }.to_string();

    let entry_point;
    let program_headers_offset;
    let section_headers_offset;
    let section_header_count;

    if bitness == 64 {
        entry_point = read_u64(24);
        program_headers_offset = read_u64(32);
        section_headers_offset = read_u64(40);
        section_header_count = read_u16(60);
    } else {
        entry_point = read_u32(24) as u64;
        program_headers_offset = read_u32(28) as u64;
        section_headers_offset = read_u32(32) as u64;
        section_header_count = read_u16(48);
    }

    Ok(ElfHeaderInfo {
        bitness,
        endianness,
        os_abi,
        object_type,
        architecture,
        entry_point,
        program_headers_offset,
        section_headers_offset,
        section_header_count,
    })
}
