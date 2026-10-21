// ============================================================================
// Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
// Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
// Copyright: (c) 2026 Fingvo. All rights reserved.
// License: MIT License
// ============================================================================
// Description: Disassembler abstraction layer for decoding x86/x86_64 instructions.
// ============================================================================

use serde::{Deserialize, Serialize};

/// DisassembledInstruction represents a single assembly instruction,
/// its virtual address, raw byte sequence, mnemonic, and operands.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DisassembledInstruction {
    pub address: u64,
    pub bytes: String,
    pub mnemonic: String,
    pub operands: String,
    pub comment: Option<String>,
}

/// Disassemble a sequence of bytes starting at a base virtual address.
/// Provides linear sweep disassembly for common x86/x64 instruction patterns.
pub fn disassemble_stream(data: &[u8], base_address: u64, max_instructions: usize) -> Vec<DisassembledInstruction> {
    let mut instructions = Vec::new();
    let mut offset = 0;
    let mut current_addr = base_address;

    while offset < data.len() && instructions.len() < max_instructions {
        let b = data[offset];

        // Basic linear sweep decoding for common prologue/epilogue/control flow opcodes
        let (len, mnemonic, operands, comment) = match b {
            0x55 => (1, "push", "rbp", Some("Standard function prologue: Save base pointer")),
            0x48 if offset + 2 < data.len() && data[offset + 1] == 0x89 && data[offset + 2] == 0xE5 => {
                (3, "mov", "rbp, rsp", Some("Standard function prologue: Set frame pointer"))
            },
            0x48 if offset + 2 < data.len() && data[offset + 1] == 0x83 && data[offset + 2] == 0xEC => {
                let sub_val = if offset + 3 < data.len() { data[offset + 3] } else { 0 };
                (4, "sub", "rsp, imm8", Some("Allocate local stack frame space"))
            },
            0x90 => (1, "nop", "", Some("No operation / Alignment padding")),
            0xC3 => (1, "ret", "", Some("Return to caller address")),
            0xCC => (1, "int3", "", Some("Software debug breakpoint")),
            0x31 if offset + 1 < data.len() && data[offset + 1] == 0xC0 => {
                (2, "xor", "eax, eax", Some("Zero-out accumulator return register"))
            },
            0xE8 if offset + 4 < data.len() => {
                let rel = i32::from_le_bytes([data[offset+1], data[offset+2], data[offset+3], data[offset+4]]);
                let target = (current_addr as i64 + 5 + rel as i64) as u64;
                (5, "call", "rel32", Some("Relative procedure call"))
            },
            0xE9 if offset + 4 < data.len() => {
                (5, "jmp", "rel32", Some("Unconditional near jump"))
            },
            0xEB if offset + 1 < data.len() => {
                (2, "jmp", "short rel8", Some("Unconditional short jump"))
            },
            0x74 if offset + 1 < data.len() => {
                (2, "je", "short rel8", Some("Jump if equal (Zero Flag = 1)"))
            },
            0x75 if offset + 1 < data.len() => {
                (2, "jne", "short rel8", Some("Jump if not equal (Zero Flag = 0)"))
            },
            _ => (1, "db", "byte", None),
        };

        let raw_slice = &data[offset..(offset + len).min(data.len())];
        let bytes_hex = hex::encode(raw_slice);

        instructions.push(DisassembledInstruction {
            address: current_addr,
            bytes: bytes_hex,
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            comment: comment.map(|s| s.to_string()),
        });

        offset += len;
        current_addr += len as u64;
    }

    instructions
}
