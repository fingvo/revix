// ============================================================================
// Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
// Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
// Copyright: (c) 2026 Fingvo. All rights reserved.
// License: MIT License
// ============================================================================
// Description: Shannon Entropy Calculator for detecting packed, compressed,
//              or encrypted binary sections and payloads.
// ============================================================================

use serde::{Deserialize, Serialize};

/// EntropyBlock represents an analyzed block of bytes along with its calculated
/// Shannon entropy score and byte offset range.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyBlock {
    pub offset: usize,
    pub size: usize,
    pub score: f64,
}

/// EntropyReport contains the overall file entropy as well as an array
/// of subdivided blocks suitable for generating visual wave/heat charts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    pub total_entropy: f64,
    pub is_likely_packed: bool,
    pub blocks: Vec<EntropyBlock>,
}

/// Calculate the Shannon Entropy for a given byte slice.
/// Formula: H = - sum( p(x) * log2( p(x) ) )
/// 
/// Returns a value between 0.0 and 8.0:
/// - 0.0 to 3.0: Highly predictable or padded data (zeros, spaces)
/// - 3.0 to 6.8: Normal uncompressed executable code and text
/// - 6.8 to 8.0: High randomness, indicating compression (UPX, etc.) or encryption
pub fn calculate_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }

    // Step 1: Count frequency of each byte (0..=255)
    let mut frequencies = [0usize; 256];
    for &byte in data {
        frequencies[byte as usize] += 1;
    }

    // Step 2: Sum p * log2(p) for all non-zero byte frequencies
    let total_len = data.len() as f64;
    let mut entropy = 0.0f64;

    for &count in &frequencies {
        if count > 0 {
            let p = count as f64 / total_len;
            entropy -= p * p.log2();
        }
    }

    entropy
}

/// Generate a full entropy report by dividing the binary into sequential blocks
/// of a specified window size (e.g., 512, 1024, or dynamically based on file size).
pub fn analyze_entropy(data: &[u8], target_blocks: usize) -> EntropyReport {
    if data.is_empty() {
        return EntropyReport {
            total_entropy: 0.0,
            is_likely_packed: false,
            blocks: Vec::new(),
        };
    }

    let total_entropy = calculate_shannon_entropy(data);
    let is_likely_packed = total_entropy > 7.1;

    // Determine window size dynamically to ensure smooth charting
    let num_blocks = if target_blocks == 0 { 64 } else { target_blocks };
    let block_size = (data.len() / num_blocks).max(64);

    let mut blocks = Vec::new();
    let mut offset = 0;

    while offset < data.len() {
        let end = (offset + block_size).min(data.len());
        let slice = &data[offset..end];
        let score = calculate_shannon_entropy(slice);

        blocks.push(EntropyBlock {
            offset,
            size: end - offset,
            score,
        });

        offset = end;
    }

    EntropyReport {
        total_entropy,
        is_likely_packed,
        blocks,
    }
}
