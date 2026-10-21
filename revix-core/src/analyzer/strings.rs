// ============================================================================
// Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
// Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
// Copyright: (c) 2026 Fingvo. All rights reserved.
// License: MIT License
// ============================================================================
// Description: High-speed ASCII and UTF-16 LE string extractor for binary forensics.
// ============================================================================

use serde::{Deserialize, Serialize};

/// ExtractedString holds a discovered human-readable sequence of characters,
/// its byte offset inside the binary, length, and encoding type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractedString {
    pub offset: usize,
    pub length: usize,
    pub encoding: String,
    pub value: String,
}

/// Extract printable ASCII strings from raw byte slices.
///
/// Parameters:
/// - data: Byte slice of the binary file
/// - min_length: Minimum number of consecutive printable ASCII characters (default 4)
pub fn extract_ascii_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut current_string = Vec::new();
    let mut start_offset = 0;

    for (i, &byte) in data.iter().enumerate() {
        // Printable ASCII range: 0x20 (space) to 0x7E (~)
        if (0x20..=0x7E).contains(&byte) {
            if current_string.is_empty() {
                start_offset = i;
            }
            current_string.push(byte);
        } else {
            if current_string.len() >= min_length {
                if let Ok(val) = String::from_utf8(current_string.clone()) {
                    results.push(ExtractedString {
                        offset: start_offset,
                        length: current_string.len(),
                        encoding: "ASCII".to_string(),
                        value: val,
                    });
                }
            }
            current_string.clear();
        }
    }

    // Flush any pending string at the end of data
    if current_string.len() >= min_length {
        if let Ok(val) = String::from_utf8(current_string.clone()) {
            results.push(ExtractedString {
                offset: start_offset,
                length: current_string.len(),
                encoding: "ASCII".to_string(),
                value: val,
            });
        }
    }

    results
}

/// Extract wide/Unicode (UTF-16 Little Endian) strings commonly used in Windows PE binaries.
///
/// Parameters:
/// - data: Byte slice of the binary file
/// - min_length: Minimum number of UTF-16 code units (default 4)
pub fn extract_utf16_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut results = Vec::new();
    let mut current_chars = Vec::new();
    let mut start_offset = 0;

    let mut i = 0;
    while i + 1 < data.len() {
        let low = data[i];
        let high = data[i + 1];

        // Standard printable ASCII represented in UTF-16LE has high byte 0x00
        if high == 0x00 && (0x20..=0x7E).contains(&low) {
            if current_chars.is_empty() {
                start_offset = i;
            }
            current_chars.push(low as char);
            i += 2;
        } else {
            if current_chars.len() >= min_length {
                let val: String = current_chars.iter().collect();
                results.push(ExtractedString {
                    offset: start_offset,
                    length: current_chars.len(),
                    encoding: "UTF-16LE".to_string(),
                    value: val,
                });
            }
            current_chars.clear();
            i += 2;
        }
    }

    if current_chars.len() >= min_length {
        let val: String = current_chars.iter().collect();
        results.push(ExtractedString {
            offset: start_offset,
            length: current_chars.len(),
            encoding: "UTF-16LE".to_string(),
            value: val,
        });
    }

    results
}

/// Combined extractor that extracts both ASCII and UTF-16LE strings and sorts them by offset.
pub fn extract_all_strings(data: &[u8], min_length: usize) -> Vec<ExtractedString> {
    let mut all = extract_ascii_strings(data, min_length);
    let mut utf16 = extract_utf16_strings(data, min_length);
    all.append(&mut utf16);
    all.sort_by_key(|s| s.offset);
    all
}
