# ============================================================================
# Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
# Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
# Copyright: (c) 2026 Fingvo. All rights reserved.
# License: MIT License
# ============================================================================
# Description: Automated Compiler, Packer, and Runtime Signature Matching Engine.
# ============================================================================

from typing import List, Dict, Any

class SignatureMatch:
    """
    Data structure representing a detected binary signature pattern.
    """
    def __init__(self, category: str, name: str, description: str, offset: int):
        self.category = category  # e.g., 'Packer', 'Compiler', 'Runtime', 'Crypto'
        self.name = name          # e.g., 'UPX', 'Rust Compiler', 'PyInstaller'
        self.description = description
        self.offset = offset

    def to_dict(self) -> Dict[str, Any]:
        return {
            "category": self.category,
            "name": self.name,
            "description": self.description,
            "offset": hex(self.offset),
        }

# Dictionary of binary byte patterns to match
SIGNATURE_PATTERNS = [
    # Packers and Protectors
    {
        "category": "Packer",
        "name": "UPX (Ultimate Packer for eXecutables)",
        "pattern": b"UPX!",
        "description": "Standard high-ratio executable compressor commonly used to pack binaries."
    },
    {
        "category": "Packer",
        "name": "UPX Section Marker",
        "pattern": b"UPX0",
        "description": "First section marker of a UPX packed executable."
    },
    {
        "category": "Packer",
        "name": "Themida / WinLicense Marker",
        "pattern": b"Themida",
        "description": "Commercial software protector with code virtualization and anti-debugger features."
    },
    # Compilers and Toolchains
    {
        "category": "Compiler",
        "name": "Rust Toolchain",
        "pattern": b"/rustc/",
        "description": "Compiled with the official Rust compiler toolchain."
    },
    {
        "category": "Compiler",
        "name": "Go (Golang) Runtime",
        "pattern": b"Go buildid",
        "description": "Compiled using the official Go toolchain with embedded Go build identifiers."
    },
    {
        "category": "Compiler",
        "name": "GCC (GNU Compiler Collection)",
        "pattern": b"GCC: (",
        "description": "GNU Compiler Collection build tag."
    },
    {
        "category": "Compiler",
        "name": "Clang / LLVM",
        "pattern": b"clang version",
        "description": "Clang LLVM compiler identifier."
    },
    {
        "category": "Compiler",
        "name": "Microsoft Visual C++ (MSVC)",
        "pattern": b"Microsoft Visual C++",
        "description": "MSVC runtime library reference or compilation marker."
    },
    # Packaging and Runtimes
    {
        "category": "Runtime",
        "name": "PyInstaller Executable",
        "pattern": b"MEI\x0c\x0b\x0a\x0b",
        "description": "Self-extracting Python application packaged with PyInstaller."
    },
    {
        "category": "Runtime",
        "name": "Electron / Node.js ASAR Archive",
        "pattern": b"\x04\x00\x00\x00{\"files\":",
        "description": "Embedded ASAR archive typical of Electron desktop applications."
    },
    # Cryptographic Constants
    {
        "category": "Crypto",
        "name": "MD5 Constant Initializer",
        "pattern": b"\x01\x23\x45\x67\x89\xab\xcd\xef",
        "description": "Standard MD5 hashing algorithm initialization constants."
    },
    {
        "category": "Crypto",
        "name": "AES S-Box Substitution Table",
        "pattern": b"\x63\x7c\x77\x7b\xf2\x6b\x6f\xc5",
        "description": "Rijndael AES S-box substitution table used in AES symmetric encryption."
    }
]

def scan_signatures(data: bytes) -> List[SignatureMatch]:
    """
    Scans the provided byte array for known signatures and returns all matches.
    
    Parameters:
    - data: Raw binary bytes to analyze
    
    Returns:
    - List of SignatureMatch instances detailing detected technologies
    """
    matches = []
    
    for sig in SIGNATURE_PATTERNS:
        pattern = sig["pattern"]
        start = 0
        while True:
            offset = data.find(pattern, start)
            if offset == -1:
                break
            matches.append(SignatureMatch(
                category=sig["category"],
                name=sig["name"],
                description=sig["description"],
                offset=offset
            ))
            # Move forward past current match
            start = offset + len(pattern)
            
    return matches
