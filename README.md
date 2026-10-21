# Revix

<h3 align="center">One MCP for reverse engineering across binaries, applications, and runtime behavior.</h3>
<p align="center"><b>See a feature you like. Understand how it works, down to the binary level.</b></p>

<p align="center">
  <img src="https://img.shields.io/badge/License-MIT-blue?style=flat-square" alt="MIT License" />
  <img src="https://img.shields.io/badge/Rust-Core%20Engine-DEA584?style=flat-square" alt="Rust Core Engine" />
  <img src="https://img.shields.io/badge/Frontend-React%20%2F%20TypeScript-3178C6?style=flat-square" alt="React TypeScript" />
  <img src="https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square" alt="Python 3.10+" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-gray?style=flat-square" alt="Platforms" />
</p>

Author: **Sohail MN (Aka Fingvo) - Full Stack Engineer**  
Copyright: **(c) 2026 Fingvo. All rights reserved.**  
License: **MIT License**

---

## Overview

Revix is a modern, modular, open-source Software Reverse Engineering (SRE) workbench designed for rapid binary analysis, malware forensics, firmware inspection, and decompilation assistance. 

Revix combines:
1. **Frontend UI:** A responsive, dark cyber-themed React.js (TypeScript) workbench providing interactive hex exploration, disassembly instruction inspection, Shannon entropy visualization, and symbol filtering.
2. **Core Engine:** A blazing-fast native Rust backend capable of parallel parsing of PE (Windows), ELF (Linux), and Mach-O headers, section mapping, and cryptographic hash verification.
3. **Automated Analytics:** A Python automation suite for heuristic checks, compiler/packer signature detection, and bridge connections to Ghidra and Frida.

---

## Architectural Breakdown

```
                            +-----------------------------------------+
                            |       Revix React.js Frontend           |
                            |   (TypeScript / Modern Dark Obsidian)   |
                            |  - Interactive Hex & ASCII Inspector    |
                            |  - Assembly Disassembly Stream          |
                            |  - Shannon Entropy Graph Visualizer     |
                            |  - Searchable Strings & Symbol Tables   |
                            +--------------------+--------------------+
                                                 |
                                     REST / JSON API Calls
                                                 |
                                                 v
                            +--------------------+--------------------+
                            |        Revix Core Engine (Rust)         |
                            |  - ELF & PE Binary Header Parsers       |
                            |  - Fast Shannon Entropy Calculation     |
                            |  - Native ASCII/Unicode String Search   |
                            |  - High Throughput Local HTTP Server    |
                            +--------------------+--------------------+
                                                 |
                                        IPC / Worker Pipes
                                                 |
                                                 v
                            +--------------------+--------------------+
                            |     Revix Automation Engine (Python)    |
                            |  - Heuristic Vulnerability Rules        |
                            |  - Compiler & Packer Signature Matcher  |
                            |  - PyGhidra Headless Integration        |
                            +-----------------------------------------+
```

---

## Project Structure

```
revix/
|-- LICENSE                     # Official MIT License with Copyright (c) 2026 Fingvo
|-- README.md                    # Project Documentation and Architecture Guide
|-- .gitignore                  # Production multi-language gitignore rules
|-- revix-core/                 # High-Performance Rust Native Engine
|   |-- Cargo.toml              # Dependencies (Axum, Tokio, Serde, Sha2, Md-5)
|   `-- src/
|       |-- lib.rs              # Core library export
|       |-- main.rs             # CLI and Axum API Server entrypoint
|       |-- parser/             # ELF and PE binary parsers
|       |-- analyzer/           # Shannon entropy and string extraction
|       `-- disassembler/       # Opcode and assembly abstraction
|-- revix-engine-py/            # Python Automation and Signature Engine
|   |-- requirements.txt        # Python package dependencies
|   `-- revix_py/
|       |-- __init__.py         # Package initialization
|       |-- scanner.py          # Automated security and heuristics scanner
|       |-- signatures.py       # Known compiler and packer signatures
|       `-- decompiler_bridge.py# Headless Ghidra / PyGhidra integration bridge
`-- revix-frontend/             # React.js + TypeScript Web Workbench
    |-- package.json            # React, Vite, Lucide, Canvas dependencies
    |-- tsconfig.json           # Strict TypeScript configuration
    |-- vite.config.ts          # Vite bundler configuration
    |-- index.html              # HTML5 root with custom dark styling
    `-- src/
        |-- App.tsx             # Main dashboard layout
        |-- types/              # Type definitions for binary inspection
        |-- components/         # Modular SRE components
        |-- services/           # Backend API integration client
        `-- styles/             # Obsidian cyber color tokens and styling
```

---

## Getting Started

### 1. Frontend Setup (React.js + TypeScript)
```bash
cd revix-frontend
npm install
npm run dev
```

### 2. Core Engine Setup (Rust)
```bash
cd revix-core
cargo build --release
cargo run
```

### 3. Python Automation Engine Setup
```bash
cd revix-engine-py
python -m venv venv
# Windows: venv\Scripts\activate
# Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
python -m revix_py.scanner --help
```

---

## License & Author Credits

* **Author:** Sohail MN (Aka Fingvo) - Full Stack Engineer
* **Copyright:** Copyright (c) 2026 Fingvo. All rights reserved.
* **License:** MIT License (Refer to LICENSE file for details).
