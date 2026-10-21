# ============================================================================
# Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
# Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
# Copyright: (c) 2026 Fingvo. All rights reserved.
# License: MIT License
# ============================================================================
# Description: Automated Heuristic Security & Threat Capability Scanner.
# ============================================================================

import sys
import os
from typing import Dict, List, Any
from .signatures import scan_signatures

# High-risk native API calls categorized by threat behaviors
CAPABILITY_INDICATORS = {
    "Process Injection & Memory Tampering": [
        "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
        "NtUnmapViewOfSection", "QueueUserAPC", "SetThreadContext", "ptrace"
    ],
    "Anti-Analysis & Anti-Debugging": [
        "IsDebuggerPresent", "CheckRemoteDebuggerPresent", "NtQueryInformationProcess",
        "OutputDebugStringA", "OutputDebugStringW", "GetTickCount", "timeGetTime"
    ],
    "Persistence & Autostart": [
        "RegSetValueExA", "RegSetValueExW", "CreateServiceA", "CreateServiceW",
        "SetWindowsHookExA", "SetWindowsHookExW"
    ],
    "Network / Exfiltration / C2": [
        "InternetOpenA", "InternetOpenW", "HttpSendRequestA", "HttpSendRequestW",
        "URLDownloadToFileA", "URLDownloadToFileW", "WSAStartup", "connect", "socket"
    ],
    "Privilege Escalation & Token Stealing": [
        "OpenProcessToken", "AdjustTokenPrivileges", "LookupPrivilegeValueA",
        "DuplicateTokenEx", "ImpersonateLoggedOnUser"
    ]
}

class ScanReport:
    """
    Consolidated heuristic scan report summarizing detected capabilities,
    identified technology signatures, and calculated risk score.
    """
    def __init__(self, file_path: str, file_size: int):
        self.file_path = file_path
        self.file_size = file_size
        self.risk_score = 0
        self.risk_level = "LOW"
        self.detected_capabilities: Dict[str, List[str]] = {}
        self.detected_signatures: List[Dict[str, Any]] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "file_path": self.file_path,
            "file_size": self.file_size,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "detected_capabilities": self.detected_capabilities,
            "detected_signatures": self.detected_signatures,
        }

def scan_file(file_path: str) -> ScanReport:
    """
    Analyzes a binary file on disk for capabilities, indicators, and signatures.
    
    Parameters:
    - file_path: Path to target executable or binary
    
    Returns:
    - ScanReport object with structured findings
    """
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Target binary not found: {file_path}")

    with open(file_path, "rb") as f:
        data = f.read()

    report = ScanReport(file_path=file_path, file_size=len(data))

    # 1. Signature analysis (compilers, packers, crypto)
    signatures = scan_signatures(data)
    report.detected_signatures = [s.to_dict() for s in signatures]

    # Adjust score if a packer like UPX or Themida is present
    for sig in signatures:
        if sig.category == "Packer":
            report.risk_score += 25

    # 2. Heuristic string capability analysis
    for category, indicators in CAPABILITY_INDICATORS.items():
        found = []
        for api in indicators:
            api_bytes = api.encode("ascii")
            if api_bytes in data:
                found.append(api)
                report.risk_score += 15

        if found:
            report.detected_capabilities[category] = found

    # 3. Normalize risk score and classify level (Cap at 100)
    report.risk_score = min(report.risk_score, 100)

    if report.risk_score >= 70:
        report.risk_level = "CRITICAL / HIGH SUSPICION"
    elif report.risk_score >= 40:
        report.risk_level = "MEDIUM RISK"
    elif report.risk_score >= 20:
        report.risk_level = "LOW / NORMAL UTILITY"
    else:
        report.risk_level = "BENIGN"

    return report

def main():
    """CLI entrypoint for standalone Python scanning."""
    if len(sys.argv) < 2:
        print("Revix Heuristic Scanner v0.1.0")
        print("Author: Sohail MN (Aka Fingvo) - Full Stack Engineer")
        print("Copyright: (c) 2026 Fingvo. All rights reserved. (MIT License)")
        print("\nUsage: python -m revix_py.scanner <path_to_binary>")
        sys.exit(1)

    target_path = sys.argv[1]
    print(f"Scanning target: {target_path}")
    report = scan_file(target_path)

    print("=" * 60)
    print(f"REVIX SCAN RESULTS: {os.path.basename(report.file_path)}")
    print(f"Risk Score: {report.risk_score}/100 [{report.risk_level}]")
    print("=" * 60)

    print("\n[Identified Signatures]")
    if report.detected_signatures:
        for s in report.detected_signatures:
            print(f" - [{s['category']}] {s['name']} (Offset: {s['offset']})")
    else:
        print(" - No third-party packer or compiler signatures detected.")

    print("\n[Detected Capabilities]")
    if report.detected_capabilities:
        for cat, apis in report.detected_capabilities.items():
            print(f" - {cat}: {', '.join(apis)}")
    else:
        print(" - No high-risk API capabilities identified in string table.")

    print("=" * 60)

if __name__ == "__main__":
    main()
