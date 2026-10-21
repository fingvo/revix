# ============================================================================
# Project: Revix - Open Source Software Reverse Engineering & Binary Inspection Framework
# Author: Sohail MN (Aka Fingvo) - Full Stack Engineer
# Copyright: (c) 2026 Fingvo. All rights reserved.
# License: MIT License
# ============================================================================
# Description: Headless Ghidra & PyGhidra Automation Bridge.
# ============================================================================

import os
import subprocess
from typing import Optional, Dict, Any

class GhidraBridge:
    """
    Bridge utility to invoke Ghidra in headless batch mode (analyzeHeadless)
    or via PyGhidra for automated function deconstruction.
    """
    def __init__(self, ghidra_home: Optional[str] = None):
        self.ghidra_home = ghidra_home or os.environ.get("GHIDRA_HOME")

    def is_available(self) -> bool:
        """Checks if a valid Ghidra installation is reachable."""
        if not self.ghidra_home:
            return False
        headless_bat = os.path.join(self.ghidra_home, "support", "analyzeHeadless.bat")
        headless_sh = os.path.join(self.ghidra_home, "support", "analyzeHeadless")
        return os.path.exists(headless_bat) or os.path.exists(headless_sh)

    def run_headless_script(self, project_dir: str, project_name: str, binary_path: str, post_script: str) -> Dict[str, Any]:
        """
        Executes a headless analysis run with a post-processing script.
        
        Parameters:
        - project_dir: Temporary directory for Ghidra project storage
        - project_name: Internal project identifier
        - binary_path: Path to target executable file
        - post_script: Ghidra Java/Python post-script name
        """
        if not self.is_available():
            return {
                "status": "error",
                "message": "GHIDRA_HOME environment variable not set or invalid."
            }

        executable = os.path.join(self.ghidra_home, "support", "analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")

        command = [
            executable,
            project_dir,
            project_name,
            "-import", binary_path,
            "-postScript", post_script,
            "-deleteProject"
        ]

        try:
            result = subprocess.run(command, capture_output=True, text=True, check=True)
            return {
                "status": "success",
                "stdout": result.stdout,
            }
        except subprocess.CalledProcessError as e:
            return {
                "status": "error",
                "message": e.stderr
            }
