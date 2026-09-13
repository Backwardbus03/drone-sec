"""
Software Write-Block Controller & Verifier for Laptop Interfaces.
Enforces read-only compliance for forensic acquisition across USB and SD interfaces.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any


class WriteBlockController:
    @staticmethod
    def verify_read_only_status(target_path: Path) -> Dict[str, Any]:
        """
        Verifies that a target evidence volume, disk device, or directory is write-protected.
        Conducts an active canary write probe to verify write denial.
        """
        target = Path(target_path)
        if not target.exists():
            return {
                "verified": False,
                "reason": f"Path does not exist: {target}",
                "canary_write_blocked": False
            }

        # 1. Attribute Check
        is_directory = target.is_dir()

        # 2. Canary Write Attempt
        canary_blocked = False
        test_file = target / ".dft_canary_write_probe.tmp" if is_directory else None

        if test_file:
            try:
                with open(test_file, "wb") as f:
                    f.write(b"CANARY_TEST")
                # If we succeeded in writing, it's NOT write-blocked!
                canary_blocked = False
                # Clean up if written
                try:
                    os.remove(test_file)
                except Exception:
                    pass
            except (PermissionError, OSError):
                # Write was correctly denied
                canary_blocked = True
        else:
            # For a single file or raw image, try opening in append mode
            try:
                with open(target, "ab") as f:
                    pass
                canary_blocked = False
            except (PermissionError, OSError):
                canary_blocked = True

        return {
            "verified": canary_blocked,
            "target": str(target),
            "is_directory": is_directory,
            "canary_write_blocked": canary_blocked,
            "os_platform": sys.platform,
            "recommendation": "Media is safely write-inhibited." if canary_blocked else "WARNING: Write protection not active! Activate software read-only policy before physical acquisition."
        }

    @staticmethod
    def enforce_file_read_only(file_path: Path) -> bool:
        """Sets OS-level read-only permissions on an evidence file."""
        try:
            p = Path(file_path)
            if p.exists():
                # Remove write permissions
                current_mode = os.stat(p).st_mode
                os.chmod(p, current_mode & ~0o222)
                return True
        except Exception:
            return False
        return False
