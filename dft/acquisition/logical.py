"""
Logical Acquisition Module for Drone Forensic Toolkit.
Extracts files, flight logs, and media recursively from mounted UAV storage
while maintaining absolute file integrity and generating per-file cryptographic manifests.
"""

import shutil
from pathlib import Path
from typing import List, Dict, Any
from dft.core.hashing import compute_hashes
from dft.core.write_blocker import WriteBlockController


class LogicalAcquisitionEngine:
    @staticmethod
    def extract_directory(
        source_dir: Path,
        destination_dir: Path
    ) -> Dict[str, Any]:
        """
        Recursively copies all files from mounted UAV media into forensic vault
        and generates an itemized hash manifest for every file.
        """
        src = Path(source_dir)
        dest = Path(destination_dir)
        dest.mkdir(parents=True, exist_ok=True)

        wb_check = WriteBlockController.verify_read_only_status(src)
        manifests: List[Dict[str, Any]] = []
        total_bytes = 0

        for file_path in src.rglob("*"):
            if file_path.is_file():
                rel_path = file_path.relative_to(src)
                target_file = dest / rel_path
                target_file.parent.mkdir(parents=True, exist_ok=True)

                shutil.copy2(file_path, target_file)
                WriteBlockController.enforce_file_read_only(target_file)

                file_manifest = compute_hashes(target_file)
                total_bytes += file_manifest.byte_count

                manifests.append({
                    "relative_path": str(rel_path),
                    "file_name": file_path.name,
                    "hashes": file_manifest.model_dump()
                })

        return {
            "source_directory": str(src),
            "destination_vault": str(dest),
            "files_extracted_count": len(manifests),
            "total_bytes_extracted": total_bytes,
            "write_block_status": wb_check,
            "file_manifests": manifests
        }
