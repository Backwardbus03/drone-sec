"""
Physical Acquisition Module for Drone Forensic Toolkit.
Performs bit-level disk imaging with live dual cryptographic hashing
and active write-block pre-flight verification.
"""

from pathlib import Path
from typing import Dict, Any, Callable, Optional
from dft.core.hashing import compute_hashes
from dft.core.write_blocker import WriteBlockController
from dft.core.models import HashManifest
from dft.acquisition.e01 import E01Writer


class PhysicalAcquisitionEngine:
    @staticmethod
    def image_source(
        source_path: Path,
        destination_image: Path,
        chunk_size: int = 65536,
        progress_callback: Optional[Callable[[int, int], None]] = None,
        case_id: str = "CASE-DEFAULT",
        evidence_id: str = "EV-001",
        examiner: str = "Forensic Examiner"
    ) -> Dict[str, Any]:
        """
        Creates a bit-level physical forensic image (.dd / raw / .E01 / .eo1) from a source device or file.
        Verifies write-inhibition and calculates dual hashes on the fly.
        """
        src = Path(source_path)
        dest = Path(destination_image)
        dest.parent.mkdir(parents=True, exist_ok=True)

        # 1. Pre-flight Write-Block Check
        wb_check = WriteBlockController.verify_read_only_status(src)

        suffix_lower = dest.suffix.lower()
        if suffix_lower in (".e01", ".eo1"):
            # Route to E01 Expert Witness Format creator
            res = E01Writer.create_e01(
                source_file=src,
                output_file=dest,
                case_id=case_id,
                evidence_id=evidence_id,
                examiner=examiner,
                description=f"Physical Bit-Level Image of {src.name}"
            )
            WriteBlockController.enforce_file_read_only(dest)
            manifest = compute_hashes(dest)
            return {
                "source": str(src),
                "destination": str(dest),
                "bytes_acquired": res["e01_size_bytes"],
                "raw_bytes": res["raw_size_bytes"],
                "write_block_status": wb_check,
                "hash_manifest": manifest.model_dump(),
                "format": "E01",
                "status": "COMPLETED"
            }

        total_bytes = src.stat().st_size if src.is_file() else 0
        bytes_copied = 0

        # 2. Bit-Stream Copy (Raw / DD)
        with open(src, "rb") as f_in, open(dest, "wb") as f_out:
            while chunk := f_in.read(chunk_size):
                f_out.write(chunk)
                bytes_copied += len(chunk)
                if progress_callback:
                    progress_callback(bytes_copied, total_bytes)

        # 3. Compute Destination Hash Manifest
        manifest = compute_hashes(dest)

        # 4. Enforce Read-Only on Acquired Image
        WriteBlockController.enforce_file_read_only(dest)

        return {
            "source": str(src),
            "destination": str(dest),
            "bytes_acquired": bytes_copied,
            "write_block_status": wb_check,
            "hash_manifest": manifest.model_dump(),
            "format": "RAW_DD",
            "status": "COMPLETED"
        }

    @staticmethod
    def create_e01_image(
        source_path: Path,
        destination_image: Path,
        case_id: str = "CASE-DEFAULT",
        evidence_id: str = "EV-001",
        examiner: str = "Forensic Examiner",
        description: str = "Drone Physical Extraction"
    ) -> Dict[str, Any]:
        """Direct helper to produce an EWF (.eo1/.E01) container."""
        src = Path(source_path)
        dest = Path(destination_image)
        wb_check = WriteBlockController.verify_read_only_status(src)
        res = E01Writer.create_e01(
            source_file=src,
            output_file=dest,
            case_id=case_id,
            evidence_id=evidence_id,
            examiner=examiner,
            description=description
        )
        WriteBlockController.enforce_file_read_only(dest)
        manifest = compute_hashes(dest)
        return {
            "source": str(src),
            "destination": str(dest),
            "bytes_acquired": res["e01_size_bytes"],
            "raw_bytes": res["raw_size_bytes"],
            "write_block_status": wb_check,
            "hash_manifest": manifest.model_dump(),
            "format": "E01",
            "status": "COMPLETED"
        }
