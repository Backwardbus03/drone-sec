"""
Forensic File Carving & Recovery Engine for Drone Forensic Toolkit.
Carves deleted UAV media (JPEG, MP4/MOV, PNG) and flight logs (DJI DAT, ArduPilot bin, PX4 ULog)
from raw physical disk images (.dd/.raw) and unallocated filesystem space.
"""

from pathlib import Path
from typing import List, Dict, Any, Optional
from dft.core.hashing import compute_hashes

# Standard Forensic File Signatures (Magic Headers & Footers)
SIGNATURES = [
    {
        "type": "JPEG_PHOTO",
        "extension": ".jpg",
        "header": b"\xff\xd8\xff",
        "footer": b"\xff\xd9",
        "max_size": 25 * 1024 * 1024  # 25 MB max per photo
    },
    {
        "type": "PNG_IMAGE",
        "extension": ".png",
        "header": b"\x89PNG\r\n\x1a\n",
        "footer": b"IEND\xaeB`\x82",
        "max_size": 15 * 1024 * 1024
    },
    {
        "type": "MP4_VIDEO",
        "extension": ".mp4",
        "header": b"ftyp",
        "header_offset": 4,  # e.g., \x00\x00\x00\x18ftyp
        "footer": None,
        "default_carve_len": 50 * 1024 * 1024
    },
    {
        "type": "PX4_ULOG",
        "extension": ".ulg",
        "header": b"ULog\x01\x12\x35",
        "footer": None,
        "default_carve_len": 10 * 1024 * 1024
    },
    {
        "type": "ARDUPILOT_DATAFLASH",
        "extension": ".bin",
        "header": b"\xa3\x95",
        "footer": None,
        "default_carve_len": 15 * 1024 * 1024
    }
]


class FileCarverEngine:
    @staticmethod
    def carve_image(raw_image_path: Path, output_dir: Path) -> List[Dict[str, Any]]:
        """
        Scans a raw disk image file byte-by-byte for known UAV file signatures
        and carves out orphaned/deleted forensic evidence artifacts.
        """
        src = Path(raw_image_path)
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        if not src.exists():
            raise FileNotFoundError(f"Raw image file not found: {src}")

        data = src.read_bytes()
        carved_results: List[Dict[str, Any]] = []
        carve_id = 1

        for sig in SIGNATURES:
            header = sig["header"]
            header_offset = sig.get("header_offset", 0)
            footer = sig.get("footer")
            max_size = sig.get("max_size", 20 * 1024 * 1024)

            pos = 0
            while True:
                idx = data.find(header, pos)
                if idx == -1:
                    break

                start_idx = max(0, idx - header_offset)
                end_idx = None

                if footer:
                    footer_idx = data.find(footer, idx + len(header))
                    if footer_idx != -1 and (footer_idx - start_idx + len(footer)) <= max_size:
                        end_idx = footer_idx + len(footer)

                if not end_idx:
                    # Carve up to default carve length or next 1MB block
                    end_idx = min(len(data), start_idx + sig.get("default_carve_len", 1024 * 1024))

                carved_bytes = data[start_idx:end_idx]
                if len(carved_bytes) > len(header):
                    out_filename = f"carved_{carve_id:04d}_{sig['type']}{sig['extension']}"
                    out_path = out / out_filename
                    out_path.write_bytes(carved_bytes)

                    manifest = compute_hashes(out_path)

                    carved_results.append({
                        "carve_id": carve_id,
                        "file_type": sig["type"],
                        "file_name": out_filename,
                        "byte_offset": start_idx,
                        "size_bytes": len(carved_bytes),
                        "hashes": manifest.model_dump()
                    })
                    carve_id += 1

                pos = idx + len(header) + 1
                if len(carved_results) >= 50:
                    break

        return carved_results
