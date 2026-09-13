"""
Automated Real Benchmark Dataset Downloader & Ingestion Pipeline.
Fetches genuine flight records, incident messages, binary ULogs, and aerial photos
from official open-access forensic and UAV research repositories.
"""

from pathlib import Path
from typing import Dict, Any, List, Optional
import urllib.request
import json
import ssl

from dft.core.hashing import compute_hashes

# Local benchmark data repository
BENCHMARK_DATA_DIR = Path("benchmarks/data")

# Official Public Source Catalog
REAL_DATA_SOURCES = {
    "dji_vto_raw_flight_record": {
        "url": "https://raw.githubusercontent.com/DroneNLP/dataset/main/case-study/raw/DJIFlightRecord_2024-11-10_%5B03-09-29%5D.txt",
        "dest_name": "vto_labs_dji_flight_record.txt",
        "description": "Real VTO Labs / DJI raw flight record (1.29 MB)",
        "expected_sha256": "24850c8c1656cfdb6e21af86fea9195b350b7a82080a612ae4e8fce8fc4ead7f"
    },
    "dji_vto_hash_manifest": {
        "url": "https://raw.githubusercontent.com/DroneNLP/dataset/main/case-study/raw/hash.json",
        "dest_name": "vto_labs_hash_manifest.json",
        "description": "Real cryptographic hash verification manifest from VTO Labs case study"
    },
    "airdata_decrypted_telemetry": {
        "url": "https://raw.githubusercontent.com/DroneNLP/dataset/main/case-study/decrypted/DJIFlightRecord_2024-11-10_%5B03-09-29%5D.csv",
        "dest_name": "airdata_dji_decrypted_telemetry.csv",
        "description": "Real decrypted flight record with thousands of high-frequency GPS fixes (1.53 MB)"
    },
    "px4_official_sample_ulog": {
        "url": "https://raw.githubusercontent.com/PX4/pyulog/master/test/sample.ulg",
        "dest_name": "px4_flight_sample.ulg",
        "description": "Real native binary ULog flight log from Dronecode PX4 (4.05 MB)"
    },
    "real_drone_aerial_photo_exif": {
        "url": "https://raw.githubusercontent.com/OpenDroneMap/odm_data_bellus/master/images/IMG_1297_RGB.jpg",
        "dest_name": "drone_aerial_photo_ebee.jpg",
        "description": "Real commercial drone aerial photo (SenseFly eBee) with full EXIF GPS metadata",
        "partial_header_only": False
    }
}


def get_benchmark_data_dir() -> Path:
    BENCHMARK_DATA_DIR.mkdir(parents=True, exist_ok=True)
    return BENCHMARK_DATA_DIR


def fetch_real_benchmark_data(target_keys: Optional[List[str]] = None) -> Dict[str, Any]:
    """
    Downloads real flight records, ULogs, and aerial photos into benchmarks/data/
    """
    dest_dir = get_benchmark_data_dir()
    downloaded: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    keys = target_keys or list(REAL_DATA_SOURCES.keys())

    # Create unverified SSL context if needed for corporate proxies/firewalls
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for key in keys:
        if key not in REAL_DATA_SOURCES:
            continue
        spec = REAL_DATA_SOURCES[key]
        dest_file = dest_dir / spec["dest_name"]

        # If already cached and valid size, skip re-download
        if dest_file.exists() and dest_file.stat().st_size > 1000:
            manifest = compute_hashes(dest_file)
            downloaded.append({
                "key": key,
                "file_name": dest_file.name,
                "size_bytes": dest_file.stat().st_size,
                "cached": True,
                "sha256": manifest.sha256,
                "description": spec["description"]
            })
            continue

        try:
            req = urllib.request.Request(spec["url"], headers={"User-Agent": "DFT-Forensics-Toolkit"})
            with urllib.request.urlopen(req, timeout=30, context=ctx) as resp:
                data = resp.read()

            dest_file.write_bytes(data)
            manifest = compute_hashes(dest_file)

            # Check expected hash if provided
            hash_match = True
            if "expected_sha256" in spec:
                hash_match = (manifest.sha256.lower() == spec["expected_sha256"].lower())

            downloaded.append({
                "key": key,
                "file_name": dest_file.name,
                "size_bytes": len(data),
                "cached": False,
                "sha256": manifest.sha256,
                "hash_matched": hash_match,
                "description": spec["description"]
            })
        except Exception as e:
            errors.append({
                "key": key,
                "url": spec["url"],
                "error": str(e)
            })

    return {
        "status": "SUCCESS" if not errors else ("PARTIAL" if downloaded else "FAILED"),
        "destination_directory": str(dest_dir.resolve()),
        "total_downloaded": len(downloaded),
        "total_errors": len(errors),
        "files": downloaded,
        "errors": errors
    }
