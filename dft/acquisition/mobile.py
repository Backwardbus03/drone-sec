"""
Mobile Acquisition Engine for Drone Forensic Toolkit (DFT).
Handles mobile device evidence acquisition, mobile backup archives (ZIP/TAR/TAR.GZ),
targeted Android companion app extractions, cryptographic dual hashing,
and strict write-blocking in compliance with ISO/IEC 27037:2012.
"""

import os
import shutil
import tarfile
import zipfile
from pathlib import Path
from typing import List, Dict, Any, Optional

from dft.core.hashing import compute_hashes
from dft.core.write_blocker import WriteBlockController


KNOWN_COMPANION_PACKAGES = {
    "dji.go.v5": {
        "app_name": "DJI Fly",
        "platform": "DJI",
        "paths": ["/sdcard/DJI/dji.go.v5/", "/data/data/dji.go.v5/"]
    },
    "dji.go.v4": {
        "app_name": "DJI GO 4",
        "platform": "DJI",
        "paths": ["/sdcard/DJI/dji.go.v4/", "/data/data/dji.go.v4/"]
    },
    "dji.pilot": {
        "app_name": "DJI GO / Pilot",
        "platform": "DJI",
        "paths": ["/sdcard/DJI/dji.pilot/", "/data/data/dji.pilot/"]
    },
    "com.dji.industry.pilot": {
        "app_name": "DJI Pilot 2 Enterprise",
        "platform": "DJI",
        "paths": ["/sdcard/DJI/com.dji.industry.pilot/"]
    },
    "com.flylitchi.litchi": {
        "app_name": "Litchi for DJI Drones",
        "platform": "DJI",
        "paths": ["/sdcard/Litchi/flightlogs/", "/sdcard/Litchi/missions/", "/data/data/com.flylitchi.litchi/"]
    },
    "org.mavlink.qgroundcontrol": {
        "app_name": "QGroundControl Mobile",
        "platform": "ArduPilot / PX4",
        "paths": ["/sdcard/Documents/QGroundControl/", "/sdcard/QGroundControl/Telemetry/", "/data/data/org.mavlink.qgroundcontrol/"]
    },
    "org.droidplanner.android": {
        "app_name": "3DR Tower / DroidPlanner",
        "platform": "ArduPilot",
        "paths": ["/sdcard/DroidPlanner/", "/sdcard/Tower/logs/"]
    },
    "com.geeksville.andropilot": {
        "app_name": "AndroPilot",
        "platform": "ArduPilot",
        "paths": ["/sdcard/AndroPilot/"]
    },
    "com.parrot.freeflight6": {
        "app_name": "Parrot FreeFlight 6",
        "platform": "Parrot",
        "paths": ["/sdcard/Parrot/", "/data/data/com.parrot.freeflight6/files/"]
    },
    "com.parrot.freeflightpro": {
        "app_name": "Parrot FreeFlight Pro",
        "platform": "Parrot",
        "paths": ["/sdcard/Parrot/", "/data/data/com.parrot.freeflightpro/files/"]
    },
    "com.runcam.speedybee": {
        "app_name": "SpeedyBee Mobile App",
        "platform": "Betaflight / iNav",
        "paths": ["/sdcard/SpeedyBee/Blackbox/", "/sdcard/SpeedyBee/Config/", "/sdcard/SpeedyBee/CLI/"]
    },
    "com.ezio.multiwii": {
        "app_name": "EZ-GUI Ground Station",
        "platform": "Betaflight / Cleanflight",
        "paths": ["/sdcard/EZ-GUI/"]
    },
    "com.autel.explorer": {
        "app_name": "Autel Explorer",
        "platform": "Autel Robotics",
        "paths": ["/sdcard/Autel/FlightRecord/", "/sdcard/Autel/Mission/"]
    }
}


class MobileAcquisitionEngine:
    """Forensic acquisition and archive extraction for mobile companion app evidence."""

    @staticmethod
    def extract_mobile_archive(archive_path: Path, destination_vault: Path) -> Dict[str, Any]:
        """
        Safely unpacks a mobile backup archive (.zip, .tar, .tar.gz, .tgz) into the forensic vault.
        Protects against path traversal (Zip Slip), enforces read-only write-blocking,
        and computes cryptographic hashes for every extracted artifact.
        """
        src = Path(archive_path)
        dest = Path(destination_vault)
        dest.mkdir(parents=True, exist_ok=True)

        if not src.exists():
            raise FileNotFoundError(f"Mobile archive not found: {src}")

        archive_hashes = compute_hashes(src)
        extracted_files: List[Dict[str, Any]] = []
        total_extracted_bytes = 0

        ext = src.suffix.lower()
        is_tar = ext in [".tar", ".gz", ".tgz"] or src.name.endswith(".tar.gz")

        if is_tar:
            with tarfile.open(src, "r:*") as tar:
                for member in tar.getmembers():
                    # Zip Slip / Path Traversal Guard
                    target = (dest / member.name).resolve()
                    if not str(target).startswith(str(dest.resolve())):
                        continue
                    if member.isfile():
                        tar.extract(member, path=dest)
                        WriteBlockController.enforce_file_read_only(target)
                        file_hashes = compute_hashes(target)
                        total_extracted_bytes += file_hashes.byte_count
                        extracted_files.append({
                            "relative_path": str(target.relative_to(dest)),
                            "file_name": target.name,
                            "hashes": file_hashes.model_dump()
                        })
        else:
            # Assume ZIP format (.zip, .apk, .ipa, or raw zip archive)
            with zipfile.ZipFile(src, "r") as z:
                for file_info in z.infolist():
                    if file_info.is_dir():
                        continue
                    target = (dest / file_info.filename).resolve()
                    # Path Traversal Guard
                    if not str(target).startswith(str(dest.resolve())):
                        continue
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with z.open(file_info) as source_f, open(target, "wb") as dest_f:
                        shutil.copyfileobj(source_f, dest_f)

                    WriteBlockController.enforce_file_read_only(target)
                    file_hashes = compute_hashes(target)
                    total_extracted_bytes += file_hashes.byte_count
                    extracted_files.append({
                        "relative_path": str(target.relative_to(dest)),
                        "file_name": target.name,
                        "hashes": file_hashes.model_dump()
                    })

        return {
            "source_archive": str(src),
            "archive_hashes": archive_hashes.model_dump(),
            "destination_vault": str(dest),
            "files_extracted_count": len(extracted_files),
            "total_bytes_extracted": total_extracted_bytes,
            "extracted_files": extracted_files
        }

    @staticmethod
    def import_mobile_directory(source_dir: Path, destination_vault: Path) -> Dict[str, Any]:
        """
        Recursively copies mobile companion app directory trees into the forensic vault,
        enforcing software write-blocking and generating cryptographic hash manifests.
        """
        src = Path(source_dir)
        dest = Path(destination_vault)
        dest.mkdir(parents=True, exist_ok=True)

        if not src.exists() or not src.is_dir():
            raise ValueError(f"Source directory not found: {src}")

        manifests = []
        total_bytes = 0

        for root, _, files in os.walk(src):
            for file_name in files:
                file_path = Path(root) / file_name
                rel_path = file_path.relative_to(src)
                target_file = dest / rel_path
                target_file.parent.mkdir(parents=True, exist_ok=True)

                shutil.copy2(file_path, target_file)
                WriteBlockController.enforce_file_read_only(target_file)

                h = compute_hashes(target_file)
                total_bytes += h.byte_count
                manifests.append({
                    "relative_path": str(rel_path),
                    "file_name": file_name,
                    "hashes": h.model_dump()
                })

        return {
            "source_directory": str(src),
            "destination_vault": str(dest),
            "files_extracted_count": len(manifests),
            "total_bytes_extracted": total_bytes,
            "extracted_files": manifests
        }

    @staticmethod
    def generate_adb_pull_plan(target_packages: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Generates structured ADB command lines for law enforcement physical/logical
        extraction of drone companion apps from connected Android devices.
        """
        packages_to_query = target_packages or list(KNOWN_COMPANION_PACKAGES.keys())
        commands = []

        for pkg in packages_to_query:
            if pkg in KNOWN_COMPANION_PACKAGES:
                info = KNOWN_COMPANION_PACKAGES[pkg]
                for p in info["paths"]:
                    commands.append({
                        "package": pkg,
                        "app_name": info["app_name"],
                        "platform": info["platform"],
                        "source_device_path": p,
                        "command": f"adb pull {p} ./evidence_vault/mobile_{pkg}/"
                    })

        return {
            "total_targets": len(commands),
            "adb_commands": commands,
            "guidance": "Execute via authorized forensic workstation with USB debugging enabled. Ensure write-blocking on vault destination."
        }
