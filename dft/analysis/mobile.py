"""
Mobile Companion Application Forensic Analysis Engine for Drone Forensic Toolkit (DFT).
Provides multi-platform companion app artifact identification, pilot identity recovery,
paired hardware serial extraction, operator smartphone geolocation recovery,
mobile flight record normalization, and configuration backup decoding.

Supported Mobile Companion Ecosystems:
1. DJI: DJI Fly (dji.go.v5), DJI GO 4 / GO (dji.go.v4, dji.pilot), DJI Pilot 2 (com.dji.industry.pilot), Litchi (com.flylitchi.litchi)
2. ArduPilot & PX4: QGroundControl Mobile (org.mavlink.qgroundcontrol), 3DR Tower / DroidPlanner (org.droidplanner.android), AndroPilot
3. Parrot: FreeFlight 6 / Pro / 7 (com.parrot.freeflight6/pro/7), FlightPlan, Academy sync
4. Betaflight & iNav: SpeedyBee Mobile (com.runcam.speedybee), EZ-GUI Ground Station (com.ezio.multiwii)
5. Autel Robotics: Autel Explorer (com.autel.explorer), Autel Sky (com.autel.autelsky)
"""

import csv
import json
import re
import sqlite3
import tarfile
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from dft.core.models import (
    TelemetryPoint, FlightEvent, OperatorLocation,
    MobileAppArtifact, MobileCompanionAnalysisResult
)
from dft.analysis.gcs import GCSAnalyzer


# Mobile Companion Catalog definition
MOBILE_APP_CATALOG = [
    {
        "app_name": "DJI Fly",
        "package_id": "dji.go.v5",
        "platform": "DJI",
        "supported_models": ["DJI Mini 2 / 3 / 4 Pro", "Mavic Air 2 / 2S / 3", "Mavic 3 / Classic / Pro", "Avata / FPV"],
        "os_types": ["Android", "iOS", "DJI RC / Smart Controller"],
        "standard_paths": ["/sdcard/DJI/dji.go.v5/", "/data/data/dji.go.v5/", "App-Sandbox/Documents/FlightRecord/"],
        "key_artifacts": ["FlightRecord/*.txt", "flight_record.db (SQLite)", "user_info.json", "fpv_video/", "noFlyZone.db"],
        "forensic_capabilities": [
            "Registered Pilot Email & User UID Extraction",
            "Paired Aircraft Serial Number (Aircraft SN, Camera SN, RC SN)",
            "Smartphone / RC GPS Operator Geolocation Recovery",
            "Cached FPV Video & Preview Thumbnail Harvesting",
            "Local Geofence Unlock / Authorization Certificate Parsing"
        ]
    },
    {
        "app_name": "DJI GO 4 / DJI GO",
        "package_id": "dji.go.v4",
        "platform": "DJI",
        "supported_models": ["Phantom 3 / 4 Pro", "Mavic Pro / 2 Pro / Zoom", "Inspire 1 / 2", "Spark"],
        "os_types": ["Android", "iOS", "CrystalSky"],
        "standard_paths": ["/sdcard/DJI/dji.go.v4/FlightRecord/", "/data/data/dji.go.v4/databases/djifpv.db"],
        "key_artifacts": ["FlightRecord/*.txt", "djifpv.db (SQLite)", "camera/cache/", "flight_stat.json"],
        "forensic_capabilities": [
            "Encrypted / Obfuscated Flight Record Decryption & Normalization",
            "Pilot Nickname, Total Flights & Distance Summaries",
            "Smart Controller / Phone Launch Position Geolocation",
            "Cached FPV Stream Log Analysis"
        ]
    },
    {
        "app_name": "DJI Pilot / Pilot 2",
        "package_id": "com.dji.industry.pilot",
        "platform": "DJI",
        "supported_models": ["Matrice 200 / 300 / 350 RTK", "Mavic 2 / 3 Enterprise", "Inspire 3"],
        "os_types": ["Android (Smart Controller Enterprise / RC Plus)"],
        "standard_paths": ["/sdcard/DJI/com.dji.industry.pilot/"],
        "key_artifacts": ["WPML (.kmz / .kml)", "Enterprise flight records", "Payload configs"],
        "forensic_capabilities": [
            "WPML Autonomous Survey & Waypoint Mission Extraction",
            "Multi-Payload (Thermal / Zoom / Lidar) State Recovery",
            "Enterprise Organization & Pilot Binding Extraction"
        ]
    },
    {
        "app_name": "Litchi for DJI Drones",
        "package_id": "com.flylitchi.litchi",
        "platform": "DJI",
        "supported_models": ["DJI Mini / Air / Mavic / Phantom series"],
        "os_types": ["Android", "iOS"],
        "standard_paths": ["/sdcard/Litchi/flightlogs/", "/sdcard/Litchi/missions/"],
        "key_artifacts": ["YYYY-MM-DD hh-mm-ss.csv", "missions/*.csv", "missions/*.json"],
        "forensic_capabilities": [
            "High-Precision Operator Phone GPS Fix Recovery (phone_latitude, phone_longitude)",
            "Home Point & Target Location Extraction",
            "Autonomous Waypoint Mission Plan Decoding (gimbalPitch, curveSize, speed)",
            "Pilot Email & Device Configuration Parsing"
        ]
    },
    {
        "app_name": "QGroundControl Mobile",
        "package_id": "org.mavlink.qgroundcontrol",
        "platform": "ArduPilot / PX4",
        "supported_models": ["Pixhawk / Cube / Holybro / Skydroid / Custom UAVs"],
        "os_types": ["Android", "iOS"],
        "standard_paths": ["/sdcard/Documents/QGroundControl/", "/sdcard/QGroundControl/Telemetry/", "/sdcard/QGroundControl/Missions/"],
        "key_artifacts": ["*.tlog", "*.plan", "*.waypoints", "*.param", "QGroundControl.log"],
        "forensic_capabilities": [
            "Downlink MAVLink 1.0/2.0 Telemetry Stream Decoding",
            "Autonomous Mission Plan (.plan) Parsing with Geofence & Rally Points",
            "Vehicle Parameter Snapshot Extraction (.param)",
            "STATUSTEXT Diagnostic & Error Alert Reconstruction"
        ]
    },
    {
        "app_name": "3DR Tower / DroidPlanner",
        "package_id": "org.droidplanner.android",
        "platform": "ArduPilot",
        "supported_models": ["3DR Solo / Iris / ArduCopter / ArduPlane"],
        "os_types": ["Android"],
        "standard_paths": ["/sdcard/DroidPlanner/", "/sdcard/Tower/logs/"],
        "key_artifacts": ["*.tlog", "quicklogs/*.txt", "*.dpml"],
        "forensic_capabilities": [
            "MAVLink Downlink Log Parsing",
            "DPML / DroidPlanner Mission Route Extraction",
            "QuickLog Diagnostic Parsing"
        ]
    },
    {
        "app_name": "Parrot FreeFlight 6 / Pro / 7",
        "package_id": "com.parrot.freeflight6",
        "platform": "Parrot",
        "supported_models": ["Parrot Anafi / Anafi USA / Bebop 2 / Disco"],
        "os_types": ["Android", "iOS", "Parrot Skycontroller"],
        "standard_paths": ["/sdcard/Parrot/", "/data/data/com.parrot.freeflight6/files/", "Documents/FlightData/"],
        "key_artifacts": ["*.json flight logs", "*.pud binary logs", "*.gutma logs", "Academy/*.json", "*.mavlink"],
        "forensic_capabilities": [
            "Pilot Academy Account Profile & Registered Email Extraction",
            "Drone Serial Number & Motor Diagnostics Extraction",
            "Operator Smartphone / Skycontroller GPS Recovery",
            "GUTMA (Global UTM Association) Standard Flight Log Normalization"
        ]
    },
    {
        "app_name": "SpeedyBee Mobile App",
        "package_id": "com.runcam.speedybee",
        "platform": "Betaflight / iNav",
        "supported_models": ["FPV Quads, Long-Range Wings, Betaflight/iNav FCs"],
        "os_types": ["Android", "iOS"],
        "standard_paths": ["/sdcard/SpeedyBee/Blackbox/", "/sdcard/SpeedyBee/Config/", "/sdcard/SpeedyBee/CLI/"],
        "key_artifacts": ["*.bbl", "*.bfl", "*.diff", "*.dump", "telemetry_*.csv"],
        "forensic_capabilities": [
            "Blackbox Flight Log Extraction & Gyro/PID/Motor Analysis",
            "CLI Config Dump Parsing (Pilot Callsign, Failsafe, Protocol)",
            "GPS-Rescue Parameters & Home Location Settings",
            "Bluetooth / Wi-Fi Flight Controller Parameter Backups"
        ]
    },
    {
        "app_name": "EZ-GUI Ground Station",
        "package_id": "com.ezio.multiwii",
        "platform": "Betaflight / Cleanflight",
        "supported_models": ["Cleanflight / Betaflight / MultiWii FPV Aircraft"],
        "os_types": ["Android"],
        "standard_paths": ["/sdcard/EZ-GUI/"],
        "key_artifacts": ["*.mwp missions", "*.csv logs"],
        "forensic_capabilities": [
            "Autonomous Waypoint Navigation (.mwp) Decoding",
            "Mobile Telemetry CSV Log Parsing"
        ]
    },
    {
        "app_name": "Autel Explorer / Sky",
        "package_id": "com.autel.explorer",
        "platform": "Autel Robotics",
        "supported_models": ["Autel EVO I / II / Dual / RTK / Nano / Lite / Dragonfish"],
        "os_types": ["Android", "iOS", "Autel Smart Controller"],
        "standard_paths": ["/sdcard/Autel/FlightRecord/", "/sdcard/Autel/Mission/"],
        "key_artifacts": ["FlightRecord/*.csv", "FlightRecord/*.bin", "mission/*.json"],
        "forensic_capabilities": [
            "Autel Flight Record Telemetry Decoding (CSV / JSON)",
            "Aircraft Serial Number & Flight Statistics Extraction",
            "Operator Home Geolocation Recovery"
        ]
    }
]


class MobileCompanionAnalyzer:
    """Forensic analyzer for mobile companion apps across all drone platforms."""

    @staticmethod
    def get_supported_catalog() -> List[Dict[str, Any]]:
        """Returns metadata catalog for all supported drone mobile companion apps."""
        return MOBILE_APP_CATALOG

    @staticmethod
    def identify_mobile_platform(path: Path) -> Tuple[Optional[str], Optional[str], Optional[str]]:
        """
        Inspects an evidence file or directory and detects:
        (app_name, package_id, target_platform).
        """
        p = Path(path)
        path_str = str(p).lower()

        # 1. Check folder/package names in path
        for app in MOBILE_APP_CATALOG:
            pkg = app["package_id"].lower()
            name = app["app_name"].lower()
            if pkg in path_str or name in path_str:
                return app["app_name"], app["package_id"], app["platform"]

        # Check keyword in path
        if "litchi" in path_str:
            return "Litchi for DJI Drones", "com.flylitchi.litchi", "DJI"
        if "speedybee" in path_str:
            return "SpeedyBee Mobile App", "com.runcam.speedybee", "Betaflight / iNav"
        if "freeflight" in path_str or "parrot" in path_str:
            return "Parrot FreeFlight 6", "com.parrot.freeflight6", "Parrot"
        if "qgroundcontrol" in path_str or "qgc" in path_str:
            return "QGroundControl Mobile", "org.mavlink.qgroundcontrol", "ArduPilot / PX4"
        if "autel" in path_str:
            return "Autel Explorer", "com.autel.explorer", "Autel Robotics"
        if "dji.go" in path_str or "djigo" in path_str or "djifly" in path_str:
            return "DJI Fly", "dji.go.v5", "DJI"

        # 2. Inspect file contents if it's a file
        if p.is_file():
            ext = p.suffix.lower()
            # Litchi CSV
            if ext == ".csv":
                try:
                    with open(p, "r", encoding="utf-8-sig", errors="ignore") as f:
                        header = f.readline().lower()
                    if "phone_latitude" in header or ("home_latitude" in header and "flyc_state" not in header):
                        return "Litchi for DJI Drones", "com.flylitchi.litchi", "DJI"
                    if "autel" in header or "flightrecord" in header:
                        return "Autel Explorer", "com.autel.explorer", "Autel Robotics"
                except Exception:
                    pass

            # SpeedyBee CLI config / diff
            if ext in [".diff", ".dump", ".txt"]:
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        snippet = f.read(2048).lower()
                    if "speedybee" in snippet or ("batch start" in snippet and "diff" in snippet) or "feature -rx_spi" in snippet:
                        return "SpeedyBee Mobile App", "com.runcam.speedybee", "Betaflight / iNav"
                    if "callsign" in snippet and ("set " in snippet or "profile" in snippet):
                        return "SpeedyBee Mobile App", "com.runcam.speedybee", "Betaflight / iNav"
                except Exception:
                    pass

            # Parrot JSON / GUTMA
            if ext == ".json":
                try:
                    with open(p, "r", encoding="utf-8", errors="ignore") as f:
                        snippet = f.read(2048).lower()
                    if "freeflight" in snippet or "anafi" in snippet or "bebop" in snippet or "parrot" in snippet:
                        return "Parrot FreeFlight 6", "com.parrot.freeflight6", "Parrot"
                    if "gutma" in snippet or "flight_logging" in snippet:
                        return "Parrot FreeFlight 6", "com.parrot.freeflight6", "Parrot"
                except Exception:
                    pass

            # SQLite DB
            if ext in [".db", ".sqlite"]:
                try:
                    conn = sqlite3.connect(f"file:{p}?mode=ro", uri=True)
                    tables = [row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]
                    conn.close()
                    tbl_str = " ".join(tables).lower()
                    if "flightrecord" in tbl_str or "flyrecord" in tbl_str or "userinfo" in tbl_str:
                        return "DJI Fly", "dji.go.v5", "DJI"
                    if "djifpv" in tbl_str or "pilot" in tbl_str:
                        return "DJI GO 4", "dji.go.v4", "DJI"
                except Exception:
                    pass

        return None, None, None

    @staticmethod
    def analyze_mobile_evidence(evidence_path: Path) -> MobileCompanionAnalysisResult:
        """
        Analyzes a mobile companion file, folder, or archive and extracts all forensic artifacts:
        pilot accounts, paired serial numbers, phone GPS operator positions, flight records,
        and configuration dumps.
        """
        target = Path(evidence_path)
        if not target.exists():
            return MobileCompanionAnalysisResult()

        # If it is an archive, unpack to a temporary directory for analysis
        temp_dir = None
        ext = target.suffix.lower()
        if target.is_file() and ext in [".zip", ".tar", ".gz", ".tgz"]:
            temp_dir = tempfile.TemporaryDirectory()
            work_dir = Path(temp_dir.name)
            if ext == ".zip":
                try:
                    with zipfile.ZipFile(target, "r") as z:
                        z.extractall(work_dir)
                except Exception:
                    pass
            else:
                try:
                    with tarfile.open(target, "r:*") as t:
                        t.extractall(work_dir)
                except Exception:
                    pass
        elif target.is_dir():
            work_dir = target
        else:
            # Single file analysis: create virtual working dir containing just this file
            temp_dir = tempfile.TemporaryDirectory()
            work_dir = Path(temp_dir.name)
            import shutil
            shutil.copy2(target, work_dir / target.name)

        artifacts: List[MobileAppArtifact] = []
        operator_locations: List[OperatorLocation] = []
        total_flight_records = 0
        total_waypoints = 0
        extracted_telemetry_points = 0

        # Scan work_dir for mobile apps
        discovered_files = list(work_dir.rglob("*"))
        app_files_map: Dict[str, List[Path]] = {}

        for f in discovered_files:
            if not f.is_file():
                continue
            app_name, pkg, plat = MobileCompanionAnalyzer.identify_mobile_platform(f)
            app_key = app_name or "Unknown Mobile App"
            if app_key not in app_files_map:
                app_files_map[app_key] = []
            app_files_map[app_key].append(f)

        if not app_files_map:
            # Check if root path itself maps to an app
            app_name, pkg, plat = MobileCompanionAnalyzer.identify_mobile_platform(target)
            if app_name:
                app_files_map[app_name] = [f for f in discovered_files if f.is_file()]

        # Process artifacts per discovered app
        for app_name, files in app_files_map.items():
            if not files:
                continue
            # Look up catalog metadata
            cat_entry = next((a for a in MOBILE_APP_CATALOG if a["app_name"].lower() == app_name.lower()), None)
            pkg_id = cat_entry["package_id"] if cat_entry else None
            plat = cat_entry["platform"] if cat_entry else "Generic Mobile"

            pilot_acc: Dict[str, Any] = {}
            paired_hw: Dict[str, Any] = {}
            app_op_locs: List[OperatorLocation] = []
            flight_logs: List[str] = []
            mission_plans: List[str] = []
            config_dumps: Dict[str, Any] = {}
            cached_media: List[str] = []
            raw_details: Dict[str, Any] = {}

            for f in files:
                fname = f.name
                fext = f.suffix.lower()

                # --- 1. Litchi for DJI Drones ---
                if "litchi" in app_name.lower():
                    if fext == ".csv" and ("20" in fname or "flight" in fname.lower() or "log" in fname.lower()):
                        flight_logs.append(fname)
                        total_flight_records += 1
                        pts, op_pt = MobileCompanionAnalyzer._parse_litchi_csv(f)
                        extracted_telemetry_points += len(pts)
                        if op_pt:
                            app_op_locs.append(op_pt)
                    elif fext in [".csv", ".json"] and "mission" in fname.lower():
                        mission_plans.append(fname)
                        wps = MobileCompanionAnalyzer._parse_litchi_mission(f)
                        total_waypoints += len(wps)
                    elif "user" in fname.lower() or "account" in fname.lower():
                        try:
                            data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
                            pilot_acc.update(data)
                        except Exception:
                            pass

                # --- 2. DJI Fly & DJI GO ---
                elif "dji" in app_name.lower():
                    if fext in [".db", ".sqlite"]:
                        db_acc, db_hw, db_fl_count = MobileCompanionAnalyzer._parse_dji_sqlite(f)
                        if db_acc:
                            pilot_acc.update(db_acc)
                        if db_hw:
                            paired_hw.update(db_hw)
                        total_flight_records += db_fl_count
                        flight_logs.append(fname)
                    elif fext in [".txt", ".csv"] and ("flight" in fname.lower() or "record" in fname.lower() or "dji" in fname.lower()):
                        flight_logs.append(fname)
                        total_flight_records += 1
                        pts, op_pt, hw_meta = MobileCompanionAnalyzer._parse_dji_mobile_txt(f)
                        extracted_telemetry_points += len(pts)
                        if op_pt:
                            app_op_locs.append(op_pt)
                        if hw_meta:
                            paired_hw.update(hw_meta)
                    elif fext == ".json" and ("user" in fname.lower() or "account" in fname.lower() or "pilot" in fname.lower()):
                        try:
                            data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
                            pilot_acc.update(data)
                        except Exception:
                            pass
                    elif fext in [".mp4", ".mov", ".ts", ".jpg", ".png"] and ("fpv" in str(f).lower() or "cache" in str(f).lower()):
                        cached_media.append(fname)

                # --- 3. Parrot FreeFlight ---
                elif "parrot" in app_name.lower() or "freeflight" in app_name.lower():
                    if fext == ".json" and ("academy" in fname.lower() or "user" in fname.lower() or "profile" in fname.lower()):
                        try:
                            data = json.loads(f.read_text(encoding="utf-8", errors="ignore"))
                            if "email" in data:
                                pilot_acc["email"] = data["email"]
                            if "user_id" in data:
                                pilot_acc["user_id"] = data["user_id"]
                            if "serial_number" in data:
                                paired_hw["aircraft_sn"] = data["serial_number"]
                        except Exception:
                            pass
                    elif fext in [".json", ".pud", ".gutma"]:
                        flight_logs.append(fname)
                        total_flight_records += 1
                        pts, op_pt, sn = MobileCompanionAnalyzer._parse_parrot_mobile_log(f)
                        extracted_telemetry_points += len(pts)
                        if op_pt:
                            app_op_locs.append(op_pt)
                        if sn and "aircraft_sn" not in paired_hw:
                            paired_hw["aircraft_sn"] = sn
                    elif fext == ".mavlink":
                        mission_plans.append(fname)

                # --- 4. SpeedyBee / Betaflight ---
                elif "speedybee" in app_name.lower():
                    if fext in [".diff", ".dump", ".txt"] and ("diff" in fname.lower() or "dump" in fname.lower() or "cli" in fname.lower() or "config" in fname.lower()):
                        conf = MobileCompanionAnalyzer._parse_speedybee_cli(f)
                        config_dumps.update(conf)
                        if "callsign" in conf and conf["callsign"]:
                            pilot_acc["callsign"] = conf["callsign"]
                    elif fext in [".bbl", ".bfl", ".csv"] and ("blackbox" in fname.lower() or "log" in fname.lower()):
                        flight_logs.append(fname)
                        total_flight_records += 1

                # --- 5. QGroundControl Mobile ---
                elif "qgroundcontrol" in app_name.lower():
                    if fext == ".tlog":
                        flight_logs.append(fname)
                        total_flight_records += 1
                        try:
                            pts, _, ops, meta = GCSAnalyzer.parse_mavlink_tlog(f)
                            extracted_telemetry_points += len(pts)
                            app_op_locs.extend(ops)
                        except Exception:
                            pass
                    elif fext in [".plan", ".waypoints"]:
                        mission_plans.append(fname)
                    elif fext in [".param", ".parm"]:
                        config_dumps[fname] = f"Parameter dump ({f.stat().st_size} bytes)"

                # --- 6. Autel Explorer ---
                elif "autel" in app_name.lower():
                    if fext in [".csv", ".json"]:
                        flight_logs.append(fname)
                        total_flight_records += 1
                        pts, op_pt, sn = MobileCompanionAnalyzer._parse_autel_mobile_log(f)
                        extracted_telemetry_points += len(pts)
                        if op_pt:
                            app_op_locs.append(op_pt)
                        if sn:
                            paired_hw["aircraft_sn"] = sn

            operator_locations.extend(app_op_locs)

            artifact = MobileAppArtifact(
                app_id=f"MOB-{len(artifacts)+1:02d}",
                app_name=app_name,
                package_id=pkg_id,
                target_platform=plat,
                pilot_account=pilot_acc or None,
                paired_hardware=paired_hw or None,
                operator_locations=app_op_locs,
                flight_logs=flight_logs,
                mission_plans=mission_plans,
                config_dumps=config_dumps,
                cached_media=cached_media,
                raw_details=raw_details
            )
            artifacts.append(artifact)

        if temp_dir:
            temp_dir.cleanup()

        apps_detected = [a.app_name for a in artifacts]
        platforms_involved = sorted(list(set(a.target_platform for a in artifacts)))

        return MobileCompanionAnalysisResult(
            apps_detected=apps_detected,
            platforms_involved=platforms_involved,
            artifacts=artifacts,
            total_flight_records=total_flight_records,
            total_waypoints_recovered=total_waypoints,
            operator_locations=operator_locations,
            extracted_telemetry_points_count=extracted_telemetry_points
        )

    # =========================================================================
    # INTERNAL PARSING HELPERS
    # =========================================================================

    @staticmethod
    def _parse_litchi_csv(file_path: Path) -> Tuple[List[TelemetryPoint], Optional[OperatorLocation]]:
        """
        Parses Litchi for DJI CSV flight logs.
        Extracts synchronized flight path and high-precision phone_latitude/phone_longitude.
        """
        points: List[TelemetryPoint] = []
        op_location: Optional[OperatorLocation] = None

        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                reader = csv.DictReader(f)
                rows = list(reader)

            for i, row in enumerate(rows):
                dt_str = row.get("datetime(utc)") or row.get("datetime") or row.get("time")
                lat = float(row.get("latitude") or 0.0)
                lon = float(row.get("longitude") or 0.0)
                alt = float(row.get("altitude(m)") or row.get("altitude(feet)", 0.0))
                # Feet to meters if altitude(feet) is present
                if "altitude(feet)" in row and "altitude(m)" not in row:
                    alt *= 0.3048

                speed = float(row.get("speed(m/s)") or row.get("speed(mps)") or 0.0)
                pitch = float(row.get("pitch") or 0.0)
                roll = float(row.get("roll") or 0.0)
                yaw = float(row.get("yaw") or row.get("heading(degrees)") or 0.0)
                battery = float(row.get("battery_percent") or row.get("battery") or 0.0) if (row.get("battery_percent") or row.get("battery")) else None

                if dt_str and abs(lat) > 0.01 and abs(lon) > 0.01:
                    points.append(TelemetryPoint(
                        timestamp_utc=dt_str if "T" in dt_str else f"{dt_str}Z",
                        latitude=lat,
                        longitude=lon,
                        altitude_m=alt,
                        ground_speed_mps=speed,
                        pitch_deg=pitch,
                        roll_deg=roll,
                        yaw_deg=yaw,
                        battery_pct=battery,
                        source_channel="LITCHI_MOBILE_LOG"
                    ))

                # Check operator phone GPS coordinates
                phone_lat_str = row.get("phone_latitude")
                phone_lon_str = row.get("phone_longitude")
                if not op_location and phone_lat_str and phone_lon_str:
                    try:
                        plat = float(phone_lat_str)
                        plon = float(phone_lon_str)
                        if abs(plat) > 0.01 and abs(plon) > 0.01:
                            op_location = OperatorLocation(
                                source="Litchi Mobile Phone GPS",
                                latitude=plat,
                                longitude=plon,
                                timestamp_utc=dt_str or datetime.now(timezone.utc).isoformat(),
                                accuracy_m=5.0,
                                description="High-precision smartphone GPS location recorded by Litchi app during UAV flight."
                            )
                    except Exception:
                        pass

                # Fallback to Home position if phone GPS not recorded
                if not op_location:
                    hlat_str = row.get("home_latitude")
                    hlon_str = row.get("home_longitude")
                    if hlat_str and hlon_str:
                        try:
                            hlat = float(hlat_str)
                            hlon = float(hlon_str)
                            if abs(hlat) > 0.01 and abs(hlon) > 0.01:
                                op_location = OperatorLocation(
                                    source="Litchi Home Location",
                                    latitude=hlat,
                                    longitude=hlon,
                                    timestamp_utc=dt_str or datetime.now(timezone.utc).isoformat(),
                                    accuracy_m=10.0,
                                    description="Home position set by Litchi mobile app at takeoff."
                                )
                        except Exception:
                            pass
        except Exception:
            pass

        return points, op_location

    @staticmethod
    def _parse_litchi_mission(file_path: Path) -> List[Dict[str, Any]]:
        """Parses Litchi autonomous waypoint mission CSV / JSON."""
        wps = []
        try:
            ext = file_path.suffix.lower()
            if ext == ".csv":
                with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        if "latitude" in row and "longitude" in row:
                            wps.append({
                                "lat": float(row["latitude"]),
                                "lon": float(row["longitude"]),
                                "alt_m": float(row.get("altitude(m)", 50.0)),
                                "speed_mps": float(row.get("speed(m/s)", 5.0)),
                                "action": row.get("actiontype1", "WAYPOINT")
                            })
            elif ext == ".json":
                data = json.loads(file_path.read_text(encoding="utf-8", errors="ignore"))
                items = data.get("waypoints") or data.get("mission", {}).get("items") or []
                for item in items:
                    wps.append({
                        "lat": item.get("latitude") or item.get("lat"),
                        "lon": item.get("longitude") or item.get("lon"),
                        "alt_m": item.get("altitude") or item.get("alt", 50.0)
                    })
        except Exception:
            pass
        return wps

    @staticmethod
    def _parse_dji_sqlite(file_path: Path) -> Tuple[Dict[str, Any], Dict[str, Any], int]:
        """
        Parses DJI SQLite databases (flight_record.db, djifpv.db).
        Extracts user profile, aircraft serial numbers, and total flight counts.
        """
        account = {}
        hardware = {}
        flight_count = 0

        try:
            conn = sqlite3.connect(f"file:{file_path}?mode=ro", uri=True)
            cursor = conn.cursor()

            # Inspect tables
            tables = [r[0] for r in cursor.execute("SELECT name FROM sqlite_master WHERE type='table';").fetchall()]

            for t in tables:
                t_lower = t.lower()
                # User / Account table
                if any(k in t_lower for k in ["user", "account", "pilot"]):
                    cols = [c[1] for c in cursor.execute(f"PRAGMA table_info({t});").fetchall()]
                    rows = cursor.execute(f"SELECT * FROM {t} LIMIT 5;").fetchall()
                    for r in rows:
                        row_dict = dict(zip(cols, r))
                        for k, v in row_dict.items():
                            kl = k.lower()
                            if "email" in kl and v:
                                account["email"] = str(v)
                            elif "name" in kl or "nick" in kl and v:
                                account["pilot_name"] = str(v)
                            elif "uid" in kl or "id" in kl and v and not account.get("user_id"):
                                account["user_id"] = str(v)
                            elif "phone" in kl and v:
                                account["phone"] = str(v)

                # Flight Record table
                if any(k in t_lower for k in ["flightrecord", "flyrecord", "record", "flight"]):
                    cnt = cursor.execute(f"SELECT COUNT(*) FROM {t};").fetchone()[0]
                    flight_count = max(flight_count, cnt)

                    # Check for aircraft SN in columns
                    cols = [c[1] for c in cursor.execute(f"PRAGMA table_info({t});").fetchall()]
                    sn_col = next((c for c in cols if "sn" in c.lower() or "serial" in c.lower() or "aircraft" in c.lower()), None)
                    if sn_col:
                        sample_sns = cursor.execute(f"SELECT DISTINCT {sn_col} FROM {t} WHERE {sn_col} IS NOT NULL LIMIT 3;").fetchall()
                        if sample_sns and sample_sns[0][0]:
                            hardware["aircraft_sn"] = str(sample_sns[0][0])

            conn.close()
        except Exception:
            pass

        return account, hardware, flight_count

    @staticmethod
    def _parse_dji_mobile_txt(file_path: Path) -> Tuple[List[TelemetryPoint], Optional[OperatorLocation], Dict[str, Any]]:
        """Parses DJI mobile CSV/TXT flight records."""
        points: List[TelemetryPoint] = []
        op_location: Optional[OperatorLocation] = None
        hw_meta: Dict[str, Any] = {}

        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                header = f.readline()
                lines = [f.readline() for _ in range(200)]

            # Check for RC / Operator coordinates or Drone Serial in header
            if "serial" in header.lower() or "sn" in header.lower():
                m = re.search(r"SN:([A-Za-z0-9]+)", header)
                if m:
                    hw_meta["aircraft_sn"] = m.group(1)

            # Heuristic CSV reader
            reader = csv.DictReader([header] + lines)
            for row in reader:
                lat_k = next((k for k in row.keys() if "osd.latitude" in k.lower() or k.lower() == "latitude"), None)
                lon_k = next((k for k in row.keys() if "osd.longitude" in k.lower() or k.lower() == "longitude"), None)
                alt_k = next((k for k in row.keys() if "osd.height" in k.lower() or "altitude" in k.lower()), None)
                time_k = next((k for k in row.keys() if "time" in k.lower() or "date" in k.lower()), None)

                rc_lat_k = next((k for k in row.keys() if "rc.latitude" in k.lower() or "home.latitude" in k.lower()), None)
                rc_lon_k = next((k for k in row.keys() if "rc.longitude" in k.lower() or "home.longitude" in k.lower()), None)

                if rc_lat_k and rc_lon_k and not op_location:
                    try:
                        rlat = float(row[rc_lat_k])
                        rlon = float(row[rc_lon_k])
                        if abs(rlat) > 0.01 and abs(rlon) > 0.01:
                            op_location = OperatorLocation(
                                source="DJI Remote Controller / Smart Controller GPS",
                                latitude=rlat,
                                longitude=rlon,
                                accuracy_m=5.0,
                                description="Operator launch / remote controller GPS coordinates."
                            )
                    except Exception:
                        pass

                if lat_k and lon_k and row[lat_k] and row[lon_k]:
                    try:
                        lat = float(row[lat_k])
                        lon = float(row[lon_k])
                        alt = float(row[alt_k]) if (alt_k and row[alt_k]) else 0.0
                        t_str = row[time_k] if time_k else datetime.now(timezone.utc).isoformat()
                        if abs(lat) > 0.01 and abs(lon) > 0.01:
                            points.append(TelemetryPoint(
                                timestamp_utc=t_str,
                                latitude=lat,
                                longitude=lon,
                                altitude_m=alt,
                                source_channel="DJI_MOBILE_LOG"
                            ))
                    except Exception:
                        pass
        except Exception:
            pass

        return points, op_location, hw_meta

    @staticmethod
    def _parse_parrot_mobile_log(file_path: Path) -> Tuple[List[TelemetryPoint], Optional[OperatorLocation], Optional[str]]:
        """Parses Parrot FreeFlight JSON or GUTMA log."""
        points: List[TelemetryPoint] = []
        op_loc: Optional[OperatorLocation] = None
        drone_sn: Optional[str] = None

        try:
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            data = json.loads(content)

            # Check drone serial number
            drone_sn = data.get("serial_number") or data.get("drone_serial") or data.get("uav_id")

            # Check controller / operator GPS
            ctrl_lat = data.get("controller_latitude") or data.get("controller_lat") or data.get("pilot_latitude")
            ctrl_lon = data.get("controller_longitude") or data.get("controller_lon") or data.get("pilot_longitude")
            if ctrl_lat and ctrl_lon and abs(float(ctrl_lat)) > 0.01:
                op_loc = OperatorLocation(
                    source="Parrot FreeFlight Mobile / Skycontroller GPS",
                    latitude=float(ctrl_lat),
                    longitude=float(ctrl_lon),
                    accuracy_m=8.0,
                    description="Parrot mobile app / Skycontroller pilot geolocation."
                )

            # Check flight trajectory items
            records = data.get("details") or data.get("telemetry") or data.get("flight_data") or []
            for r in records:
                lat = float(r.get("gps_latitude") or r.get("latitude") or 0.0)
                lon = float(r.get("gps_longitude") or r.get("longitude") or 0.0)
                alt = float(r.get("altitude") or r.get("gps_altitude") or 0.0)
                ts = r.get("timestamp") or data.get("run_date") or datetime.now(timezone.utc).isoformat()
                if abs(lat) > 0.01 and abs(lon) > 0.01:
                    points.append(TelemetryPoint(
                        timestamp_utc=ts,
                        latitude=lat,
                        longitude=lon,
                        altitude_m=alt,
                        source_channel="PARROT_FREEFLIGHT_LOG"
                    ))
        except Exception:
            pass

        return points, op_loc, drone_sn

    @staticmethod
    def _parse_speedybee_cli(file_path: Path) -> Dict[str, Any]:
        """
        Parses SpeedyBee Mobile App CLI dump / diff files.
        Extracts pilot callsign, motor protocol, failsafe action, and receiver settings.
        """
        config = {
            "source_file": file_path.name,
            "firmware": "Betaflight / iNav"
        }
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        # Extract firmware version banner
                        if "Betaflight /" in line or "INAV /" in line:
                            config["firmware_version"] = line.lstrip("# ")
                        continue

                    # Extract settings
                    if line.startswith("set "):
                        parts = line[4:].split("=", 1)
                        if len(parts) == 2:
                            k = parts[0].strip()
                            v = parts[1].strip()
                            if "callsign" in k:
                                config["callsign"] = v
                            elif "failsafe_procedure" in k:
                                config["failsafe_procedure"] = v
                            elif "motor_pwm_protocol" in k:
                                config["motor_protocol"] = v
                            elif "gps_rescue" in k:
                                config[k] = v
                    elif line.startswith("name "):
                        config["callsign"] = line.split(" ", 1)[1].strip()
        except Exception:
            pass

        return config

    @staticmethod
    def _parse_autel_mobile_log(file_path: Path) -> Tuple[List[TelemetryPoint], Optional[OperatorLocation], Optional[str]]:
        """Parses Autel Explorer CSV flight records."""
        points: List[TelemetryPoint] = []
        op_loc: Optional[OperatorLocation] = None
        drone_sn: Optional[str] = None

        try:
            with open(file_path, "r", encoding="utf-8-sig", errors="ignore") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    lat = float(row.get("latitude") or row.get("Latitude") or 0.0)
                    lon = float(row.get("longitude") or row.get("Longitude") or 0.0)
                    alt = float(row.get("altitude") or row.get("Altitude") or 0.0)
                    t_str = row.get("datetime") or row.get("Time") or datetime.now(timezone.utc).isoformat()

                    if not drone_sn and (row.get("sn") or row.get("aircraft_sn")):
                        drone_sn = row.get("sn") or row.get("aircraft_sn")

                    if not op_loc and (row.get("home_lat") or row.get("pilot_lat")):
                        op_loc = OperatorLocation(
                            source="Autel Explorer Pilot GPS",
                            latitude=float(row.get("home_lat") or row.get("pilot_lat")),
                            longitude=float(row.get("home_lon") or row.get("pilot_lon")),
                            accuracy_m=10.0,
                            description="Autel Explorer operator home position."
                        )

                    if abs(lat) > 0.01 and abs(lon) > 0.01:
                        points.append(TelemetryPoint(
                            timestamp_utc=t_str,
                            latitude=lat,
                            longitude=lon,
                            altitude_m=alt,
                            source_channel="AUTEL_EXPLORER_LOG"
                        ))
        except Exception:
            pass

        return points, op_loc, drone_sn
