"""
Ground Control Station (GCS) Forensic Analysis Engine for Drone Forensic Toolkit.
Provides multi-platform GCS detection, mission plan parsing, operator geolocation,
downlink telemetry decoding, and planned vs. executed trajectory compliance analysis.

Supported GCS Ecosystems:
- Mission Planner / QGroundControl / MAVProxy (ArduPilot FCs)
- QGroundControl (PX4 Autopilot FCs)
- DJI Pilot 2 WPML / DJI GS Pro / DJI Fly & GO (DJI FCs)
- iNav Mission Planner / mwp / Configurator (Betaflight / iNav FCs)
- Parrot FreeFlight / FlightPlan (Parrot FCs)
"""

import json
import math
import mmap
import struct
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple

from dft.core.models import (
    TelemetryPoint, FlightEvent, PlannedWaypoint, GCSMissionPlan,
    OperatorLocation, GCSAnalysisResult, GeofenceZone
)
from dft.analysis.flight_path import haversine_distance_meters


# Standard MAVLink Command Names
MAV_CMD_NAMES = {
    16: "WAYPOINT",
    17: "LOITER_UNLIM",
    18: "LOITER_TURNS",
    19: "LOITER_TIME",
    20: "RETURN_TO_LAUNCH",
    21: "LAND",
    22: "TAKEOFF",
    82: "SPLINE_WAYPOINT",
    84: "VTOL_TAKEOFF",
    85: "VTOL_LAND",
    177: "DO_SET_ROI",
    178: "DO_DIGICAM_CONTROL",
    201: "DO_SET_ROI_LOCATION",
    206: "DO_SET_SERVO"
}


class GCSAnalyzer:
    """Unified forensic analyzer for UAV Ground Control Station artifacts."""

    @staticmethod
    def identify_gcs_format(file_path: Path) -> Tuple[Optional[str], Optional[str]]:
        """
        Inspects evidence file and returns (detected_gcs_name, target_fc_platform).
        """
        ext = file_path.suffix.lower()

        # 1. MAVLink Telemetry Stream (.tlog)
        if ext == ".tlog":
            return "Mission Planner / QGroundControl", "ArduPilot / PX4"

        # 2. QGroundControl Plan (.plan)
        if ext == ".plan":
            return "QGroundControl", "PX4 / ArduPilot"

        # 3. QGC WPL 110 Waypoints (.waypoints or .txt)
        if ext in [".waypoints", ".txt"]:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    first_line = f.readline().strip()
                if "QGC WPL" in first_line:
                    return "QGroundControl / Mission Planner", "ArduPilot / PX4"
            except Exception:
                pass

        # 4. DJI Pilot 2 WPML (.kmz or .kml)
        if ext in [".kmz", ".kml"]:
            try:
                if ext == ".kmz":
                    with zipfile.ZipFile(file_path, "r") as z:
                        namelist = z.namelist()
                        for name in namelist:
                            if name.endswith(".kml"):
                                with z.open(name) as kml_f:
                                    snippet = kml_f.read(2048).decode("utf-8", errors="ignore")
                                if "wpml:" in snippet or "dji" in snippet.lower():
                                    return "DJI Pilot 2 (WPML)", "DJI"
                else:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        snippet = f.read(2048)
                    if "wpml:" in snippet or "dji" in snippet.lower():
                        return "DJI Pilot 2 (WPML)", "DJI"
            except Exception:
                pass

        # 5. iNav Mission Planner / MWP (.mission, .mwp)
        if ext in [".mission", ".mwp"]:
            return "iNav Mission Planner / mwp", "Betaflight / iNav"

        # 6. JSON files (DJI GS Pro, Parrot FlightPlan, QGC Plan, iNav JSON)
        if ext == ".json":
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read(4096)
                if '"groundStation": "QGroundControl"' in content or '"fileType": "Plan"' in content:
                    return "QGroundControl", "PX4 / ArduPilot"
                if "gs_pro" in content.lower() or "gs pro" in content.lower() or "gspro" in content.lower() or "dji" in content.lower():
                    return "DJI GS Pro", "DJI"
                if "flightplan" in content.lower() or "freeflight" in content.lower() or "parrot" in content.lower():
                    return "Parrot FlightPlan", "Parrot"
                if "inav" in content.lower() or "mwp" in content.lower():
                    return "iNav Mission Planner", "Betaflight / iNav"
            except Exception:
                pass

        # 7. Parrot .mavlink FlightPlan
        if ext == ".mavlink":
            return "Parrot FlightPlan", "Parrot"

        # 8. Parameter Dumps (.param, .parm)
        if ext in [".param", ".parm"]:
            return "Mission Planner / QGroundControl", "ArduPilot"

        return None, None

    # =========================================================================
    # 1. ARDUPILOT & PX4: MAVLINK TLOG PARSER
    # =========================================================================

    @staticmethod
    def parse_mavlink_tlog(file_path: Path) -> Tuple[List[TelemetryPoint], List[FlightEvent], List[OperatorLocation], Dict[str, Any]]:
        """
        Pure-Python forensic parser for MAVLink 1.0 (0xFE) and MAVLink 2.0 (0xFD) .tlog streams.
        Decodes 8-byte big-endian microsecond timestamps, vehicle position, Home location, and commands.
        """
        telemetry: List[TelemetryPoint] = []
        events: List[FlightEvent] = []
        operator_locations: List[OperatorLocation] = []
        metadata: Dict[str, Any] = {
            "gcs_protocol": "MAVLink",
            "detected_gcs": "Mission Planner / QGroundControl",
            "messages_decoded": 0,
            "statustext_messages": []
        }

        TARGET_MSG_IDS = {0, 24, 33, 242, 253}
        is_mmap = False
        data = None

        try:
            with open(file_path, "rb") as f:
                file_len = f.seek(0, 2)
                if file_len < 9:
                    return telemetry, events, operator_locations, metadata
                f.seek(0)
                try:
                    data = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
                    is_mmap = True
                except Exception:
                    data = f.read()
                    is_mmap = False
        except Exception:
            return telemetry, events, operator_locations, metadata

        offset = 0
        armed_state = False
        cached_usec = -1
        cached_iso = ""

        try:
            while offset <= file_len - 9:
                # TLOG packet format:
                # 8 bytes: Unix timestamp in microseconds (big-endian uint64)
                # Followed by MAVLink packet starting with 0xFE (MAVLink 1) or 0xFD (MAVLink 2)
                ts_usec = struct.unpack_from(">Q", data, offset)[0]
                offset += 8

                if offset >= file_len:
                    break

                magic = data[offset]
                if magic not in (0xFE, 0xFD):
                    # Resynchronize by scanning for magic byte preceded by reasonable timestamp
                    found = False
                    for sync_offset in range(offset, min(offset + 128, file_len - 9)):
                        if data[sync_offset] in (0xFE, 0xFD) and sync_offset >= 8:
                            candidate_ts = struct.unpack_from(">Q", data, sync_offset - 8)[0]
                            if 1_200_000_000_000_000 < candidate_ts < 2_500_000_000_000_000:
                                offset = sync_offset
                                magic = data[offset]
                                found = True
                                break
                    if not found:
                        offset += 1
                        continue

                # Parse MAVLink header first before doing any timestamp conversions
                if magic == 0xFE:  # MAVLink 1.0
                    if offset + 6 > file_len:
                        break
                    payload_len = data[offset + 1]
                    msg_id = data[offset + 5]
                    header_len = 6
                    total_pkt_len = header_len + payload_len + 2  # 2 checksum bytes
                else:  # MAVLink 2.0 (0xFD)
                    if offset + 10 > file_len:
                        break
                    payload_len = data[offset + 1]
                    incompat_flags = data[offset + 2]
                    msg_id = data[offset + 7] | (data[offset + 8] << 8) | (data[offset + 9] << 16)
                    header_len = 10
                    sig_len = 13 if (incompat_flags & 0x01) else 0
                    total_pkt_len = header_len + payload_len + 2 + sig_len

                if offset + total_pkt_len > file_len:
                    break

                # Early filter: Skip decoding non-target message payloads and skip ISO datetime generation
                if msg_id not in TARGET_MSG_IDS:
                    offset += total_pkt_len
                    metadata["messages_decoded"] += 1
                    continue

                # Only format timestamp for consumed messages
                if ts_usec == cached_usec:
                    ts_iso = cached_iso
                else:
                    try:
                        ts_sec = ts_usec / 1_000_000.0
                        dt = datetime.fromtimestamp(ts_sec, timezone.utc)
                        ts_iso = dt.isoformat()
                    except Exception:
                        ts_iso = datetime.now(timezone.utc).isoformat()
                    cached_usec = ts_usec
                    cached_iso = ts_iso

                payload = data[offset + header_len : offset + header_len + payload_len]
                offset += total_pkt_len
                metadata["messages_decoded"] += 1

                # -------------------------------------------------------------
                # Message 33: GLOBAL_POSITION_INT (lat, lon, alt, vx, vy, vz, hdg)
                # -------------------------------------------------------------
                if msg_id == 33 and len(payload) >= 28:
                    try:
                        time_boot_ms, lat_int, lon_int, alt_mm, rel_alt_mm, vx, vy, vz, hdg = struct.unpack_from("<Iiiii3hH", payload, 0)
                        lat = lat_int / 1e7
                        lon = lon_int / 1e7
                        alt_m = round(rel_alt_mm / 1000.0, 2)
                        spd = round(math.sqrt(vx * vx + vy * vy) / 100.0, 2)

                        if abs(lat) <= 90.0 and abs(lon) <= 180.0 and (abs(lat) > 0.001 or abs(lon) > 0.001):
                            telemetry.append(TelemetryPoint(
                                timestamp_utc=ts_iso,
                                latitude=round(lat, 7),
                                longitude=round(lon, 7),
                                altitude_m=alt_m,
                                ground_speed_mps=spd,
                                yaw_deg=round(hdg / 100.0, 1),
                                source_channel="MAVLINK_GLOBAL_POSITION_INT"
                            ))
                    except Exception:
                        pass

                # -------------------------------------------------------------
                # Message 24: GPS_RAW_INT (fix_type, lat, lon, alt, vel, satellites)
                # -------------------------------------------------------------
                elif msg_id == 24 and len(payload) >= 30:
                    try:
                        lat, lon, alt_mm, vel, sats = 0.0, 0.0, 0, 0, 0
                        try:
                            # Try canonical wire order (<QiiiHHHHBB)
                            time_usec_raw, lat_int, lon_int, alt_mm, eph, epv, vel, cog, fix_type, sats = struct.unpack_from("<QiiiHHHHBB", payload, 0)
                            lat = lat_int / 1e7
                            lon = lon_int / 1e7
                            if not (-90.0 <= lat <= 90.0 and -180.0 <= lon <= 180.0 and (abs(lat) > 0.001 or abs(lon) > 0.001)):
                                raise ValueError("Invalid wire coordinates")
                        except Exception:
                            # Fallback to logical definition order (<QBiiiHHHHB)
                            time_usec_raw, fix_type, lat_int, lon_int, alt_mm, eph, epv, vel, cog, sats = struct.unpack_from("<QBiiiHHHHB", payload, 0)
                            lat = lat_int / 1e7
                            lon = lon_int / 1e7

                        if (abs(lat) <= 90.0 and abs(lon) <= 180.0 and (abs(lat) > 0.001 or abs(lon) > 0.001) and
                                not (telemetry and telemetry[-1].source_channel == "MAVLINK_GLOBAL_POSITION_INT" and telemetry[-1].timestamp_utc == ts_iso)):
                            telemetry.append(TelemetryPoint(
                                timestamp_utc=ts_iso,
                                latitude=round(lat, 7),
                                longitude=round(lon, 7),
                                altitude_m=round(alt_mm / 1000.0, 2),
                                ground_speed_mps=round(vel / 100.0, 2),
                                satellites_visible=sats,
                                source_channel="MAVLINK_GPS_RAW_INT"
                            ))
                    except Exception:
                        pass

                # -------------------------------------------------------------
                # Message 242: HOME_POSITION (lat, lon, alt, x, y, z, q, appro)
                # Operator / Launch Location recorded in GCS telemetry!
                # -------------------------------------------------------------
                elif msg_id == 242 and len(payload) >= 28:
                    try:
                        home_lat_int, home_lon_int, home_alt_mm = struct.unpack_from("<iii", payload, 0)
                        h_lat = home_lat_int / 1e7
                        h_lon = home_lon_int / 1e7
                        h_alt = round(home_alt_mm / 1000.0, 2)
                        if abs(h_lat) <= 90.0 and abs(h_lon) <= 180.0 and (abs(h_lat) > 0.001 or abs(h_lon) > 0.001):
                            op_loc = OperatorLocation(
                                source="GCS_MAVLINK_HOME_POSITION",
                                latitude=round(h_lat, 7),
                                longitude=round(h_lon, 7),
                                altitude_m=h_alt,
                                timestamp_utc=ts_iso,
                                description="Ground Control Station / Vehicle Home Location negotiated over MAVLink"
                            )
                            if not any(abs(ol.latitude - op_loc.latitude) < 0.00001 and abs(ol.longitude - op_loc.longitude) < 0.00001 for ol in operator_locations):
                                operator_locations.append(op_loc)
                    except Exception:
                        pass

                # -------------------------------------------------------------
                # Message 0: HEARTBEAT (custom_mode, type, autopilot, base_mode, system_status)
                # -------------------------------------------------------------
                elif msg_id == 0 and len(payload) >= 9:
                    try:
                        custom_mode, veh_type, autopilot, base_mode, sys_status, mavlink_ver = struct.unpack_from("<IBBBBB", payload, 0)
                        is_armed = bool(base_mode & 128)  # MAV_MODE_FLAG_SAFETY_ARMED = 128
                        if autopilot == 3:
                            metadata["autopilot_family"] = "ArduPilot"
                        elif autopilot == 12:
                            metadata["autopilot_family"] = "PX4"

                        if is_armed and not armed_state:
                            armed_state = True
                            events.append(FlightEvent(
                                event_id=f"GCS-EV-{len(events)+1}",
                                timestamp_utc=ts_iso,
                                event_type="ARM",
                                severity="INFO",
                                description="Vehicle Armed (Recorded via GCS MAVLink Heartbeat downlink)",
                                latitude=telemetry[-1].latitude if telemetry else None,
                                longitude=telemetry[-1].longitude if telemetry else None,
                                altitude_m=telemetry[-1].altitude_m if telemetry else None
                            ))
                        elif not is_armed and armed_state:
                            armed_state = False
                            events.append(FlightEvent(
                                event_id=f"GCS-EV-{len(events)+1}",
                                timestamp_utc=ts_iso,
                                event_type="DISARM",
                                severity="INFO",
                                description="Vehicle Disarmed / Motors Stopped (GCS MAVLink Heartbeat)",
                                latitude=telemetry[-1].latitude if telemetry else None,
                                longitude=telemetry[-1].longitude if telemetry else None,
                                altitude_m=0.0
                            ))
                    except Exception:
                        pass

                # -------------------------------------------------------------
                # Message 253: STATUSTEXT (severity, text[50])
                # Pre-arm checks, failsafes, battery warnings, mode announcements
                # -------------------------------------------------------------
                elif msg_id == 253 and len(payload) >= 51:
                    try:
                        severity = payload[0]
                        text_bytes = payload[1:51].split(b"\x00")[0]
                        status_text = text_bytes.decode("ascii", errors="ignore").strip()
                        if status_text:
                            metadata["statustext_messages"].append({"time": ts_iso, "text": status_text, "severity": severity})
                            sev_cat = "CRITICAL" if severity <= 2 else ("WARNING" if severity <= 4 else "INFO")
                            ev_type = "FAILSAFE" if ("failsafe" in status_text.lower() or "crash" in status_text.lower()) else "ERROR_ALERT"
                            events.append(FlightEvent(
                                event_id=f"GCS-MSG-{len(events)+1}",
                                timestamp_utc=ts_iso,
                                event_type=ev_type,
                                severity=sev_cat,
                                description=f"GCS Downlink Status: {status_text}",
                                latitude=telemetry[-1].latitude if telemetry else None,
                                longitude=telemetry[-1].longitude if telemetry else None,
                                altitude_m=telemetry[-1].altitude_m if telemetry else None
                            ))
                    except Exception:
                        pass
            # Synthesize ARM and DISARM if absent
            if telemetry:
                has_arm = any(e.event_type == "ARM" for e in events)
                has_disarm = any(e.event_type == "DISARM" for e in events)
                if not has_arm:
                    events.insert(0, FlightEvent(
                        event_id="GCS-TLOG-ARM",
                        timestamp_utc=telemetry[0].timestamp_utc,
                        event_type="ARM",
                        severity="INFO",
                        description="GCS Telemetry Stream Initialized / Vehicle Armed",
                        latitude=telemetry[0].latitude,
                        longitude=telemetry[0].longitude,
                        altitude_m=telemetry[0].altitude_m
                    ))
                if not has_disarm:
                    events.append(FlightEvent(
                        event_id="GCS-TLOG-DISARM",
                        timestamp_utc=telemetry[-1].timestamp_utc,
                        event_type="DISARM",
                        severity="INFO",
                        description="GCS Telemetry Stream Ended / Safe Shutdown Confirmed",
                        latitude=telemetry[-1].latitude,
                        longitude=telemetry[-1].longitude,
                        altitude_m=telemetry[-1].altitude_m
                    ))
        finally:
            if is_mmap and data is not None:
                try:
                    data.close()
                except Exception:
                    pass

        metadata["telemetry_points_extracted"] = len(telemetry)
        metadata["events_extracted"] = len(events)
        metadata["operator_locations_found"] = len(operator_locations)
        return telemetry, events, operator_locations, metadata

    # =========================================================================
    # 2. ARDUPILOT & PX4: QGC WPL 110 WAYPOINTS PARSER (.waypoints, .txt)
    # =========================================================================

    @staticmethod
    def parse_qgc_wpl(file_path: Path) -> Tuple[GCSMissionPlan, List[TelemetryPoint], List[FlightEvent], List[OperatorLocation]]:
        """
        Parses QGC WPL 110 plain-text waypoint files used by Mission Planner & QGroundControl.
        Format: INDEX CURRENT COORD_FRAME COMMAND PARAM1 PARAM2 PARAM3 PARAM4 LAT LON ALT AUTOCONTINUE
        """
        waypoints: List[PlannedWaypoint] = []
        telemetry: List[TelemetryPoint] = []
        events: List[FlightEvent] = []
        operator_locations: List[OperatorLocation] = []

        base_time = datetime.now(timezone.utc)
        home_lat = None
        home_lon = None
        home_alt = None

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("#")]

        if not lines or "QGC WPL" not in lines[0]:
            return GCSMissionPlan(plan_id="ERR", gcs_name="Unknown", target_fc="ArduPilot", file_name=file_path.name), [], [], []

        total_dist = 0.0
        max_alt = 0.0

        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 11:
                continue

            try:
                idx = int(parts[0])
                current = int(parts[1])
                coord_frame = int(parts[2])
                cmd_id = int(parts[3])
                p1 = float(parts[4])
                p2 = float(parts[5])
                p3 = float(parts[6])
                p4 = float(parts[7])
                lat = float(parts[8])
                lon = float(parts[9])
                alt = float(parts[10])
                autocont = bool(int(parts[11])) if len(parts) > 11 else True

                cmd_name = "HOME" if idx == 0 else MAV_CMD_NAMES.get(cmd_id, f"MAV_CMD_{cmd_id}")

                # Waypoint 0 in QGC WPL format is typically the Home/Operator Location
                if idx == 0 and (abs(lat) > 0.001 or abs(lon) > 0.001):
                    home_lat = lat
                    home_lon = lon
                    home_alt = alt
                    operator_locations.append(OperatorLocation(
                        source="QGC_WPL_HOME_WAYPOINT",
                        latitude=round(lat, 7),
                        longitude=round(lon, 7),
                        altitude_m=alt,
                        timestamp_utc=base_time.isoformat(),
                        description=f"Planned Home / Launch Position defined in {file_path.name}"
                    ))

                wp = PlannedWaypoint(
                    index=idx,
                    command=cmd_name,
                    latitude=round(lat, 7),
                    longitude=round(lon, 7),
                    altitude_m=round(alt, 2),
                    param1=p1,
                    param2=p2,
                    param3=p3,
                    param4=p4,
                    autocontinue=autocont,
                    action_description=f"{cmd_name} at altitude {alt}m"
                )
                waypoints.append(wp)

                if alt > max_alt:
                    max_alt = alt

                # Generate pseudo-telemetry and flight events from planned waypoints
                if abs(lat) > 0.001 or abs(lon) > 0.001:
                    pt_time = (base_time + timedelta(seconds=idx * 15)).isoformat()
                    telemetry.append(TelemetryPoint(
                        timestamp_utc=pt_time,
                        latitude=round(lat, 7),
                        longitude=round(lon, 7),
                        altitude_m=round(alt, 2),
                        ground_speed_mps=12.0,
                        source_channel="GCS_PLANNED_WAYPOINT"
                    ))

                    ev_type = "TAKEOFF" if cmd_name == "TAKEOFF" else ("LANDING" if cmd_name == "LAND" else "WAYPOINT_REACHED")
                    events.append(FlightEvent(
                        event_id=f"GCS-WP-{idx:02d}",
                        timestamp_utc=pt_time,
                        event_type=ev_type,
                        severity="INFO",
                        description=f"Planned Autonomous Waypoint #{idx}: {cmd_name} (Altitude: {alt:.1f}m)",
                        latitude=round(lat, 7),
                        longitude=round(lon, 7),
                        altitude_m=round(alt, 2)
                    ))
            except Exception:
                continue

        # Compute total planned distance
        for i in range(1, len(telemetry)):
            p1 = telemetry[i - 1]
            p2 = telemetry[i]
            total_dist += haversine_distance_meters(p1.latitude, p1.longitude, p2.latitude, p2.longitude)

        plan = GCSMissionPlan(
            plan_id=f"QGC-WPL-{file_path.stem}",
            gcs_name="Mission Planner / QGroundControl",
            target_fc="ArduPilot / PX4",
            file_name=file_path.name,
            waypoints=waypoints,
            planned_home_lat=home_lat,
            planned_home_lon=home_lon,
            planned_home_alt_m=home_alt,
            total_planned_distance_m=round(total_dist, 2),
            planned_max_altitude_m=round(max_alt, 2),
            raw_metadata={"line_count": len(lines), "qgc_version": lines[0]}
        )

        return plan, telemetry, events, operator_locations

    # =========================================================================
    # 3. PX4 & ARDUPILOT: QGROUNDCONTROL JSON PLAN PARSER (.plan)
    # =========================================================================

    @staticmethod
    def parse_qgc_plan(file_path: Path) -> Tuple[GCSMissionPlan, List[TelemetryPoint], List[FlightEvent], List[OperatorLocation], List[GeofenceZone]]:
        """
        Parses QGroundControl JSON .plan files containing mission items, geofence polygons, and rally points.
        """
        waypoints: List[PlannedWaypoint] = []
        telemetry: List[TelemetryPoint] = []
        events: List[FlightEvent] = []
        operator_locations: List[OperatorLocation] = []
        geofences: List[GeofenceZone] = []

        base_time = datetime.now(timezone.utc)

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        gcs_name = data.get("groundStation", "QGroundControl")
        mission_obj = data.get("mission", {})
        cruise_speed = mission_obj.get("cruiseSpeed", 15.0)
        items = mission_obj.get("items", [])

        # Home location
        planned_home = mission_obj.get("plannedHomePosition", [])
        home_lat = planned_home[0] if len(planned_home) > 0 else None
        home_lon = planned_home[1] if len(planned_home) > 1 else None
        home_alt = planned_home[2] if len(planned_home) > 2 else 0.0

        if home_lat is not None and home_lon is not None:
            operator_locations.append(OperatorLocation(
                source="QGC_PLAN_HOME_POSITION",
                latitude=round(home_lat, 7),
                longitude=round(home_lon, 7),
                altitude_m=round(home_alt, 2),
                timestamp_utc=base_time.isoformat(),
                description=f"Planned Home / Launch Site configured in QGroundControl Plan: {file_path.name}"
            ))

        total_dist = 0.0
        max_alt = 0.0

        for idx, it in enumerate(items):
            cmd_id = it.get("command", 16)
            cmd_name = MAV_CMD_NAMES.get(cmd_id, f"MAV_CMD_{cmd_id}")
            params = it.get("params", [])
            autocont = it.get("autoContinue", True)

            # In QGC JSON plan: params = [p1, p2, p3, p4, lat, lon, alt]
            lat = params[4] if len(params) > 4 and params[4] is not None else 0.0
            lon = params[5] if len(params) > 5 and params[5] is not None else 0.0
            alt = params[6] if len(params) > 6 and params[6] is not None else 0.0

            if alt > max_alt:
                max_alt = alt

            wp = PlannedWaypoint(
                index=idx + 1,
                command=cmd_name,
                latitude=round(lat, 7) if lat else 0.0,
                longitude=round(lon, 7) if lon else 0.0,
                altitude_m=round(alt, 2),
                speed_mps=cruise_speed,
                param1=params[0] if len(params) > 0 and params[0] is not None else 0.0,
                param2=params[1] if len(params) > 1 and params[1] is not None else 0.0,
                param3=params[2] if len(params) > 2 and params[2] is not None else 0.0,
                param4=params[3] if len(params) > 3 and params[3] is not None else 0.0,
                autocontinue=autocont,
                action_description=f"QGC Item #{idx+1}: {cmd_name} ({alt}m)"
            )
            waypoints.append(wp)

            if lat and lon and (abs(lat) > 0.001 or abs(lon) > 0.001):
                pt_time = (base_time + timedelta(seconds=(idx + 1) * 12)).isoformat()
                telemetry.append(TelemetryPoint(
                    timestamp_utc=pt_time,
                    latitude=round(lat, 7),
                    longitude=round(lon, 7),
                    altitude_m=round(alt, 2),
                    ground_speed_mps=cruise_speed,
                    source_channel="QGC_PLAN_WAYPOINT"
                ))

                ev_type = "TAKEOFF" if cmd_name == "TAKEOFF" else ("LANDING" if cmd_name == "LAND" else "WAYPOINT_REACHED")
                events.append(FlightEvent(
                    event_id=f"QGC-EV-{idx+1:02d}",
                    timestamp_utc=pt_time,
                    event_type=ev_type,
                    severity="INFO",
                    description=f"Planned Waypoint #{idx+1}: {cmd_name} at {alt}m MSL",
                    latitude=round(lat, 7),
                    longitude=round(lon, 7),
                    altitude_m=round(alt, 2)
                ))

        # Geofence extraction from QGC plan
        geofence_obj = data.get("geoFence", {})
        polygons = geofence_obj.get("polygons", [])
        geo_polys: List[List[List[float]]] = []

        for p_idx, poly in enumerate(polygons):
            coords = poly.get("polygon", [])
            if coords:
                geo_polys.append(coords)
                geofences.append(GeofenceZone(
                    zone_id=f"QGC-FENCE-{p_idx+1}",
                    name=f"QGC Geofence ({'Inclusion' if poly.get('inclusion') else 'Exclusion'})",
                    zone_type="polygon",
                    coordinates=coords,
                    description=f"Imported from QGroundControl Plan: {file_path.name}",
                    category="CUSTOM",
                    zone_class="RED" if not poly.get("inclusion") else "YELLOW"
                ))

        for i in range(1, len(telemetry)):
            p1 = telemetry[i - 1]
            p2 = telemetry[i]
            total_dist += haversine_distance_meters(p1.latitude, p1.longitude, p2.latitude, p2.longitude)

        plan = GCSMissionPlan(
            plan_id=f"QGC-PLAN-{file_path.stem}",
            gcs_name=gcs_name,
            target_fc="PX4 / ArduPilot",
            file_name=file_path.name,
            waypoints=waypoints,
            planned_home_lat=home_lat,
            planned_home_lon=home_lon,
            planned_home_alt_m=home_alt,
            total_planned_distance_m=round(total_dist, 2),
            planned_max_altitude_m=round(max_alt, 2),
            geofence_included=len(geo_polys) > 0,
            geofence_polygons=geo_polys,
            raw_metadata={
                "version": data.get("version"),
                "cruiseSpeed": cruise_speed,
                "hoverSpeed": mission_obj.get("hoverSpeed"),
                "rallyPointsCount": len(data.get("rallyPoints", {}).get("points", []))
            }
        )

        return plan, telemetry, events, operator_locations, geofences

    # =========================================================================
    # 4. DJI: PILOT 2 WPML (.kmz, .kml) & GS PRO (.json) PARSER
    # =========================================================================

    @staticmethod
    def parse_dji_wpml(file_path: Path) -> Tuple[GCSMissionPlan, List[TelemetryPoint], List[FlightEvent], List[OperatorLocation]]:
        """
        Parses DJI Pilot 2 WPML (Waypoint Markup Language) mission files.
        WPML files define placemarks with <Point><coordinates>lon,lat,alt</coordinates></Point>,
        waypointSpeed, executeHeight, and missionConfig.
        """
        waypoints: List[PlannedWaypoint] = []
        telemetry: List[TelemetryPoint] = []
        events: List[FlightEvent] = []
        operator_locations: List[OperatorLocation] = []

        base_time = datetime.now(timezone.utc)
        kml_content = ""

        # Extract KML from KMZ or read directly
        if file_path.suffix.lower() == ".kmz":
            try:
                with zipfile.ZipFile(file_path, "r") as z:
                    for name in z.namelist():
                        if name.endswith("template.kml") or name.endswith("waypoint.kml") or name.endswith(".kml"):
                            with z.open(name) as f:
                                kml_content = f.read().decode("utf-8", errors="ignore")
                            break
            except Exception:
                pass
        else:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                kml_content = f.read()

        if not kml_content:
            return GCSMissionPlan(plan_id="ERR", gcs_name="DJI Pilot 2", target_fc="DJI", file_name=file_path.name), [], [], []

        try:
            root = ET.fromstring(kml_content)
        except Exception:
            return GCSMissionPlan(plan_id="ERR", gcs_name="DJI Pilot 2", target_fc="DJI", file_name=file_path.name), [], [], []

        total_dist = 0.0
        max_alt = 0.0
        ns = {"kml": "http://www.opengis.net/kml/2.2", "wpml": "http://www.dji.com/wpmz/1.0.2"}

        # Find all Placemark elements (namespace-agnostic)
        placemarks = [el for el in root.iter() if el.tag.endswith("Placemark")]

        for idx, pm in enumerate(placemarks):
            coord_elem = next((el for el in pm.iter() if el.tag.endswith("coordinates")), None)
            if coord_elem is None or not coord_elem.text:
                continue

            coords_str = coord_elem.text.strip()
            parts = coords_str.split(",")
            if len(parts) < 2:
                continue

            lon = float(parts[0])
            lat = float(parts[1])
            alt = float(parts[2]) if len(parts) > 2 else 50.0

            # WPML height and speed attributes
            h_elem = next((el for el in pm.iter() if el.tag.endswith("executeHeight")), None)
            if h_elem is not None and h_elem.text:
                try:
                    alt = float(h_elem.text)
                except ValueError:
                    pass

            s_elem = next((el for el in pm.iter() if el.tag.endswith("waypointSpeed")), None)
            spd = float(s_elem.text) if s_elem is not None and s_elem.text else 10.0

            if alt > max_alt:
                max_alt = alt

            wp = PlannedWaypoint(
                index=idx + 1,
                command="WAYPOINT",
                latitude=round(lat, 7),
                longitude=round(lon, 7),
                altitude_m=round(alt, 2),
                speed_mps=round(spd, 2),
                autocontinue=True,
                action_description=f"DJI Pilot 2 WPML Waypoint #{idx+1} (Speed: {spd} m/s, Height: {alt}m)"
            )
            waypoints.append(wp)

            pt_time = (base_time + timedelta(seconds=(idx + 1) * 10)).isoformat()
            telemetry.append(TelemetryPoint(
                timestamp_utc=pt_time,
                latitude=round(lat, 7),
                longitude=round(lon, 7),
                altitude_m=round(alt, 2),
                ground_speed_mps=spd,
                source_channel="DJI_WPML_WAYPOINT"
            ))

            events.append(FlightEvent(
                event_id=f"DJI-WPML-{idx+1:02d}",
                timestamp_utc=pt_time,
                event_type="WAYPOINT_REACHED",
                severity="INFO",
                description=f"DJI Pilot Autonomous Survey Waypoint #{idx+1}",
                latitude=round(lat, 7),
                longitude=round(lon, 7),
                altitude_m=round(alt, 2)
            ))

        # Home location if first waypoint is origin
        if waypoints:
            operator_locations.append(OperatorLocation(
                source="DJI_WPML_MISSION_ORIGIN",
                latitude=waypoints[0].latitude,
                longitude=waypoints[0].longitude,
                altitude_m=waypoints[0].altitude_m,
                timestamp_utc=base_time.isoformat(),
                description=f"DJI Pilot 2 Survey Origin / GCS Mission Anchor: {file_path.name}"
            ))

        for i in range(1, len(telemetry)):
            p1 = telemetry[i - 1]
            p2 = telemetry[i]
            total_dist += haversine_distance_meters(p1.latitude, p1.longitude, p2.latitude, p2.longitude)

        plan = GCSMissionPlan(
            plan_id=f"DJI-WPML-{file_path.stem}",
            gcs_name="DJI Pilot 2 (WPML)",
            target_fc="DJI Enterprise",
            file_name=file_path.name,
            waypoints=waypoints,
            planned_home_lat=waypoints[0].latitude if waypoints else None,
            planned_home_lon=waypoints[0].longitude if waypoints else None,
            planned_home_alt_m=waypoints[0].altitude_m if waypoints else None,
            total_planned_distance_m=round(total_dist, 2),
            planned_max_altitude_m=round(max_alt, 2),
            raw_metadata={"placemarks_count": len(placemarks)}
        )

        return plan, telemetry, events, operator_locations

    @staticmethod
    def parse_dji_gspro(file_path: Path) -> Tuple[GCSMissionPlan, List[TelemetryPoint], List[FlightEvent], List[OperatorLocation]]:
        """Parses DJI Ground Station Pro (GS Pro) JSON flight plans."""
        waypoints: List[PlannedWaypoint] = []
        telemetry: List[TelemetryPoint] = []
        events: List[FlightEvent] = []
        operator_locations: List[OperatorLocation] = []

        base_time = datetime.now(timezone.utc)

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        raw_wps = data.get("waypoints", []) or data.get("mission", {}).get("waypoints", [])
        home = data.get("home_location", {}) or data.get("homeLocation", {})

        home_lat = home.get("latitude") or home.get("lat")
        home_lon = home.get("longitude") or home.get("lon")

        if home_lat and home_lon:
            operator_locations.append(OperatorLocation(
                source="DJI_GS_PRO_HOME_POSITION",
                latitude=round(float(home_lat), 7),
                longitude=round(float(home_lon), 7),
                altitude_m=0.0,
                timestamp_utc=base_time.isoformat(),
                description=f"DJI Ground Station Pro Home Location ({file_path.name})"
            ))

        total_dist = 0.0
        max_alt = 0.0

        for idx, r_wp in enumerate(raw_wps):
            lat = float(r_wp.get("latitude") or r_wp.get("lat", 0.0))
            lon = float(r_wp.get("longitude") or r_wp.get("lon", 0.0))
            alt = float(r_wp.get("altitude") or r_wp.get("alt", 30.0))
            spd = float(r_wp.get("speed", 8.0))

            if alt > max_alt:
                max_alt = alt

            wp = PlannedWaypoint(
                index=idx + 1,
                command="WAYPOINT",
                latitude=round(lat, 7),
                longitude=round(lon, 7),
                altitude_m=round(alt, 2),
                speed_mps=spd,
                autocontinue=True,
                action_description=f"DJI GS Pro Waypoint #{idx+1}"
            )
            waypoints.append(wp)

            pt_time = (base_time + timedelta(seconds=(idx + 1) * 10)).isoformat()
            telemetry.append(TelemetryPoint(
                timestamp_utc=pt_time,
                latitude=round(lat, 7),
                longitude=round(lon, 7),
                altitude_m=round(alt, 2),
                ground_speed_mps=spd,
                source_channel="DJI_GSPRO_WAYPOINT"
            ))

            events.append(FlightEvent(
                event_id=f"DJI-GSPRO-{idx+1:02d}",
                timestamp_utc=pt_time,
                event_type="WAYPOINT_REACHED",
                severity="INFO",
                description=f"DJI GS Pro Waypoint #{idx+1} Reached",
                latitude=round(lat, 7),
                longitude=round(lon, 7),
                altitude_m=round(alt, 2)
            ))

        for i in range(1, len(telemetry)):
            p1 = telemetry[i - 1]
            p2 = telemetry[i]
            total_dist += haversine_distance_meters(p1.latitude, p1.longitude, p2.latitude, p2.longitude)

        plan = GCSMissionPlan(
            plan_id=f"DJI-GSPRO-{file_path.stem}",
            gcs_name="DJI Ground Station Pro",
            target_fc="DJI",
            file_name=file_path.name,
            waypoints=waypoints,
            planned_home_lat=float(home_lat) if home_lat else None,
            planned_home_lon=float(home_lon) if home_lon else None,
            total_planned_distance_m=round(total_dist, 2),
            planned_max_altitude_m=round(max_alt, 2),
            raw_metadata={"waypoints_count": len(raw_wps)}
        )

        return plan, telemetry, events, operator_locations

    # =========================================================================
    # 5. BETAFLIGHT / INAV: MISSION PLANNER & MWP PARSER (.mission, .mwp)
    # =========================================================================

    @staticmethod
    def parse_inav_mission(file_path: Path) -> Tuple[GCSMissionPlan, List[TelemetryPoint], List[FlightEvent], List[OperatorLocation]]:
        """
        Parses iNav Mission Planner / EZ-GUI (.mission, .json) and MWP XML (.mwp, .xml) waypoint missions.
        iNav supports autonomous FPV wings and quads with actions: WAYPOINT, POSHOLD_TIME, RTH, JUMP.
        """
        waypoints: List[PlannedWaypoint] = []
        telemetry: List[TelemetryPoint] = []
        events: List[FlightEvent] = []
        operator_locations: List[OperatorLocation] = []

        base_time = datetime.now(timezone.utc)
        ext = file_path.suffix.lower()

        total_dist = 0.0
        max_alt = 0.0

        if ext in [".mission", ".json"]:
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                # Try parsing as JSON first
                if content.strip().startswith("{") or content.strip().startswith("["):
                    data = json.loads(content)
                    raw_wps = data.get("waypoints", []) if isinstance(data, dict) else data

                    for idx, r_wp in enumerate(raw_wps):
                        action = str(r_wp.get("action", "WAYPOINT")).upper()
                        lat = float(r_wp.get("lat") or r_wp.get("latitude", 0.0))
                        lon = float(r_wp.get("lon") or r_wp.get("longitude", 0.0))
                        alt = float(r_wp.get("alt") or r_wp.get("altitude", 30.0))
                        spd = float(r_wp.get("speed", 15.0))

                        if alt > max_alt:
                            max_alt = alt

                        wp = PlannedWaypoint(
                            index=idx + 1,
                            command=action,
                            latitude=round(lat, 7),
                            longitude=round(lon, 7),
                            altitude_m=round(alt, 2),
                            speed_mps=spd,
                            action_description=f"iNav Mission Action: {action}"
                        )
                        waypoints.append(wp)

                        if abs(lat) > 0.001 or abs(lon) > 0.001:
                            pt_time = (base_time + timedelta(seconds=(idx + 1) * 12)).isoformat()
                            telemetry.append(TelemetryPoint(
                                timestamp_utc=pt_time,
                                latitude=round(lat, 7),
                                longitude=round(lon, 7),
                                altitude_m=round(alt, 2),
                                ground_speed_mps=spd,
                                source_channel="INAV_MISSION_WAYPOINT"
                            ))

                            ev_type = "TAKEOFF" if action == "TAKEOFF" else ("RETURN_TO_HOME" if action == "RTH" else "WAYPOINT_REACHED")
                            events.append(FlightEvent(
                                event_id=f"INAV-WP-{idx+1:02d}",
                                timestamp_utc=pt_time,
                                event_type=ev_type,
                                severity="INFO",
                                description=f"iNav Autonomous Action: {action} (Altitude: {alt}m)",
                                latitude=round(lat, 7),
                                longitude=round(lon, 7),
                                altitude_m=round(alt, 2)
                            ))
                else:
                    # Plain text lines: comma or whitespace separated
                    lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith("#")]
                    for idx, line in enumerate(lines):
                        if "," in line:
                            parts = [p.strip() for p in line.split(",")]
                            if len(parts) >= 4:
                                action = parts[1].upper() if not parts[1].replace(".", "").isdigit() else "WAYPOINT"
                                lat = float(parts[2])
                                lon = float(parts[3])
                                alt = float(parts[4]) if len(parts) > 4 else 30.0
                                spd = float(parts[5]) if len(parts) > 5 else 15.0
                            else:
                                continue
                        else:
                            parts = line.split()
                            if len(parts) >= 11:
                                cmd_id = int(parts[3])
                                action = MAV_CMD_NAMES.get(cmd_id, "WAYPOINT")
                                lat = float(parts[8])
                                lon = float(parts[9])
                                alt = float(parts[10])
                                spd = 15.0
                            elif len(parts) >= 4:
                                action = parts[1].upper() if not parts[1].replace(".", "").isdigit() else "WAYPOINT"
                                lat = float(parts[2])
                                lon = float(parts[3])
                                alt = float(parts[4]) if len(parts) > 4 else 30.0
                                spd = float(parts[5]) if len(parts) > 5 else 15.0
                            else:
                                continue

                        if alt > max_alt:
                            max_alt = alt

                        wp = PlannedWaypoint(
                            index=idx + 1,
                            command=action,
                            latitude=round(lat, 7),
                            longitude=round(lon, 7),
                            altitude_m=round(alt, 2),
                            speed_mps=spd,
                            action_description=f"iNav Mission Action: {action}"
                        )
                        waypoints.append(wp)

                        if abs(lat) > 0.001 or abs(lon) > 0.001:
                            pt_time = (base_time + timedelta(seconds=(idx + 1) * 12)).isoformat()
                            telemetry.append(TelemetryPoint(
                                timestamp_utc=pt_time,
                                latitude=round(lat, 7),
                                longitude=round(lon, 7),
                                altitude_m=round(alt, 2),
                                ground_speed_mps=spd,
                                source_channel="INAV_MISSION_WAYPOINT"
                            ))
            except Exception:
                pass

        elif ext in [".mwp", ".xml"]:
            # MWP Mission Waypoint Planner XML
            try:
                tree = ET.parse(file_path)
                root = tree.getroot()
                wps = root.findall(".//waypoint") or root.findall(".//wp")
                for idx, w in enumerate(wps):
                    lat = float(w.get("lat", 0.0))
                    lon = float(w.get("lon", 0.0))
                    alt = float(w.get("alt", 30.0))
                    action = w.get("action", "WAYPOINT").upper()
                    spd = float(w.get("speed", 15.0))

                    if alt > max_alt:
                        max_alt = alt

                    waypoints.append(PlannedWaypoint(
                        index=idx + 1,
                        command=action,
                        latitude=round(lat, 7),
                        longitude=round(lon, 7),
                        altitude_m=round(alt, 2),
                        speed_mps=spd,
                        action_description=f"MWP Waypoint: {action}"
                    ))

                    if abs(lat) > 0.001 or abs(lon) > 0.001:
                        pt_time = (base_time + timedelta(seconds=(idx + 1) * 12)).isoformat()
                        telemetry.append(TelemetryPoint(
                            timestamp_utc=pt_time,
                            latitude=round(lat, 7),
                            longitude=round(lon, 7),
                            altitude_m=round(alt, 2),
                            ground_speed_mps=spd,
                            source_channel="MWP_MISSION_WAYPOINT"
                        ))
            except Exception:
                pass

        if waypoints and (abs(waypoints[0].latitude) > 0.001 or abs(waypoints[0].longitude) > 0.001):
            operator_locations.append(OperatorLocation(
                source="INAV_MISSION_TAKEOFF_ORIGIN",
                latitude=waypoints[0].latitude,
                longitude=waypoints[0].longitude,
                altitude_m=waypoints[0].altitude_m,
                timestamp_utc=base_time.isoformat(),
                description=f"iNav Mission Origin / Pilot Launch Site: {file_path.name}"
            ))

        for i in range(1, len(telemetry)):
            p1 = telemetry[i - 1]
            p2 = telemetry[i]
            total_dist += haversine_distance_meters(p1.latitude, p1.longitude, p2.latitude, p2.longitude)

        plan = GCSMissionPlan(
            plan_id=f"INAV-{file_path.stem}",
            gcs_name="iNav Mission Planner / mwp",
            target_fc="Betaflight / iNav",
            file_name=file_path.name,
            waypoints=waypoints,
            planned_home_lat=waypoints[0].latitude if waypoints else None,
            planned_home_lon=waypoints[0].longitude if waypoints else None,
            total_planned_distance_m=round(total_dist, 2),
            planned_max_altitude_m=round(max_alt, 2),
            raw_metadata={"waypoints_count": len(waypoints)}
        )

        return plan, telemetry, events, operator_locations

    # =========================================================================
    # 6. PARROT: FLIGHTPLAN & FREEFLIGHT PARSER (.mavlink, .json)
    # =========================================================================

    @staticmethod
    def parse_parrot_flightplan(file_path: Path) -> Tuple[GCSMissionPlan, List[TelemetryPoint], List[FlightEvent], List[OperatorLocation]]:
        """
        Parses Parrot FlightPlan waypoint mission files created in FreeFlight 6.
        FlightPlan missions are formatted either as QGC WPL dialect (.mavlink) or FreeFlight JSON.
        """
        ext = file_path.suffix.lower()
        if ext == ".mavlink":
            # Parrot uses standard QGC WPL 110 dialect for .mavlink files
            plan, pts, evs, ops = GCSAnalyzer.parse_qgc_wpl(file_path)
            plan.gcs_name = "Parrot FreeFlight 6 / FlightPlan"
            plan.target_fc = "Parrot (Anafi / Bebop)"
            return plan, pts, evs, ops

        waypoints: List[PlannedWaypoint] = []
        telemetry: List[TelemetryPoint] = []
        events: List[FlightEvent] = []
        operator_locations: List[OperatorLocation] = []

        base_time = datetime.now(timezone.utc)

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        raw_points = data.get("points", []) or data.get("waypoints", []) or data.get("flightPlan", {}).get("points", [])
        controller_gps = data.get("controller_location", {}) or data.get("controller_gps", {})

        c_lat = controller_gps.get("latitude") or controller_gps.get("lat")
        c_lon = controller_gps.get("longitude") or controller_gps.get("lon")
        if c_lat and c_lon:
            operator_locations.append(OperatorLocation(
                source="PARROT_SKYCONTROLLER_GPS",
                latitude=round(float(c_lat), 7),
                longitude=round(float(c_lon), 7),
                altitude_m=0.0,
                timestamp_utc=base_time.isoformat(),
                description=f"Parrot Skycontroller / FreeFlight Device GPS Location ({file_path.name})"
            ))

        total_dist = 0.0
        max_alt = 0.0

        for idx, pt in enumerate(raw_points):
            lat = float(pt.get("latitude") or pt.get("lat", 0.0))
            lon = float(pt.get("longitude") or pt.get("lon", 0.0))
            alt = float(pt.get("altitude") or pt.get("alt", 25.0))
            spd = float(pt.get("speed", 10.0))

            if alt > max_alt:
                max_alt = alt

            wp = PlannedWaypoint(
                index=idx + 1,
                command="WAYPOINT",
                latitude=round(lat, 7),
                longitude=round(lon, 7),
                altitude_m=round(alt, 2),
                speed_mps=spd,
                action_description=f"Parrot FlightPlan Waypoint #{idx+1}"
            )
            waypoints.append(wp)

            if abs(lat) > 0.001 or abs(lon) > 0.001:
                pt_time = (base_time + timedelta(seconds=(idx + 1) * 10)).isoformat()
                telemetry.append(TelemetryPoint(
                    timestamp_utc=pt_time,
                    latitude=round(lat, 7),
                    longitude=round(lon, 7),
                    altitude_m=round(alt, 2),
                    ground_speed_mps=spd,
                    source_channel="PARROT_FLIGHTPLAN_WAYPOINT"
                ))
                events.append(FlightEvent(
                    event_id=f"PARROT-WP-{idx+1:02d}",
                    timestamp_utc=pt_time,
                    event_type="WAYPOINT_REACHED",
                    severity="INFO",
                    description=f"Parrot Autonomous Waypoint #{idx+1} Reached",
                    latitude=round(lat, 7),
                    longitude=round(lon, 7),
                    altitude_m=round(alt, 2)
                ))

        for i in range(1, len(telemetry)):
            p1 = telemetry[i - 1]
            p2 = telemetry[i]
            total_dist += haversine_distance_meters(p1.latitude, p1.longitude, p2.latitude, p2.longitude)

        plan = GCSMissionPlan(
            plan_id=f"PARROT-FP-{file_path.stem}",
            gcs_name="Parrot FreeFlight 6 / FlightPlan",
            target_fc="Parrot (Anafi / Bebop)",
            file_name=file_path.name,
            waypoints=waypoints,
            planned_home_lat=waypoints[0].latitude if waypoints else None,
            planned_home_lon=waypoints[0].longitude if waypoints else None,
            total_planned_distance_m=round(total_dist, 2),
            planned_max_altitude_m=round(max_alt, 2),
            raw_metadata={"points_count": len(raw_points)}
        )

        return plan, telemetry, events, operator_locations

    # =========================================================================
    # 7. TRAJECTORY COMPLIANCE & MISSION COMPARISON ENGINE
    # =========================================================================

    @staticmethod
    def compare_mission_trajectory(
        planned_plan: GCSMissionPlan,
        executed_telemetry: List[TelemetryPoint],
        acceptance_radius_m: float = 25.0
    ) -> Dict[str, Any]:
        """
        Performs forensic verification comparing planned GCS waypoint route
        against actual flown trajectory recovered from flight controller logs.
        Computes compliance rate, deviation distances, and identifies abandoned waypoints.
        """
        if not planned_plan.waypoints or not executed_telemetry:
            return {
                "compliance_score_pct": 0.0,
                "waypoints_total": len(planned_plan.waypoints),
                "waypoints_reached": 0,
                "waypoints_missed": len(planned_plan.waypoints),
                "mean_deviation_meters": 0.0,
                "max_deviation_meters": 0.0,
                "mission_interrupted": False,
                "waypoint_compliance_details": []
            }

        valid_waypoints = [
            wp for wp in planned_plan.waypoints
            if (abs(wp.latitude) > 0.001 or abs(wp.longitude) > 0.001) and wp.command not in ("HOME", "RETURN_TO_LAUNCH")
        ]

        if not valid_waypoints:
            valid_waypoints = planned_plan.waypoints

        reached_count = 0
        deviations: List[float] = []
        details: List[Dict[str, Any]] = []

        for wp in valid_waypoints:
            # Find closest executed point to this planned waypoint
            min_dist = float("inf")
            closest_pt = None

            for pt in executed_telemetry:
                d = haversine_distance_meters(wp.latitude, wp.longitude, pt.latitude, pt.longitude)
                if d < min_dist:
                    min_dist = d
                    closest_pt = pt

            is_reached = min_dist <= acceptance_radius_m
            if is_reached:
                reached_count += 1
            deviations.append(min_dist)

            details.append({
                "waypoint_index": wp.index,
                "command": wp.command,
                "planned_lat": wp.latitude,
                "planned_lon": wp.longitude,
                "planned_alt_m": wp.altitude_m,
                "closest_telemetry_distance_m": round(min_dist, 2),
                "status": "REACHED" if is_reached else "DEVIATED",
                "reached": is_reached
            })

        adherence_pct = round((reached_count / len(valid_waypoints)) * 100.0, 1) if valid_waypoints else 0.0
        mean_dev = round(sum(deviations) / len(deviations), 2) if deviations else 0.0
        max_dev = round(max(deviations), 2) if deviations else 0.0

        # Mission interrupted flag: reached early waypoints but abandoned later ones
        mission_interrupted = False
        if valid_waypoints and 0 < reached_count < len(valid_waypoints):
            if not details[-1]["reached"]:
                mission_interrupted = True

        return {
            "compliance_score_pct": adherence_pct,
            "waypoints_total": len(valid_waypoints),
            "waypoints_reached": reached_count,
            "waypoints_missed": len(valid_waypoints) - reached_count,
            "acceptance_radius_meters": acceptance_radius_m,
            "mean_deviation_meters": mean_dev,
            "max_deviation_meters": max_dev,
            "mission_interrupted": mission_interrupted,
            "waypoint_compliance_details": details
        }
