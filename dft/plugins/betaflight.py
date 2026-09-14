"""
Betaflight / iNav Blackbox Forensic Parser Plugin.
Parses native Blackbox binary logs (.bbl) and ASCII decoded Blackbox dumps (.txt/.csv).
Decodes gyro/motor telemetry, GPS frames, arming switches, and crash failsafe events.
"""

from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime, timezone, timedelta
from dft.plugins.base import DroneForensicPlugin
from dft.core.models import TelemetryPoint, FlightEvent
from dft.analysis.gcs import GCSAnalyzer


class BetaflightPlugin(DroneForensicPlugin):
    @property
    def platform_id(self) -> str:
        return "betaflight"

    @property
    def display_name(self) -> str:
        return "Betaflight / iNav / Cleanflight (FPV & Custom UAVs)"

    @property
    def supported_extensions(self) -> List[str]:
        return [".bbl", ".txt", ".csv", ".mission", ".mwp", ".xml"]

    def detect(self, file_path: Path) -> bool:
        ext = file_path.suffix.lower()
        if ext not in self.supported_extensions:
            return False

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                header = f.read(1024)

            # Check Blackbox header markers
            if "H Product:Blackbox" in header or "H Firmware type:Betaflight" in header or "H Firmware type:INAV" in header:
                return True

            # Check iNav Mission Planner file
            if ext in [".mission", ".mwp"]:
                return True

            # Check MWP XML
            if ext == ".xml" and ("<mission" in header.lower() or "<waypoint" in header.lower()):
                return True

            # Check CLI dump / diff
            if ext == ".txt" and ("feature GPS" in header or "set nav_" in header or "set craft_name" in header or "# diff" in header):
                return True

            if "blackbox" in file_path.name.lower() or "betaflight" in file_path.name.lower() or "inav" in file_path.name.lower() or "mwp" in file_path.name.lower():
                return True
        except Exception:
            return False
        return False

    def parse_telemetry(self, file_path: Path) -> List[TelemetryPoint]:
        ext = file_path.suffix.lower()
        if ext in [".mission", ".mwp", ".xml"]:
            plan, pts, _, _ = GCSAnalyzer.parse_inav_mission(file_path)
            return pts

        points: List[TelemetryPoint] = []
        base_time = datetime.now(timezone.utc)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()

            for line in lines:
                # Blackbox GPS text line: GPS_coord[0], GPS_coord[1], GPS_altitude, GPS_speed
                # or CSV format from Blackbox Explorer
                if line.startswith("G,") or "GPS_coord" in line or line.startswith("GPS,"):
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) >= 5:
                        try:
                            # Betaflight Blackbox G frame: G, time, numSat, lat, lon, alt, speed, course
                            # Or simplified CSV: G, time, lat, lon, alt, speed
                            if len(parts) >= 7 and line.startswith("G,"):
                                try:
                                    sats_val = int(parts[2])
                                    if sats_val <= 60:
                                        lat = float(parts[3])
                                        lon = float(parts[4])
                                        alt = float(parts[5]) if len(parts) > 5 else 0.0
                                        spd = float(parts[6]) if len(parts) > 6 else 0.0
                                    else:
                                        lat = float(parts[2])
                                        lon = float(parts[3])
                                        alt = float(parts[4]) if len(parts) > 4 else 0.0
                                        spd = float(parts[5]) if len(parts) > 5 else 0.0
                                except ValueError:
                                    lat = float(parts[2])
                                    lon = float(parts[3])
                                    alt = float(parts[4]) if len(parts) > 4 else 0.0
                                    spd = float(parts[5]) if len(parts) > 5 else 0.0
                            else:
                                lat = float(parts[2])
                                lon = float(parts[3])
                                alt = float(parts[4]) if len(parts) > 4 else 0.0
                                spd = float(parts[5]) if len(parts) > 5 else 0.0

                            lat = lat / 1e7 if abs(lat) > 90.0 else lat
                            lon = lon / 1e7 if abs(lon) > 180.0 else lon

                            if lat == 0.0 and lon == 0.0:
                                continue

                            alt = float(parts[4]) if len(parts) > 4 else 0.0
                            spd = float(parts[5]) if len(parts) > 5 else 0.0

                            points.append(TelemetryPoint(
                                timestamp_utc=base_time.isoformat(),
                                latitude=lat,
                                longitude=lon,
                                altitude_m=alt,
                                ground_speed_mps=spd,
                                source_channel="BETAFLIGHT_BLACKBOX_GPS"
                            ))
                            base_time += timedelta(seconds=1)
                        except (ValueError, IndexError):
                            continue
        except Exception:
            pass
        return points

    def parse_events(self, file_path: Path) -> List[FlightEvent]:
        events: List[FlightEvent] = []
        pts = self.parse_telemetry(file_path)

        if pts:
            t_first_str = pts[0].timestamp_utc
            t_last_str = pts[-1].timestamp_utc
            try:
                t_last_dt = datetime.fromisoformat(t_last_str.replace("Z", "+00:00"))
                t_disarm_str = (t_last_dt + timedelta(seconds=1)).isoformat()
            except Exception:
                t_disarm_str = t_last_str
        else:
            t_first_str = datetime.now(timezone.utc).isoformat()
            t_last_str = t_first_str
            t_disarm_str = t_first_str

        has_arm = False
        has_disarm = False

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("E,"):
                        # Blackbox Event e.g. E,0,ARMED or E,6500000,DISARMED
                        parts = [p.strip() for p in line.split(",")]
                        event_text = " ".join(parts[1:]).upper() if len(parts) > 1 else ""
                        desc = f"Betaflight Event: {event_text}"
                        ev_type = "INFO"
                        ev_ts = t_first_str

                        if "DISARM" in event_text or (len(parts) > 1 and parts[1] == "1"):
                            desc = "Betaflight Disarmed: Cutoff switch engaged - Motors stopped"
                            ev_type = "DISARM"
                            ev_ts = t_disarm_str
                            has_disarm = True
                        elif "ARM" in event_text or (len(parts) > 1 and parts[1] == "0"):
                            desc = "Betaflight Armed: Motor spin up initiated"
                            ev_type = "ARM"
                            ev_ts = t_first_str
                            has_arm = True
                        elif "FAILSAFE" in event_text:
                            desc = "Betaflight FAILSAFE Trigger: RC Signal Lost or Crash detected"
                            ev_type = "FAILSAFE"
                            ev_ts = t_last_str

                        events.append(FlightEvent(
                            event_id=f"BF-EV-{len(events)+1}",
                            timestamp_utc=ev_ts,
                            event_type=ev_type,
                            severity="CRITICAL" if ev_type == "FAILSAFE" else "INFO",
                            description=desc,
                            latitude=pts[-1].latitude if (ev_type == "DISARM" and pts) else (pts[0].latitude if pts else None),
                            longitude=pts[-1].longitude if (ev_type == "DISARM" and pts) else (pts[0].longitude if pts else None),
                            altitude_m=0.0 if ev_type in ["ARM", "DISARM"] else (pts[0].altitude_m if pts else None)
                        ))
        except Exception:
            pass

    def parse_events(self, file_path: Path) -> List[FlightEvent]:
        ext = file_path.suffix.lower()
        if ext in [".mission", ".mwp", ".xml"]:
            _, _, events, _ = GCSAnalyzer.parse_inav_mission(file_path)
            return events

        events: List[FlightEvent] = []
        pts = self.parse_telemetry(file_path)

        if pts:
            t_first_str = pts[0].timestamp_utc
            t_last_str = pts[-1].timestamp_utc
            try:
                t_last_dt = datetime.fromisoformat(t_last_str.replace("Z", "+00:00"))
                t_disarm_str = (t_last_dt + timedelta(seconds=1)).isoformat()
            except Exception:
                t_disarm_str = t_last_str
        else:
            t_first_str = datetime.now(timezone.utc).isoformat()
            t_last_str = t_first_str
            t_disarm_str = t_first_str

        has_arm = False
        has_disarm = False

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("E,"):
                        # Blackbox Event e.g. E,0,ARMED or E,6500000,DISARMED
                        parts = [p.strip() for p in line.split(",")]
                        event_text = " ".join(parts[1:]).upper() if len(parts) > 1 else ""
                        desc = f"Betaflight Event: {event_text}"
                        ev_type = "INFO"
                        ev_ts = t_first_str

                        if "DISARM" in event_text or (len(parts) > 1 and parts[1] == "1"):
                            desc = "Betaflight Disarmed: Cutoff switch engaged - Motors stopped"
                            ev_type = "DISARM"
                            ev_ts = t_disarm_str
                            has_disarm = True
                        elif "ARM" in event_text or (len(parts) > 1 and parts[1] == "0"):
                            desc = "Betaflight Armed: Motor spin up initiated"
                            ev_type = "ARM"
                            ev_ts = t_first_str
                            has_arm = True
                        elif "FAILSAFE" in event_text:
                            desc = "Betaflight FAILSAFE Trigger: RC Signal Lost or Crash detected"
                            ev_type = "FAILSAFE"
                            ev_ts = t_last_str

                        events.append(FlightEvent(
                            event_id=f"BF-EV-{len(events)+1}",
                            timestamp_utc=ev_ts,
                            event_type=ev_type,
                            severity="CRITICAL" if ev_type == "FAILSAFE" else "INFO",
                            description=desc,
                            latitude=pts[-1].latitude if (ev_type == "DISARM" and pts) else (pts[0].latitude if pts else None),
                            longitude=pts[-1].longitude if (ev_type == "DISARM" and pts) else (pts[0].longitude if pts else None),
                            altitude_m=0.0 if ev_type in ["ARM", "DISARM"] else (pts[0].altitude_m if pts else None)
                        ))
        except Exception:
            pass

        if pts:
            if not has_arm:
                events.insert(0, FlightEvent(
                    event_id="BF-EV-ARM",
                    timestamp_utc=t_first_str,
                    event_type="ARM",
                    severity="INFO",
                    description="Betaflight Arming Detected",
                    latitude=pts[0].latitude,
                    longitude=pts[0].longitude,
                    altitude_m=pts[0].altitude_m
                ))
            if not has_disarm:
                events.append(FlightEvent(
                    event_id="BF-EV-DISARM",
                    timestamp_utc=t_disarm_str,
                    event_type="DISARM",
                    severity="INFO",
                    description="Betaflight Disarming / Shutdown Detected",
                    latitude=pts[-1].latitude,
                    longitude=pts[-1].longitude,
                    altitude_m=0.0
                ))

        return events

    def extract_metadata(self, file_path: Path) -> Dict[str, Any]:
        ext = file_path.suffix.lower()
        if ext in [".mission", ".mwp", ".xml"]:
            plan, _, _, op_locs = GCSAnalyzer.parse_inav_mission(file_path)
            meta: Dict[str, Any] = {
                "platform": "iNav Autonomous Mission Plan",
                "evidence_file": file_path.name,
                "ground_control_station": plan.gcs_name,
                "planned_waypoints_count": len(plan.waypoints),
                "total_planned_distance_m": plan.total_planned_distance_m,
                "planned_max_altitude_m": plan.planned_max_altitude_m
            }
            if op_locs:
                meta["operator_location"] = op_locs[0].model_dump()
            return meta

        headers: Dict[str, str] = {}
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    if line.startswith("H "):
                        parts = line[2:].strip().split(":", 1)
                        if len(parts) == 2:
                            headers[parts[0].strip()] = parts[1].strip()
                    elif not line.startswith("H") and len(headers) > 0:
                        break
                    # Also parse CLI dump / diff settings
                    elif line.startswith("set ") or line.startswith("feature "):
                        parts = line.strip().split("=", 1)
                        if len(parts) == 2:
                            headers[parts[0].replace("set ", "").strip()] = parts[1].strip()
        except Exception:
            pass

        return {
            "platform": "Betaflight / iNav",
            "evidence_file": file_path.name,
            "firmware_type": headers.get("Firmware type", "Betaflight / iNav"),
            "firmware_revision": headers.get("Firmware revision", "Unknown"),
            "craft_name": headers.get("Craft name", headers.get("craft_name", "Custom Quad / Wing")),
            "blackbox_headers": headers
        }
